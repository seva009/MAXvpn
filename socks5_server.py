import asyncio
import logging
import socket
import struct
from typing import Callable
from tunnel_crypto import (
    TunnelCrypto,
    CMD_CONNECT,
    CMD_CONNECT_OK,
    CMD_CONNECT_FAIL,
    CMD_DATA,
    CMD_CLOSE,
)

logger = logging.getLogger("socks5_proxy")

CHUNK_SIZE = 4096  # 4 KB chunk size for WebRTC DataChannel frames (lowers packet loss retransmissions)

class Socks5Server:
    """
    Local SOCKS5 proxy server.
    Accepts client connections (browser, curl, OS VPN/tun2socks), performs SOCKS5 handshake,
    encrypts traffic with AES-GCM, and multiplexes connections over the WebRTC DataChannel.
    """
    def __init__(
        self,
        crypto: TunnelCrypto,
        send_packet_fn: Callable[[bytes], bool],
        host: str = "127.0.0.1",
        port: int = 1080,
        get_buffered_amount: Callable[[], int] = None
    ):
        self.crypto = crypto
        self.send_packet_fn = send_packet_fn
        self.host = host
        self.port = port
        self.get_buffered_amount = get_buffered_amount
        self.server = None
        self.next_conn_id = 1
        self.pending_connects: dict[int, asyncio.Future] = {}
        self.active_clients: dict[int, tuple[asyncio.StreamReader, asyncio.StreamWriter, asyncio.Task]] = {}
        self._running = False

    async def start(self):
        self._running = True
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port
        )
        logger.info(f"[SOCKS5] Local proxy server listening on {self.host}:{self.port}")

    async def stop(self):
        if not self._running:
            return
        self._running = False

        # 1. Cancel and fail all pending connects immediately
        for conn_id, fut in list(self.pending_connects.items()):
            if not fut.done():
                fut.cancel()
        self.pending_connects.clear()

        # 2. Cancel and close all active clients BEFORE waiting for server closure
        for conn_id, (_, writer, task) in list(self.active_clients.items()):
            task.cancel()
            try:
                writer.close()
            except Exception:
                pass
        self.active_clients.clear()

        # 3. Close the server listener
        if self.server:
            self.server.close()
            try:
                await asyncio.wait_for(self.server.wait_closed(), timeout=1.0)
            except Exception:
                pass
            self.server = None

        logger.info("[SOCKS5] Local proxy stopped.")

    def handle_channel_packet(self, raw_bytes: bytes):
        """Called when a decrypted packet arrives from the remote relay via DataChannel."""
        try:
            msg_type, conn_id, payload = self.crypto.decrypt(raw_bytes)
        except Exception as e:
            logger.error(f"[SOCKS5 RX] Failed to decrypt packet: {e}")
            return

        if msg_type == CMD_CONNECT_OK:
            logger.info(f"[SOCKS5 RX] CONNECT_OK for conn #{conn_id}")
            fut = self.pending_connects.get(conn_id)
            if fut and not fut.done():
                fut.set_result(True)

        elif msg_type == CMD_CONNECT_FAIL:
            err_msg = payload.decode("utf-8", errors="replace")
            logger.warning(f"[SOCKS5 RX] Remote connect failed for conn #{conn_id}: {err_msg}")
            fut = self.pending_connects.get(conn_id)
            if fut and not fut.done():
                fut.set_result(False)

        elif msg_type == CMD_DATA:
            client_info = self.active_clients.get(conn_id)
            if client_info:
                _, writer, _ = client_info
                try:
                    writer.write(payload)
                    # Safe backpressure: drain only if transport buffer has accumulated data
                    if writer.transport and writer.transport.get_write_buffer_size() > 64 * 1024:
                        if not getattr(writer, "_draining", False):
                            setattr(writer, "_draining", True)
                            async def _drain(w):
                                try:
                                    await w.drain()
                                except Exception:
                                    pass
                                finally:
                                    setattr(w, "_draining", False)
                            asyncio.create_task(_drain(writer))
                except Exception as e:
                    logger.debug(f"[SOCKS5 RX] Error writing to client conn {conn_id}: {e}")

        elif msg_type == CMD_CLOSE:
            logger.info(f"[SOCKS5 RX] CLOSE for conn #{conn_id}")
            client_info = self.active_clients.pop(conn_id, None)
            if client_info:
                _, writer, task = client_info
                task.cancel()
                try:
                    writer.close()
                except Exception:
                    pass

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn_id = self.next_conn_id
        self.next_conn_id = (self.next_conn_id + 1) & 0xFFFFFFFF
        if self.next_conn_id == 0:
            self.next_conn_id = 1

        try:
            # 1. SOCKS5 greeting: VER (1B) + NMETHODS (1B) + METHODS
            greeting = await reader.read(2)
            if len(greeting) < 2 or greeting[0] != 5:
                writer.close()
                return

            nmethods = greeting[1]
            methods = await reader.readexactly(nmethods)
            if b"\x00" not in methods:
                # No acceptable auth methods
                writer.write(b"\x05\xff")
                await writer.drain()
                writer.close()
                return

            # Respond with NO AUTH (0x00)
            writer.write(b"\x05\x00")
            await writer.drain()

            # 2. SOCKS5 request: VER (1B) + CMD (1B) + RSV (1B) + ATYP (1B)
            req = await reader.readexactly(4)
            ver, cmd, _, atyp = req
            if ver != 5 or cmd != 1:  # Only CONNECT (0x01) supported
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # Command not supported
                await writer.drain()
                writer.close()
                return

            # Parse target destination address
            if atyp == 1:  # IPv4
                addr_bytes = await reader.readexactly(4)
                host = socket.inet_ntoa(addr_bytes)
            elif atyp == 3:  # Domain name
                dlen = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(dlen)).decode("utf-8", errors="replace")
            elif atyp == 4:  # IPv6
                addr_bytes = await reader.readexactly(16)
                host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                writer.close()
                return

            port_bytes = await reader.readexactly(2)
            port = struct.unpack("!H", port_bytes)[0]

            if not self._running:
                writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")  # Network unreachable
                await writer.drain()
                writer.close()
                return

            logger.info(f"[SOCKS5] New connection #{conn_id} -> {host}:{port}")

            # Send encrypted CONNECT command to remote relay
            connect_payload = self.crypto.pack_connect_payload(host, port)
            pkt = self.crypto.encrypt(CMD_CONNECT, conn_id, connect_payload)

            fut = asyncio.get_running_loop().create_future()
            self.pending_connects[conn_id] = fut
            sent = self.send_packet_fn(pkt)
            if sent is False:
                self.pending_connects.pop(conn_id, None)
                writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return

            # Wait for remote relay response (timeout 15s to match relay's 12s dial timeout + latency)
            try:
                success = await asyncio.wait_for(fut, timeout=15.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                if self._running:
                    logger.warning(f"[SOCKS5] Timeout waiting for connect ACK #{conn_id} -> {host}:{port}")
                success = False
            finally:
                self.pending_connects.pop(conn_id, None)

            if not success or not self._running:
                # Connection refused / failure
                writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return

            # SOCKS5 success reply
            logger.info(f"[SOCKS5] Connected #{conn_id} -> {host}:{port}")
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            # 3. Stream data from client to tunnel
            task = asyncio.create_task(self._client_reader_loop(conn_id, reader))
            self.active_clients[conn_id] = (reader, writer, task)
            await task

        except Exception as e:
            logger.debug(f"[SOCKS5] Client #{conn_id} error: {e}")
        finally:
            self.active_clients.pop(conn_id, None)
            try:
                writer.close()
            except Exception:
                pass
            # Only send CLOSE if proxy is still running
            if self._running:
                try:
                    logger.info(f"[SOCKS5 TX] Sending CLOSE #{conn_id}")
                    pkt_close = self.crypto.encrypt(CMD_CLOSE, conn_id)
                    self.send_packet_fn(pkt_close)
                except Exception:
                    pass

    async def _client_reader_loop(self, conn_id: int, reader: asyncio.StreamReader):
        try:
            while self._running:
                chunk = await reader.read(CHUNK_SIZE)
                if not chunk:
                    break
                # Backpressure: brief pause if outbound DataChannel buffer is congested
                while self.get_buffered_amount and self.get_buffered_amount() > 256 * 1024:
                    if not self._running:
                        break
                    await asyncio.sleep(0.01)
                pkt = self.crypto.encrypt(CMD_DATA, conn_id, chunk)
                if self.send_packet_fn(pkt) is False:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"[SOCKS5] Reader error conn #{conn_id}: {e}")
