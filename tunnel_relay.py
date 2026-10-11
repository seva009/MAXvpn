import asyncio
import logging
from typing import Callable
from tunnel_crypto import (
    TunnelCrypto,
    CMD_CONNECT,
    CMD_CONNECT_OK,
    CMD_CONNECT_FAIL,
    CMD_DATA,
    CMD_CLOSE,
)

logger = logging.getLogger("tunnel_relay")

CHUNK_SIZE = 4096  # 4 KB chunk size for WebRTC DataChannel frames

class TunnelRelay:
    """
    Remote Relay that runs on the receiving side (Raspberry Pi / Server).
    Receives AES-GCM encrypted requests from the caller via WebRTC DataChannel,
    establishes outbound TCP connections to the real Internet targets,
    and relays decrypted data bidirectionally.
    """
    def __init__(
        self,
        crypto: TunnelCrypto,
        send_packet_fn: Callable[[bytes], bool],
        get_buffered_amount: Callable[[], int] = None,
    ):
        self.crypto = crypto
        self.send_packet_fn = send_packet_fn
        self.get_buffered_amount = get_buffered_amount
        self.active_conns: dict[int, tuple[asyncio.StreamReader, asyncio.StreamWriter, asyncio.Task]] = {}
        self._running = True

    def stop(self):
        if not self._running:
            return
        self._running = False
        conns = list(self.active_conns.values())
        self.active_conns.clear()
        for _, writer, task in conns:
            task.cancel()
            try:
                writer.close()
            except Exception:
                pass
        logger.info("[Tunnel Relay] Stopped all active internet connections.")

    def handle_channel_packet(self, raw_bytes: bytes):
        """Called when an encrypted packet arrives from the caller via DataChannel."""
        try:
            msg_type, conn_id, payload = self.crypto.decrypt(raw_bytes)
        except Exception as e:
            logger.error(f"[Tunnel Relay RX] Failed to decrypt packet: {e}")
            return

        if msg_type == CMD_CONNECT:
            try:
                host, port = self.crypto.unpack_connect_payload(payload)
                asyncio.create_task(self._handle_connect(conn_id, host, port))
            except Exception as e:
                logger.error(f"[Tunnel Relay] Error unpacking connect payload #{conn_id}: {e}")
                fail_pkt = self.crypto.encrypt(CMD_CONNECT_FAIL, conn_id, str(e).encode())
                self.send_packet_fn(fail_pkt)

        elif msg_type == CMD_DATA:
            conn_info = self.active_conns.get(conn_id)
            if conn_info:
                _, writer, _ = conn_info
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
                    logger.debug(f"[Tunnel Relay] Error writing to target conn #{conn_id}: {e}")

        elif msg_type == CMD_CLOSE:
            conn_info = self.active_conns.pop(conn_id, None)
            if conn_info:
                _, writer, task = conn_info
                task.cancel()
                try:
                    writer.close()
                except Exception:
                    pass

    async def _handle_connect(self, conn_id: int, host: str, port: int):
        if not self._running:
            return
        logger.info(f"[Tunnel Relay] Connecting to {host}:{port} for conn #{conn_id}...")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            logger.info(f"[Tunnel Relay] CONNECTED to {host}:{port} for conn #{conn_id}!")

            if not self._running:
                try:
                    writer.close()
                except Exception:
                    pass
                return

            # Spawn remote reader task
            task = asyncio.create_task(self._remote_reader_loop(conn_id, reader))
            self.active_conns[conn_id] = (reader, writer, task)

            # Send CONNECT_OK back to caller
            pkt_ok = self.crypto.encrypt(CMD_CONNECT_OK, conn_id)
            self.send_packet_fn(pkt_ok)

        except Exception as e:
            logger.warning(f"[Tunnel Relay] Failed to connect to {host}:{port} for conn #{conn_id}: {e}")
            pkt_fail = self.crypto.encrypt(CMD_CONNECT_FAIL, conn_id, str(e).encode())
            self.send_packet_fn(pkt_fail)

    async def _remote_reader_loop(self, conn_id: int, reader: asyncio.StreamReader):
        try:
            while self._running:
                if self.get_buffered_amount:
                    while self.get_buffered_amount() > 512 * 1024:
                        if not self._running:
                            break
                        await asyncio.sleep(0.01)
                chunk = await reader.read(CHUNK_SIZE)
                if not chunk:
                    break
                pkt = self.crypto.encrypt(CMD_DATA, conn_id, chunk)
                if self.send_packet_fn(pkt) is False:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self._running and not isinstance(e, ConnectionResetError):
                logger.debug(f"[Tunnel Relay] Target socket closed or error #{conn_id}: {e}")
        finally:
            conn_info = self.active_conns.pop(conn_id, None)
            if conn_info:
                _, writer, _ = conn_info
                try:
                    writer.close()
                except Exception:
                    pass
            # Notify caller only if we are still running
            if self._running:
                try:
                    pkt_close = self.crypto.encrypt(CMD_CLOSE, conn_id)
                    self.send_packet_fn(pkt_close)
                except Exception:
                    pass
