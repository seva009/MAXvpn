import asyncio
import os
import struct
import socket
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("test_socks")

# Commands
CMD_CONNECT = 1
CMD_CONNECT_OK = 2
CMD_CONNECT_FAIL = 3
CMD_DATA = 4
CMD_CLOSE = 5

class TunnelCrypto:
    def __init__(self, secret: str = "test_secret"):
        key = hashlib.sha256(secret.encode("utf-8")).digest()
        self.aes = AESGCM(key)

    def encrypt(self, msg_type: int, conn_id: int, payload: bytes = b"") -> bytes:
        nonce = os.urandom(12)
        plain = struct.pack("!BI", msg_type, conn_id) + payload
        ct = self.aes.encrypt(nonce, plain, None)
        return nonce + ct

    def decrypt(self, data: bytes) -> tuple[int, int, bytes]:
        if len(data) < 12 + 16 + 5:
            raise ValueError("Packet too short")
        nonce = data[:12]
        ct = data[12:]
        plain = self.aes.decrypt(nonce, ct, None)
        msg_type, conn_id = struct.unpack("!BI", plain[:5])
        return msg_type, conn_id, plain[5:]

class VirtualChannel:
    def __init__(self):
        self.q_to_client = asyncio.Queue()
        self.q_to_caller = asyncio.Queue()

# Simulate Remote Relay (Client side)
class RemoteRelay:
    def __init__(self, crypto: TunnelCrypto, channel: VirtualChannel):
        self.crypto = crypto
        self.channel = channel
        self.active_conns = {}  # conn_id -> (reader, writer, task)

    async def run(self):
        while True:
            pkt = await self.channel.q_to_client.get()
            try:
                msg_type, conn_id, payload = self.crypto.decrypt(pkt)
            except Exception as e:
                logger.error(f"[Relay] Decrypt error: {e}")
                continue

            if msg_type == CMD_CONNECT:
                port = struct.unpack("!H", payload[:2])[0]
                host = payload[2:].decode("utf-8")
                asyncio.create_task(self._handle_connect(conn_id, host, port))
            elif msg_type == CMD_DATA:
                if conn_id in self.active_conns:
                    _, writer, _ = self.active_conns[conn_id]
                    try:
                        writer.write(payload)
                        await writer.drain()
                    except Exception as e:
                        logger.warning(f"[Relay] Write error conn {conn_id}: {e}")
            elif msg_type == CMD_CLOSE:
                if conn_id in self.active_conns:
                    _, writer, task = self.active_conns.pop(conn_id)
                    task.cancel()
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

    async def _handle_connect(self, conn_id: int, host: str, port: int):
        logger.info(f"[Relay] Connecting to {host}:{port} for conn {conn_id}...")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10.0)
            logger.info(f"[Relay] Connected to {host}:{port} for conn {conn_id}!")
            
            task = asyncio.create_task(self._read_remote(conn_id, reader))
            self.active_conns[conn_id] = (reader, writer, task)
            
            # Send OK
            pkt_ok = self.crypto.encrypt(CMD_CONNECT_OK, conn_id)
            await self.channel.q_to_caller.put(pkt_ok)
        except Exception as e:
            logger.error(f"[Relay] Failed connect {host}:{port}: {e}")
            pkt_fail = self.crypto.encrypt(CMD_CONNECT_FAIL, conn_id, str(e).encode())
            await self.channel.q_to_caller.put(pkt_fail)

    async def _read_remote(self, conn_id: int, reader: asyncio.StreamReader):
        try:
            while True:
                data = await reader.read(16384)
                if not data:
                    break
                pkt = self.crypto.encrypt(CMD_DATA, conn_id, data)
                await self.channel.q_to_caller.put(pkt)
        except Exception:
            pass
        finally:
            if conn_id in self.active_conns:
                _, writer, _ = self.active_conns.pop(conn_id, (None, None, None))
                if writer:
                    try:
                        writer.close()
                    except Exception:
                        pass
            pkt_close = self.crypto.encrypt(CMD_CLOSE, conn_id)
            await self.channel.q_to_caller.put(pkt_close)

# Simulate Caller SOCKS5 Server
class LocalSocks5:
    def __init__(self, crypto: TunnelCrypto, channel: VirtualChannel, port: int = 11080):
        self.crypto = crypto
        self.channel = channel
        self.port = port
        self.next_conn_id = 1
        self.pending_connects = {}  # conn_id -> asyncio.Future
        self.active_clients = {}    # conn_id -> (reader, writer, task)

    async def run(self):
        # Background listener for replies from relay
        asyncio.create_task(self._listen_channel())

        server = await asyncio.start_server(self._handle_socks_client, "127.0.0.1", self.port)
        logger.info(f"[SOCKS5] Listening on 127.0.0.1:{self.port}")
        async with server:
            await server.serve_forever()

    async def _listen_channel(self):
        while True:
            pkt = await self.channel.q_to_caller.get()
            try:
                msg_type, conn_id, payload = self.crypto.decrypt(pkt)
            except Exception as e:
                logger.error(f"[SOCKS5] Decrypt error: {e}")
                continue

            if msg_type == CMD_CONNECT_OK:
                if conn_id in self.pending_connects:
                    fut = self.pending_connects[conn_id]
                    if not fut.done():
                        fut.set_result(True)
            elif msg_type == CMD_CONNECT_FAIL:
                if conn_id in self.pending_connects:
                    fut = self.pending_connects[conn_id]
                    if not fut.done():
                        fut.set_result(False)
            elif msg_type == CMD_DATA:
                if conn_id in self.active_clients:
                    _, writer, _ = self.active_clients[conn_id]
                    try:
                        writer.write(payload)
                        await writer.drain()
                    except Exception:
                        pass
            elif msg_type == CMD_CLOSE:
                if conn_id in self.active_clients:
                    _, writer, task = self.active_clients.pop(conn_id)
                    task.cancel()
                    try:
                        writer.close()
                    except Exception:
                        pass

    async def _handle_socks_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn_id = self.next_conn_id
        self.next_conn_id += 1

        try:
            # SOCKS5 Handshake
            header = await reader.read(2)
            if len(header) < 2 or header[0] != 5:
                writer.close()
                return
            nmethods = header[1]
            methods = await reader.readexactly(nmethods)
            if b"\x00" not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x05\x00")
            await writer.drain()

            # Request
            req = await reader.readexactly(4)
            ver, cmd, _, atyp = req
            if ver != 5 or cmd != 1:  # Only CONNECT supported
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return

            if atyp == 1:  # IPv4
                addr_bytes = await reader.readexactly(4)
                host = socket.inet_ntoa(addr_bytes)
            elif atyp == 3:  # Domain
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

            logger.info(f"[SOCKS5] Client requested CONNECT to {host}:{port} (conn_id={conn_id})")

            # Send connect request to tunnel
            connect_payload = struct.pack("!H", port) + host.encode("utf-8")
            pkt = self.crypto.encrypt(CMD_CONNECT, conn_id, connect_payload)
            
            fut = asyncio.get_running_loop().create_future()
            self.pending_connects[conn_id] = fut
            await self.channel.q_to_client.put(pkt)

            # Wait for relay reply
            try:
                ok = await asyncio.wait_for(fut, timeout=10.0)
            finally:
                self.pending_connects.pop(conn_id, None)

            if not ok:
                logger.warning(f"[SOCKS5] Connect failed for {host}:{port}")
                writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return

            # Success response
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            # Start reading from client
            task = asyncio.create_task(self._read_client(conn_id, reader))
            self.active_clients[conn_id] = (reader, writer, task)
            await task

        except Exception as e:
            logger.debug(f"[SOCKS5] Client error conn_id={conn_id}: {e}")
        finally:
            if conn_id in self.active_clients:
                _, w, _ = self.active_clients.pop(conn_id)
                try:
                    w.close()
                except Exception:
                    pass
            pkt_close = self.crypto.encrypt(CMD_CLOSE, conn_id)
            await self.channel.q_to_client.put(pkt_close)

    async def _read_client(self, conn_id: int, reader: asyncio.StreamReader):
        try:
            while True:
                data = await reader.read(16384)
                if not data:
                    break
                pkt = self.crypto.encrypt(CMD_DATA, conn_id, data)
                await self.channel.q_to_client.put(pkt)
        except Exception:
            pass

async def main():
    crypto = TunnelCrypto("my_secret_key")
    channel = VirtualChannel()
    relay = RemoteRelay(crypto, channel)
    socks = LocalSocks5(crypto, channel, port=11080)

    asyncio.create_task(relay.run())
    asyncio.create_task(socks.run())
    logger.info("Test system running, waiting 30 seconds for test...")
    await asyncio.sleep(30)

if __name__ == "__main__":
    asyncio.run(main())
