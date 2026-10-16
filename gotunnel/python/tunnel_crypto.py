import base64
import hashlib
import hmac
import os
import struct
import time
import logging
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("tunnel_crypto")

# Protocol command opcodes
CMD_CONNECT = 1        # [conn_id: 4B][port: 2B][host: UTF-8]
CMD_CONNECT_OK = 2     # [conn_id: 4B]
CMD_CONNECT_FAIL = 3   # [conn_id: 4B][error_msg: UTF-8]
CMD_DATA = 4           # [conn_id: 4B][payload: bytes]
CMD_CLOSE = 5          # [conn_id: 4B]
CMD_PING = 6           # [conn_id: 4B][timestamp: 8B]
CMD_PONG = 7           # [conn_id: 4B][timestamp: 8B]
CMD_HANDSHAKE_INIT = 10 # Handshake init from caller to relay
CMD_HANDSHAKE_RESP = 11 # Handshake response from relay to caller

DEFAULT_TUNNEL_SECRET = "oneme_webrtc_aes_tunnel_key"

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info
    ).derive(ikm)

def generate_keypair() -> tuple[str, str]:
    """Generates an X25519 keypair and returns (private_hex, public_hex)."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv.private_bytes_raw().hex(), pub.public_bytes_raw().hex()

def parse_key(key_str: str) -> bytes:
    """Parses a 32-byte key from a 64-char hex or base64 string."""
    s = key_str.strip()
    if len(s) == 64:
        try:
            b = bytes.fromhex(s)
            if len(b) == 32:
                return b
        except ValueError:
            pass
    try:
        b = base64.b64decode(s)
        if len(b) == 32:
            return b
    except Exception:
        pass
    try:
        b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        if len(b) == 32:
            return b
    except Exception:
        pass
    raise ValueError("Invalid key: must be 32 bytes (64 hex characters or base64)")

def compute_knock_uuid(priv_key: bytes, peer_pub_key: bytes, ts: int | None = None) -> str:
    """Generates an authenticated UUIDv4 knock token for incoming call screening."""
    if ts is None:
        ts = int(time.time())
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_key)
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_key)
    dh_static = priv.exchange(peer_pub)
    k_knock = hkdf_sha256(dh_static, b"calltunnel-knock-salt", b"calltunnel-knock", 32)
    ts_bytes = struct.pack("!I", ts)
    h = hmac.new(k_knock, ts_bytes, hashlib.sha256).digest()[:12]
    raw = bytearray(ts_bytes + h)
    raw[6] = (raw[6] & 0x0f) | 0x40  # version 4
    raw[8] = (raw[8] & 0x3f) | 0x80  # variant RFC 4122
    hex_str = raw.hex()
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"

_knock_cache: dict[str, int] = {}

def verify_knock_uuid(priv_key: bytes, allowed_pub_keys: list[bytes], uuid_str: str, window_sec: int = 60) -> bool:
    """Verifies whether uuid_str contains a valid knock token from any allowed peer."""
    clean = uuid_str.replace("-", "").strip()
    if len(clean) != 32:
        return False
    try:
        raw = bytes.fromhex(clean)
    except ValueError:
        return False
    ts = struct.unpack("!I", raw[:4])[0]
    now = int(time.time())
    if abs(now - ts) > window_sec:
        return False

    # Anti-replay check for knock UUID
    if clean in _knock_cache and abs(now - _knock_cache[clean]) <= window_sec:
        return False

    ts_bytes = raw[:4]
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_key)
    for peer_pub_bytes in allowed_pub_keys:
        try:
            peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
            dh_static = priv.exchange(peer_pub)
            k_knock = hkdf_sha256(dh_static, b"calltunnel-knock-salt", b"calltunnel-knock", 32)
            h = hmac.new(k_knock, ts_bytes, hashlib.sha256).digest()[:12]
            exp = bytearray(ts_bytes + h)
            exp[6] = (exp[6] & 0x0f) | 0x40
            exp[8] = (exp[8] & 0x3f) | 0x80
            if hmac.compare_digest(raw, bytes(exp)):
                _knock_cache[clean] = now
                # Prune old cache entries
                to_del = [k for k, v in _knock_cache.items() if now - v > window_sec * 2]
                for k in to_del:
                    _knock_cache.pop(k, None)
                return True
        except Exception:
            continue
    return False

class TunnelCrypto:
    """
    Handles AES-256-GCM authenticated encryption for tunnel packets.
    Uses deterministic 64-bit monotonic sequence counters in the 12-byte nonce
    to eliminate GCM nonce collision risks and provide sliding-window anti-replay protection.
    Wire format:
      [12-byte Nonce: 4B prefix + 8B big-endian seq] + [AES-GCM Ciphertext + 16-byte GCM Tag]
    Plaintext inside ciphertext:
      [1-byte msg_type] + [4-byte conn_id uint32] + [payload]
    """
    def __init__(self, secret: str = None, tx_key: bytes = None, rx_key: bytes = None):
        if tx_key is not None and rx_key is not None:
            self.tx_aes = AESGCM(tx_key)
            self.rx_aes = AESGCM(rx_key)
        else:
            if secret is None:
                secret = DEFAULT_TUNNEL_SECRET
            key = hashlib.sha256(secret.encode("utf-8")).digest()
            self.tx_aes = AESGCM(key)
            self.rx_aes = AESGCM(key)
        self.tx_seq = 0
        self.last_rx_seq = 0
        self.replay_bitmap = 0

    def encrypt(self, msg_type: int, conn_id: int, payload: bytes = b"") -> bytes:
        self.tx_seq += 1
        nonce = struct.pack("!IQ", 0, self.tx_seq)
        plaintext = struct.pack("!BI", msg_type, conn_id) + payload
        ciphertext = self.tx_aes.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> tuple[int, int, bytes]:
        if len(data) < 33:
            raise ValueError(f"Packet too short for AES-GCM decrypt: {len(data)} bytes")
        nonce = data[:12]
        ciphertext = data[12:]
        seq = struct.unpack("!Q", nonce[4:12])[0]

        # 1. Anti-replay pre-check (sliding window 64)
        if seq == 0:
            if self.last_rx_seq > 0:
                raise ValueError("tunnelcrypto: invalid zero sequence number")
        elif seq <= self.last_rx_seq:
            diff = self.last_rx_seq - seq
            if diff >= 64:
                raise ValueError(f"tunnelcrypto: packet too old (seq {seq}, last {self.last_rx_seq})")
            if (self.replay_bitmap & (1 << diff)) != 0:
                raise ValueError(f"tunnelcrypto: duplicate/replayed packet (seq {seq})")

        # 2. Decrypt and authenticate
        plaintext = self.rx_aes.decrypt(nonce, ciphertext, None)

        # 3. Authenticated: commit sequence number to replay window
        if seq > 0:
            if seq > self.last_rx_seq:
                diff = seq - self.last_rx_seq
                if diff < 64:
                    self.replay_bitmap = (self.replay_bitmap << diff) | 1
                else:
                    self.replay_bitmap = 1
                self.last_rx_seq = seq
            else:
                diff = self.last_rx_seq - seq
                if diff < 64:
                    self.replay_bitmap |= (1 << diff)

        msg_type, conn_id = struct.unpack("!BI", plaintext[:5])
        payload = plaintext[5:]
        return msg_type, conn_id, payload

    @staticmethod
    def pack_connect_payload(host: str, port: int) -> bytes:
        return struct.pack("!H", port) + host.encode("utf-8")

    @staticmethod
    def unpack_connect_payload(payload: bytes) -> tuple[str, int]:
        if len(payload) < 2:
            raise ValueError("Connect payload too short")
        port = struct.unpack("!H", payload[:2])[0]
        host = payload[2:].decode("utf-8", errors="replace")
        return host, port

class HandshakeInitiator:
    """Caller-side handshake over WebRTC DataChannel."""
    def __init__(self, priv_key: bytes, peer_pub_key: bytes):
        self.priv_key = priv_key
        self.peer_pub_key = peer_pub_key
        self.ephemeral_priv = None
        self.ephemeral_pub = None
        self.dh1 = None
        self.dh2 = None

    def create_init_packet(self) -> bytes:
        priv = x25519.X25519PrivateKey.from_private_bytes(self.priv_key)
        pub = priv.public_key().public_bytes_raw()
        peer_pub = x25519.X25519PublicKey.from_public_bytes(self.peer_pub_key)

        e_priv = x25519.X25519PrivateKey.generate()
        self.ephemeral_priv = e_priv.private_bytes_raw()
        self.ephemeral_pub = e_priv.public_key().public_bytes_raw()

        self.dh1 = e_priv.exchange(peer_pub)
        k1 = hkdf_sha256(self.dh1, self.ephemeral_pub, b"calltunnel-hs1", 32)
        nonce1 = os.urandom(12)
        c1 = AESGCM(k1).encrypt(nonce1, pub, None)

        self.dh2 = priv.exchange(peer_pub)
        k2 = hkdf_sha256(self.dh2, c1[:16], b"calltunnel-hs2", 32)
        nonce2 = os.urandom(12)
        ts_entropy = struct.pack("!Q", int(time.time())) + os.urandom(16)
        c2 = AESGCM(k2).encrypt(nonce2, ts_entropy, None)

        return struct.pack("!B", CMD_HANDSHAKE_INIT) + self.ephemeral_pub + nonce1 + c1 + nonce2 + c2

    def process_resp_packet(self, resp_bytes: bytes) -> TunnelCrypto:
        if len(resp_bytes) != 79 or resp_bytes[0] != CMD_HANDSHAKE_RESP:
            raise ValueError(f"Invalid resp packet size or opcode: {len(resp_bytes)}")
        e_relay = resp_bytes[1:33]
        nonce3 = resp_bytes[33:45]
        c3 = resp_bytes[45:]

        e_priv = x25519.X25519PrivateKey.from_private_bytes(self.ephemeral_priv)
        priv = x25519.X25519PrivateKey.from_private_bytes(self.priv_key)
        relay_e_pub = x25519.X25519PublicKey.from_public_bytes(e_relay)

        dh3 = e_priv.exchange(relay_e_pub)
        dh4 = priv.exchange(relay_e_pub)

        # Full DH binding: dh1 + dh2 + dh3 + dh4 ensures mutual proof of static keys
        ikm_resp = self.dh1 + self.dh2 + dh3 + dh4
        salt_resp = self.ephemeral_pub + e_relay
        k_resp = hkdf_sha256(ikm_resp, salt_resp, b"calltunnel-resp", 32)

        confirm = AESGCM(k_resp).decrypt(nonce3, c3, None)
        if confirm != b"CALLTUNNEL_AUTH_OK":
            raise ValueError("Invalid confirmation tag from relay")

        session_ikm = self.dh1 + self.dh2 + dh3 + dh4
        session_salt = self.ephemeral_pub + e_relay
        k_c2r = hkdf_sha256(session_ikm, session_salt, b"calltunnel-key-c2r", 32)
        k_r2c = hkdf_sha256(session_ikm, session_salt, b"calltunnel-key-r2c", 32)

        # Caller sends with k_c2r, receives with k_r2c
        return TunnelCrypto(tx_key=k_c2r, rx_key=k_r2c)

class HandshakeResponder:
    """Relay-side handshake over WebRTC DataChannel."""
    def __init__(self, priv_key: bytes, allowed_pub_keys: list[bytes]):
        self.priv_key = priv_key
        self.allowed_pub_keys = allowed_pub_keys
        self.last_seen_ts: dict[str, int] = {}

    def process_init_packet(self, init_bytes: bytes) -> tuple[bytes, TunnelCrypto]:
        if len(init_bytes) != 145 or init_bytes[0] != CMD_HANDSHAKE_INIT:
            raise ValueError(f"Invalid init packet size or opcode: {len(init_bytes)}")
        e_caller = init_bytes[1:33]
        nonce1 = init_bytes[33:45]
        c1 = init_bytes[45:93]
        nonce2 = init_bytes[93:105]
        c2 = init_bytes[105:145]

        priv = x25519.X25519PrivateKey.from_private_bytes(self.priv_key)
        caller_e_pub = x25519.X25519PublicKey.from_public_bytes(e_caller)

        dh1 = priv.exchange(caller_e_pub)
        k1 = hkdf_sha256(dh1, e_caller, b"calltunnel-hs1", 32)
        caller_pub = AESGCM(k1).decrypt(nonce1, c1, None)

        if caller_pub not in self.allowed_pub_keys:
            raise PermissionError(f"Caller public key {caller_pub.hex()} not authorized")

        dh2 = priv.exchange(x25519.X25519PublicKey.from_public_bytes(caller_pub))
        k2 = hkdf_sha256(dh2, c1[:16], b"calltunnel-hs2", 32)
        ts_entropy = AESGCM(k2).decrypt(nonce2, c2, None)
        ts = struct.unpack("!Q", ts_entropy[:8])[0]
        now = int(time.time())
        if abs(now - ts) > 60:
            raise ValueError(f"Expired handshake timestamp: {ts} (now={now})")

        pub_hex = caller_pub.hex()
        last = self.last_seen_ts.get(pub_hex, 0)
        if ts <= last:
            raise ValueError(f"Replayed handshake timestamp: {ts} <= {last}")
        self.last_seen_ts[pub_hex] = ts

        e_priv = x25519.X25519PrivateKey.generate()
        e_pub_bytes = e_priv.public_key().public_bytes_raw()

        dh3 = e_priv.exchange(caller_e_pub)
        dh4 = e_priv.exchange(x25519.X25519PublicKey.from_public_bytes(caller_pub))

        # Full DH binding: dh1 + dh2 + dh3 + dh4 ensures mutual proof of static keys
        ikm_resp = dh1 + dh2 + dh3 + dh4
        salt_resp = e_caller + e_pub_bytes
        k_resp = hkdf_sha256(ikm_resp, salt_resp, b"calltunnel-resp", 32)
        nonce3 = os.urandom(12)
        c3 = AESGCM(k_resp).encrypt(nonce3, b"CALLTUNNEL_AUTH_OK", None)
        resp_pkt = struct.pack("!B", CMD_HANDSHAKE_RESP) + e_pub_bytes + nonce3 + c3

        session_ikm = dh1 + dh2 + dh3 + dh4
        session_salt = e_caller + e_pub_bytes
        k_c2r = hkdf_sha256(session_ikm, session_salt, b"calltunnel-key-c2r", 32)
        k_r2c = hkdf_sha256(session_ikm, session_salt, b"calltunnel-key-r2c", 32)

        # Relay sends with k_r2c, receives with k_c2r
        return resp_pkt, TunnelCrypto(tx_key=k_r2c, rx_key=k_c2r)

if __name__ == "__main__":
    import sys
    if "--gen-key" in sys.argv:
        priv_hex, pub_hex = generate_keypair()
        print(f"Private Key: {priv_hex}")
        print(f"Public Key:  {pub_hex}")
    else:
        print("Usage: python3 tunnel_crypto.py --gen-key")

