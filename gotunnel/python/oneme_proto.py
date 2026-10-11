import struct
import lz4.block
import msgpack

# Protocol constants
PROTO_VERSION = 10
HEADER_SIZE = 10

OPCODE_INIT = 6
OPCODE_LOGIN = 19
OPCODE_START_CALL = 78
OPCODE_INCOMING_CALL = 137
OPCODE_GET_CALL_TOKEN = 158

import base64
import json

def decode_vcp(vcp_str: str) -> dict:
    """
    Decodes conversationParams (vcp) from incoming call notification (opcode 137).
    Format: '<original_length>:<base64_lz4_compressed_json>'
    Returns dict with keys: 'tkn', 'wse', 'stne', 'trne', 'trnu', 'trnp', etc.
    """
    orig_len_str, b64_data = vcp_str.split(":", 1)
    orig_len = int(orig_len_str)
    compressed = base64.b64decode(b64_data)
    decompressed = lz4.block.decompress(compressed, uncompressed_size=orig_len)
    return json.loads(decompressed.decode("utf-8"))

def msgpack_ext_hook(code, data):
    """
    Decodes custom extension types used by OneMe/Max API.
    Type 1 = BigInt (64-bit user/chat/message IDs).
    """
    if code == 1:
        try:
            return msgpack.unpackb(data)
        except Exception:
            return int.from_bytes(data, byteorder="big", signed=True)
    return msgpack.ExtType(code, data)

def decode_packet(data: bytes):
    """
    Decodes a binary packet from wss://api.oneme.ru/websocket.
    Header format (10 bytes):
      byte 0: version (10)
      byte 1: cmd (0 = notification/request, 1 = response, 3 = error)
      byte 2-3: seq (int16 big-endian)
      byte 4-5: opcode (int16 big-endian)
      byte 6: compression ratio (0 if uncompressed, else lz4 ratio)
      byte 7-9: payload length (24-bit unsigned big-endian)
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Data too short for header: {len(data)} bytes")

    ver, cmd, seq, opcode, comp_ratio = struct.unpack(">BBhhB", data[:7])
    payload_len = (data[7] << 16) | (data[8] << 8) | data[9]

    payload_raw = data[HEADER_SIZE:HEADER_SIZE + payload_len]
    if len(payload_raw) != payload_len:
        raise ValueError(f"Truncated payload: expected {payload_len}, got {len(payload_raw)}")

    if comp_ratio > 0:
        # LZ4 block compression
        uncompressed_size = payload_len * comp_ratio
        payload_bytes = lz4.block.decompress(payload_raw, uncompressed_size=uncompressed_size)
    else:
        payload_bytes = payload_raw

    payload = None
    if payload_bytes:
        payload = msgpack.unpackb(
            payload_bytes,
            raw=False,
            strict_map_key=False,
            ext_hook=msgpack_ext_hook
        )

    return {
        "cmd": cmd,
        "seq": seq,
        "opcode": opcode,
        "payload": payload
    }

def encode_packet(cmd: int, seq: int, opcode: int, payload=None) -> bytes:
    """
    Encodes a binary packet for wss://api.oneme.ru/websocket.
    Outgoing packets are sent uncompressed (comp_ratio = 0).
    """
    if payload is not None:
        raw_payload = msgpack.packb(payload, use_bin_type=True)
    else:
        raw_payload = b""

    payload_len = len(raw_payload)
    if payload_len > 0xFFFFFF:
        raise ValueError("Payload exceeds 24-bit max length")

    header = bytearray(HEADER_SIZE)
    header[0] = PROTO_VERSION
    header[1] = cmd & 0xFF
    struct.pack_into(">h", header, 2, seq)
    struct.pack_into(">h", header, 4, opcode)
    header[6] = 0  # uncompressed
    header[7] = (payload_len >> 16) & 0xFF
    header[8] = (payload_len >> 8) & 0xFF
    header[9] = payload_len & 0xFF

    return bytes(header) + raw_payload
