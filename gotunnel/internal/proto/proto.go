// Package proto is a port of oneme_proto.py: it encodes/decodes the binary
// packets used on wss://api.oneme.ru/websocket, and decodes the LZ4+base64
// "vcp" (conversationParams) blob carried in incoming-call notifications.
// The wire layout is reproduced exactly from the Python source:
//
//	Header (10 bytes):
//	  byte 0:    version (10)
//	  byte 1:    cmd (0 = notification/request, 1 = response, 3 = error)
//	  byte 2-3:  seq (int16 big-endian)
//	  byte 4-5:  opcode (int16 big-endian)
//	  byte 6:    compression ratio (0 if uncompressed, else lz4 ratio)
//	  byte 7-9:  payload length (24-bit unsigned big-endian)
package proto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"
)

// Protocol constants - identical to oneme_proto.py
const (
	ProtoVersion = 10
	HeaderSize   = 10

	OpcodeInit         = 6
	OpcodeLogin        = 19
	OpcodeStartCall    = 78
	OpcodeIncomingCall = 137
	OpcodeGetCallToken = 158
)

// Packet is the decoded form of a frame, mirroring the dict returned by
// decode_packet() in Python.
type Packet struct {
	Cmd     byte
	Seq     int16
	Opcode  int16
	Payload interface{}
}

func init() {
	// Type 1 = BigInt (64-bit user/chat/message IDs), mirrors
	// msgpack_ext_hook in oneme_proto.py.
	msgpack.RegisterExt(1, (*BigIntExt)(nil))

	// Register generic fallback for other extension IDs so unknown ext types
	// never abort decoding, mirroring Python's ExtType(code, data).
	for i := -128; i <= 127; i++ {
		id := int8(i)
		if id != 1 && id != -1 { // -1 is reserved for msgpack timestamp
			msgpack.RegisterExt(id, (*RawExt)(nil))
		}
	}
}

// RawExt handles generic extension types not explicitly modeled.
type RawExt struct {
	Type int8
	Data []byte
}

func (r *RawExt) MarshalMsgpack() ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return r.Data, nil
}

func (r *RawExt) UnmarshalMsgpack(data []byte) error {
	r.Data = make([]byte, len(data))
	copy(r.Data, data)
	return nil
}

func (r *RawExt) String() string {
	if r == nil {
		return ""
	}
	return string(r.Data)
}

// BigIntExt decodes the OneMe/Max custom msgpack extension type 1, used for
// 64-bit IDs that don't fit msgpack's native int range cleanly. It mirrors
// msgpack_ext_hook: try to unpack the extension payload as nested msgpack
// first, falling back to a big-endian signed integer.
type BigIntExt struct {
	Value interface{}
}

// MarshalMsgpack is required to satisfy msgpack.MarshalerUnmarshaler for
// RegisterExt. The Go client never needs to emit this extension type.
func (b *BigIntExt) MarshalMsgpack() ([]byte, error) {
	return nil, fmt.Errorf("proto: BigIntExt encoding is not supported")
}

// UnmarshalMsgpack mirrors:
//
//	if code == 1:
//	    try: return msgpack.unpackb(data)
//	    except Exception: return int.from_bytes(data, byteorder="big", signed=True)
func (b *BigIntExt) UnmarshalMsgpack(data []byte) error {
	var inner interface{}
	r := bytes.NewReader(data)
	dec := msgpack.NewDecoder(r)
	dec.SetMapDecoder(decodeCustomMap)
	if err := dec.Decode(&inner); err == nil && r.Len() == 0 {
		b.Value = inner
		return nil
	}
	n := new(big.Int).SetBytes(data)
	if len(data) > 0 && data[0]&0x80 != 0 {
		// two's-complement negative value, matching Python's signed=True
		full := new(big.Int).Lsh(big.NewInt(1), uint(len(data)*8))
		n.Sub(n, full)
	}
	if n.IsInt64() {
		b.Value = n.Int64()
	} else {
		b.Value = n
	}
	return nil
}

func (b *BigIntExt) String() string {
	if b == nil {
		return ""
	}
	return fmt.Sprint(b.Value)
}

// decodeCustomMap allows maps with non-string keys (e.g. BigInt/Ext8 or integers,
// which OneMe uses for user IDs and chat IDs) to be decoded into map[string]interface{}.
func decodeCustomMap(d *msgpack.Decoder) (interface{}, error) {
	n, err := d.DecodeMapLen()
	if err != nil {
		return nil, err
	}
	if n == -1 {
		return nil, nil
	}
	m := make(map[string]interface{}, n)
	for i := 0; i < n; i++ {
		k, err := d.DecodeInterface()
		if err != nil {
			return nil, err
		}
		v, err := d.DecodeInterface()
		if err != nil {
			return nil, err
		}
		var keyStr string
		switch tk := k.(type) {
		case string:
			keyStr = tk
		case *BigIntExt:
			if tk != nil {
				keyStr = fmt.Sprint(tk.Value)
			}
		case fmt.Stringer:
			keyStr = tk.String()
		default:
			keyStr = fmt.Sprint(tk)
		}
		m[keyStr] = v
	}
	return m, nil
}

// DecodePacket mirrors decode_packet(data).
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("proto: data too short for header: %d bytes", len(data))
	}

	ver := data[0]
	cmd := data[1]
	seq := int16(binary.BigEndian.Uint16(data[2:4]))
	opcode := int16(binary.BigEndian.Uint16(data[4:6]))
	compRatio := data[6]
	payloadLen := int(data[7])<<16 | int(data[8])<<8 | int(data[9])
	_ = ver // version is not validated by the Python client either

	if HeaderSize+payloadLen > len(data) {
		return nil, fmt.Errorf("proto: truncated payload: expected %d, got %d", payloadLen, len(data)-HeaderSize)
	}
	payloadRaw := data[HeaderSize : HeaderSize+payloadLen]

	var payloadBytes []byte
	if compRatio > 0 {
		uncompressedSize := payloadLen * int(compRatio)
		dst := make([]byte, uncompressedSize)
		n, err := lz4.UncompressBlock(payloadRaw, dst)
		if err != nil {
			// In case ratio was an underestimate, retry with larger buffer
			dst = make([]byte, uncompressedSize*4+1024)
			n, err = lz4.UncompressBlock(payloadRaw, dst)
			if err != nil {
				return nil, fmt.Errorf("proto: lz4 decompress: %w", err)
			}
		}
		payloadBytes = dst[:n]
	} else {
		payloadBytes = payloadRaw
	}

	var payload interface{}
	if len(payloadBytes) > 0 {
		dec := msgpack.NewDecoder(bytes.NewReader(payloadBytes))
		dec.SetMapDecoder(decodeCustomMap)
		if err := dec.Decode(&payload); err != nil {
			return nil, fmt.Errorf("proto: msgpack decode: %w", err)
		}
	}

	return &Packet{Cmd: cmd, Seq: seq, Opcode: opcode, Payload: payload}, nil
}

// EncodePacket mirrors encode_packet(cmd, seq, opcode, payload). Outgoing
// packets are always sent uncompressed (comp_ratio = 0), same as the Python
// client.
func EncodePacket(cmd byte, seq int16, opcode int16, payload interface{}) ([]byte, error) {
	var rawPayload []byte
	if payload != nil {
		b, err := msgpack.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("proto: msgpack marshal: %w", err)
		}
		rawPayload = b
	}

	payloadLen := len(rawPayload)
	if payloadLen > 0xFFFFFF {
		return nil, fmt.Errorf("proto: payload exceeds 24-bit max length")
	}

	header := make([]byte, HeaderSize)
	header[0] = ProtoVersion
	header[1] = cmd
	binary.BigEndian.PutUint16(header[2:4], uint16(seq))
	binary.BigEndian.PutUint16(header[4:6], uint16(opcode))
	header[6] = 0 // uncompressed
	header[7] = byte(payloadLen >> 16)
	header[8] = byte(payloadLen >> 8)
	header[9] = byte(payloadLen)

	out := make([]byte, 0, HeaderSize+payloadLen)
	out = append(out, header...)
	out = append(out, rawPayload...)
	return out, nil
}

// DecodeVCP mirrors decode_vcp(vcp_str): the format is
// "<original_length>:<base64_lz4_compressed_json>" and the result is a
// generic map with keys like "tkn", "wse", "stne", "trne", "trnu", "trnp".
func DecodeVCP(vcpStr string) (map[string]interface{}, error) {
	origLenStr, b64Data, found := strings.Cut(vcpStr, ":")
	if !found {
		return nil, fmt.Errorf("proto: malformed vcp string (missing ':')")
	}
	origLen, err := strconv.Atoi(origLenStr)
	if err != nil {
		return nil, fmt.Errorf("proto: bad vcp length prefix: %w", err)
	}
	compressed, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, fmt.Errorf("proto: vcp base64 decode: %w", err)
	}
	dst := make([]byte, origLen)
	n, err := lz4.UncompressBlock(compressed, dst)
	if err != nil {
		return nil, fmt.Errorf("proto: vcp lz4 decompress: %w", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(dst[:n], &out); err != nil {
		return nil, fmt.Errorf("proto: vcp json decode: %w", err)
	}
	return out, nil
}
