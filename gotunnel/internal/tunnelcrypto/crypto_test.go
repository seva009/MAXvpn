package tunnelcrypto

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Vector produced by the original Python tunnel_crypto.py
// (secret "testsecret", CMD_DATA, conn 77, "hello from python").
const pyPacket = "ac19b6376cca662546bb9d22dfb984e1b1f8dab71d9848abf85c40b8cbc75c13cc1ea8d84209c5ff69b1378584a12f400734"

func TestDecryptPythonPacket(t *testing.T) {
	c, _ := New("testsecret")
	raw, _ := hex.DecodeString(pyPacket)
	typ, id, payload, err := c.Decrypt(raw)
	if err != nil || typ != CmdData || id != 77 || string(payload) != "hello from python" {
		t.Fatalf("got %d %d %q %v", typ, id, payload, err)
	}
}

func TestRoundTripAndConnectPayload(t *testing.T) {
	c, _ := New("")
	pkt, _ := c.Encrypt(CmdClose, 5, nil)
	typ, id, p, err := c.Decrypt(pkt)
	if err != nil || typ != CmdClose || id != 5 || len(p) != 0 {
		t.Fatal("roundtrip failed")
	}
	want, _ := hex.DecodeString("01bb6578616d706c652e636f6d")
	if !bytes.Equal(PackConnectPayload("example.com", 443), want) {
		t.Fatal("connect payload differs from python")
	}
	h, port, _ := UnpackConnectPayload(want)
	if h != "example.com" || port != 443 {
		t.Fatal("unpack")
	}
}

func TestAsymmetricKnockAndHandshake(t *testing.T) {
	callerPrivHex, callerPubHex, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	relayPrivHex, relayPubHex, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	callerPriv, _ := ParseKey(callerPrivHex)
	callerPub, _ := ParseKey(callerPubHex)
	relayPriv, _ := ParseKey(relayPrivHex)
	relayPub, _ := ParseKey(relayPubHex)

	// Test Knock UUID
	knockUUID, err := ComputeKnockUUID(callerPriv, relayPub, 0)
	if err != nil {
		t.Fatalf("ComputeKnockUUID: %v", err)
	}
	if !VerifyKnockUUID(relayPriv, [][]byte{callerPub}, knockUUID, 60) {
		t.Fatalf("VerifyKnockUUID failed for valid knock: %s", knockUUID)
	}
	fakePub := make([]byte, 32)
	if VerifyKnockUUID(relayPriv, [][]byte{fakePub}, knockUUID, 60) {
		t.Fatalf("VerifyKnockUUID accepted invalid caller")
	}

	// Test In-band Handshake
	initiator, err := NewHandshakeInitiator(callerPriv, relayPub)
	if err != nil {
		t.Fatalf("NewHandshakeInitiator: %v", err)
	}
	responder, err := NewHandshakeResponder(relayPriv, [][]byte{callerPub})
	if err != nil {
		t.Fatalf("NewHandshakeResponder: %v", err)
	}

	initPkt, err := initiator.CreateInitPacket()
	if err != nil {
		t.Fatalf("CreateInitPacket: %v", err)
	}
	respPkt, relayCrypto, err := responder.ProcessInitPacket(initPkt)
	if err != nil {
		t.Fatalf("ProcessInitPacket: %v", err)
	}
	callerCrypto, err := initiator.ProcessRespPacket(respPkt)
	if err != nil {
		t.Fatalf("ProcessRespPacket: %v", err)
	}

	// Test Bidirectional Transmission
	// Caller -> Relay
	c2rPkt, err := callerCrypto.Encrypt(CmdData, 100, []byte("request from caller"))
	if err != nil {
		t.Fatalf("caller encrypt: %v", err)
	}
	typ, id, payload, err := relayCrypto.Decrypt(c2rPkt)
	if err != nil || typ != CmdData || id != 100 || string(payload) != "request from caller" {
		t.Fatalf("relay decrypt failed: typ=%d id=%d payload=%s err=%v", typ, id, payload, err)
	}

	// Relay -> Caller
	r2cPkt, err := relayCrypto.Encrypt(CmdData, 100, []byte("response from relay"))
	if err != nil {
		t.Fatalf("relay encrypt: %v", err)
	}
	typ, id, payload, err = callerCrypto.Decrypt(r2cPkt)
	if err != nil || typ != CmdData || id != 100 || string(payload) != "response from relay" {
		t.Fatalf("caller decrypt failed: typ=%d id=%d payload=%s err=%v", typ, id, payload, err)
	}

	// Test Replay rejection
	_, _, err = responder.ProcessInitPacket(initPkt)
	if err == nil {
		t.Fatalf("expected replay rejection for duplicate init packet, got nil error")
	}
}

func TestCrossPlatformPythonGo(t *testing.T) {
	// Caller keys (Python will use these)
	callerPrivHex, callerPubHex, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Relay keys (Go will use these)
	relayPrivHex, relayPubHex, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	callerPub, _ := ParseKey(callerPubHex)
	relayPriv, _ := ParseKey(relayPrivHex)

	// Python script creates knock UUID and Handshake Init packet
	pyScript := fmt.Sprintf(`
import sys
sys.path.insert(0, "../../python")
from tunnel_crypto import compute_knock_uuid, HandshakeInitiator, parse_key

c_priv = parse_key("%s")
r_pub = parse_key("%s")

knock = compute_knock_uuid(c_priv, r_pub)
init = HandshakeInitiator(c_priv, r_pub)
pkt1 = init.create_init_packet()

# Output knock and init pkt
print(knock)
print(pkt1.hex())
`, callerPrivHex, relayPubHex)

	cmd := exec.Command("python3", "-c", pyScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python execution failed: %v, out: %s", err, string(out))
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		t.Fatalf("unexpected python output: %s", string(out))
	}
	pyKnock := strings.TrimSpace(lines[0])
	pyInitHex := strings.TrimSpace(lines[1])
	pyInitPkt, err := hex.DecodeString(pyInitHex)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Go verifies Python's knock UUID!
	if !VerifyKnockUUID(relayPriv, [][]byte{callerPub}, pyKnock, 60) {
		t.Fatalf("Go failed to verify Python's knock UUID: %s", pyKnock)
	}

	// 2. Go HandshakeResponder processes Python's Init packet!
	responder, err := NewHandshakeResponder(relayPriv, [][]byte{callerPub})
	if err != nil {
		t.Fatal(err)
	}
	respPkt, relayCrypto, err := responder.ProcessInitPacket(pyInitPkt)
	if err != nil {
		t.Fatalf("Go failed to process Python's Init packet: %v", err)
	}

	// 3. Python processes Go's Resp packet and sends an encrypted data packet to Go!
	pyScript2 := fmt.Sprintf(`
import sys
sys.path.insert(0, "../../python")
from tunnel_crypto import HandshakeInitiator, parse_key, CMD_DATA

c_priv = parse_key("%s")
r_pub = parse_key("%s")
resp_pkt = bytes.fromhex("%s")

# Reconstruct initiator state using same ephemeral?
# Or Python runs full roundtrip with Resp packet passed to it:
`, callerPrivHex, relayPubHex, hex.EncodeToString(respPkt))
	_ = pyScript2

	// We can also test Go relay encrypting data and Python decrypting:
	// But in pyScript, HandshakeInitiator held ephemeral state. So let's run a full pipe script:
	pipeScript := fmt.Sprintf(`
import sys
sys.path.insert(0, "../../python")
from tunnel_crypto import compute_knock_uuid, HandshakeInitiator, parse_key, CMD_DATA

c_priv = parse_key("%s")
r_pub = parse_key("%s")

init = HandshakeInitiator(c_priv, r_pub)
pkt1 = init.create_init_packet()
sys.stdout.write(pkt1.hex() + "\n")
sys.stdout.flush()

resp_hex = sys.stdin.readline().strip()
crypto = init.process_resp_packet(bytes.fromhex(resp_hex))

# Send encrypted packet to Go
c2r = crypto.encrypt(CMD_DATA, 55, b"hello from python caller")
sys.stdout.write(c2r.hex() + "\n")
sys.stdout.flush()

# Read encrypted packet from Go
r2c_hex = sys.stdin.readline().strip()
typ, cid, data = crypto.decrypt(bytes.fromhex(r2c_hex))
if typ == CMD_DATA and cid == 55 and data == b"hello from go relay":
    sys.stdout.write("OK\n")
    sys.stdout.flush()
`, callerPrivHex, relayPubHex)

	pCmd := exec.Command("python3", "-c", pipeScript)
	stdin, err := pCmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := pCmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := pCmd.Start(); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(stdout)

	// Create fresh responder so replay detector sees a new session
	responder, _ = NewHandshakeResponder(relayPriv, [][]byte{callerPub})

	// Read Python's Init packet
	initLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	initBytes, _ := hex.DecodeString(strings.TrimSpace(initLine))

	// Go processes Init packet
	respPkt, relayCrypto, err = responder.ProcessInitPacket(initBytes)
	if err != nil {
		t.Fatalf("Go responder error: %v", err)
	}

	// Send Go's Resp packet to Python
	_, _ = stdin.Write([]byte(hex.EncodeToString(respPkt) + "\n"))

	// Read Python's encrypted data packet
	c2rLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	c2rBytes, _ := hex.DecodeString(strings.TrimSpace(c2rLine))

	// Go decrypts Python's data packet
	typ, cid, data, err := relayCrypto.Decrypt(c2rBytes)
	if err != nil || typ != CmdData || cid != 55 || string(data) != "hello from python caller" {
		t.Fatalf("Go failed to decrypt Python data: %v, typ=%d cid=%d data=%s", err, typ, cid, data)
	}

	// Go encrypts response to Python
	r2cBytes, err := relayCrypto.Encrypt(CmdData, 55, []byte("hello from go relay"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = stdin.Write([]byte(hex.EncodeToString(r2cBytes) + "\n"))

	// Read Python's final OK
	okLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(okLine) != "OK" {
		t.Fatalf("Python reported error: %s", okLine)
	}
	_ = pCmd.Wait()
}


