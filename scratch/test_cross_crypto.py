import subprocess
from tunnel_crypto import TunnelCrypto, CMD_CONNECT

tc = TunnelCrypto("my_secret_key")
# Pack connect payload: host="example.com", port=80
payload = tc.pack_connect_payload("example.com", 80)
pkt = tc.encrypt(CMD_CONNECT, 12345, payload)
with open("scratch/pkt_from_py.bin", "wb") as f:
    f.write(pkt)
print(f"Python wrote {len(pkt)} bytes")
