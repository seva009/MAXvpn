import argparse
import asyncio
import json
import logging
import os
import sys
from urllib.parse import urlparse, parse_qs
import uuid
import websockets
import oneme_proto
from webrtc_call import OKWebRTCSignaling
from tunnel_crypto import compute_knock_uuid, generate_keypair, parse_key

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("oneme_caller")

DEFAULT_CONFIG_CALLER = "config_caller.json"
DEFAULT_CONFIG_MAIN = "config.json"

def load_or_create_config(config_path: str = None) -> dict:
    if not config_path:
        if os.path.exists(DEFAULT_CONFIG_CALLER):
            config_path = DEFAULT_CONFIG_CALLER
        elif os.path.exists(DEFAULT_CONFIG_MAIN):
            config_path = DEFAULT_CONFIG_MAIN
        else:
            config_path = DEFAULT_CONFIG_CALLER

    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            data["_config_path"] = config_path
            return data

    default_config = {
        "callee_id": 0,
        "token": "YOUR_CALLER_AUTH_TOKEN",
        "device_id": str(uuid.uuid4()),
        "private_key": "",
        "peer_public_key": "",
        "tunnel_secret": "oneme_webrtc_aes_tunnel_key",
        "proxy_host": "127.0.0.1",
        "proxy_port": 1080,
        "mode": "proxy",
        "audio_only": False
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(default_config, f, indent=2)
    default_config["_config_path"] = config_path
    return default_config

class OneMeCaller:
    def __init__(
        self,
        token: str,
        device_id: str = None,
        callee_id: int = None,
        speed_test_duration: float = 5.0,
        speed_test_direction: str = "both",
        is_video: bool = True,
        mode: str = "proxy",
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 1080,
        tunnel_secret: str = "oneme_webrtc_aes_tunnel_key",
        private_key: str = None,
        peer_public_key: str = None
    ):
        self.token = token
        self.device_id = device_id or str(uuid.uuid4())
        self.callee_id = callee_id
        self.speed_test_duration = speed_test_duration
        self.speed_test_direction = speed_test_direction
        self.is_video = bool(is_video)
        self.mode = mode
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.tunnel_secret = tunnel_secret
        self.private_key_str = private_key
        self.peer_public_key_str = peer_public_key
        self.priv_key = parse_key(private_key) if private_key else None
        self.peer_pub_key = parse_key(peer_public_key) if peer_public_key else None
        self.seq = 0
        self.ws = None
        self.pending_responses = {}
        self.viewer_id = None

    def next_seq(self) -> int:
        s = self.seq
        self.seq += 1
        return s

    async def send_cmd(self, opcode: int, payload=None, expect_response: bool = True):
        seq = self.next_seq()
        pkt = oneme_proto.encode_packet(cmd=0, seq=seq, opcode=opcode, payload=payload)

        fut = None
        if expect_response:
            fut = asyncio.get_running_loop().create_future()
            self.pending_responses[seq] = fut

        logger.debug(f"[OneMe TX] cmd=0 seq={seq} opcode={opcode}")
        await self.ws.send(pkt)

        if fut:
            try:
                res = await asyncio.wait_for(fut, timeout=10.0)
                return res
            finally:
                self.pending_responses.pop(seq, None)
        return None

    async def run(self):
        ws_url = "wss://api.oneme.ru/websocket"
        logger.info(f"Connecting to OneMe gateway: {ws_url}...")

        headers = {
            "Origin": "https://web.max.ru",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0"
        }

        async with websockets.connect(ws_url, additional_headers=headers) as ws:
            self.ws = ws
            logger.info("Connected to wss://api.oneme.ru/websocket!")

            # Start background packet receiver
            recv_task = asyncio.create_task(self._recv_loop())

            # Step 1: Session Init (Opcode 6)
            init_payload = {
                "userAgent": {
                    "deviceType": "WEB",
                    "pushDeviceType": "WEBPUSH",
                    "locale": "ru",
                    "deviceLocale": "ru",
                    "osVersion": "Linux",
                    "deviceName": "Firefox",
                    "headerUserAgent": headers["User-Agent"],
                    "isPwa": False,
                    "appVersion": "26.10.3",
                    "screen": "1920x1080 1.0x",
                    "timezone": "Europe/Moscow"
                },
                "deviceId": self.device_id
            }
            logger.debug("Initializing session (opcode 6)...")
            await self.send_cmd(oneme_proto.OPCODE_INIT, init_payload)

            # Step 2: Login with auth token (Opcode 19)
            logger.debug("Logging in with caller auth token (opcode 19)...")
            login_payload = {
                "token": self.token,
                "chatsCount": 15
            }
            res_login = await self.send_cmd(oneme_proto.OPCODE_LOGIN, login_payload)
            profile = res_login.get("profile", {}).get("contact", {}) if isinstance(res_login, dict) else {}
            self.viewer_id = profile.get("id")
            user_name = profile.get("name") or profile.get("firstName") or str(self.viewer_id)
            logger.info(f"Logged in successfully as caller '{user_name}' (ID: {self.viewer_id})!")

            if not self.callee_id:
                logger.error("No callee ID specified! Pass as argument: python3 oneme_caller.py <callee_user_id>")
                recv_task.cancel()
                return

            # Step 3: Initiate call (Opcode 78)
            if self.priv_key and self.peer_pub_key:
                conversation_id = compute_knock_uuid(self.priv_key, self.peer_pub_key)
                logger.info(f"[Auth] Generated authenticated Call Knock conversationId: {conversation_id}")
            else:
                conversation_id = str(uuid.uuid4())

            internal_params = json.dumps({
                "deviceId": self.device_id,
                "sdkVersion": "2.8.13-beta.6",
                "clientAppKey": "",
                "platform": "WEB",
                "protocolVersion": 5,
                "domainId": "",
                "capabilities": "6A03F"
            })

            logger.info(f"Calling user ID {self.callee_id} (isVideo={self.is_video}, conversationId: {conversation_id})...")
            call_res = await self.send_cmd(oneme_proto.OPCODE_START_CALL, {
                "conversationId": conversation_id,
                "calleeIds": [int(self.callee_id)],
                "internalParams": internal_params,
                "isVideo": self.is_video
            })

            if not call_res:
                logger.error("No response received for opcode 78!")
                recv_task.cancel()
                return

            rejected = call_res.get("rejectedParticipants", [])
            if rejected:
                logger.error(f"Call was rejected by server: {rejected}")
                recv_task.cancel()
                return

            internal_caller_params_raw = call_res.get("internalCallerParams")
            if not internal_caller_params_raw:
                logger.error(f"Missing internalCallerParams in response: {call_res}")
                recv_task.cancel()
                return

            caller_params = json.loads(internal_caller_params_raw)
            endpoint = caller_params.get("endpoint", "")
            logger.info(f"Call initiated successfully! Endpoint: {endpoint[:80]}...")

            # Extract OK user ID and call token from endpoint URL
            parsed_query = parse_qs(urlparse(endpoint).query)
            ok_user_id = parsed_query.get("userId", [str(self.viewer_id)])[0]
            call_token = parsed_query.get("token", [""])[0]

            logger.info(f"Connecting to WebRTC media as caller (OkCDN userId: {ok_user_id})...")

            # Step 4: WebRTC caller signaling and DataChannel
            webrtc_session = OKWebRTCSignaling(
                user_id=ok_user_id,
                conv_id=conversation_id,
                token=call_token,
                is_caller=True,
                remote_participant_id=str(self.callee_id),
                vcp_params=caller_params,
                speed_test_duration=self.speed_test_duration,
                speed_test_direction=self.speed_test_direction,
                is_video=self.is_video,
                mode=self.mode,
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                tunnel_secret=self.tunnel_secret,
                private_key=self.private_key_str,
                peer_public_key=self.peer_public_key_str
            )

            try:
                # Wait for call negotiation and running tunnel/test
                await webrtc_session.run()
                logger.info("Caller session finished!")
            finally:
                recv_task.cancel()

    async def _recv_loop(self):
        try:
            async for raw_data in self.ws:
                if isinstance(raw_data, str):
                    logger.debug(f"[OneMe RX text] {raw_data}")
                    continue

                pkt = oneme_proto.decode_packet(raw_data)
                cmd = pkt["cmd"]
                seq = pkt["seq"]
                opcode = pkt["opcode"]
                payload = pkt["payload"]

                logger.debug(f"[OneMe RX] cmd={cmd} seq={seq} opcode={opcode}")

                if cmd == 3:
                    logger.error(f"[OneMe Error RX] seq={seq} opcode={opcode}: {payload}")
                    if seq in self.pending_responses:
                        self.pending_responses[seq].set_exception(
                            RuntimeError(f"Server error for opcode {opcode}: {payload}")
                        )
                    continue

                if cmd == 1 and seq in self.pending_responses:
                    self.pending_responses[seq].set_result(payload)
                    continue

                # Server ping keepalive
                if opcode == 1:
                    pong = oneme_proto.encode_packet(cmd=1, seq=seq, opcode=1, payload=None)
                    await self.ws.send(pong)
                    continue

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in recv_loop: {e}", exc_info=True)

def main():
    parser = argparse.ArgumentParser(description="OneMe WebRTC Headless Caller (PoC)")
    parser.add_argument("callee_id", nargs="?", type=int, default=None, help="Target user ID to call (optional if set in config)")
    parser.add_argument("--token", "-t", type=str, default=None, help="Caller account auth token")
    parser.add_argument("--config", "-c", type=str, default=None, help="Path to config JSON file (default: config_caller.json)")
    parser.add_argument("--device-id", "-d", type=str, default=None, help="Caller device UUID")
    parser.add_argument("--mode", choices=["proxy", "speedtest"], default=None, help="Operation mode: proxy or speedtest")
    parser.add_argument("--proxy-port", "-p", type=int, default=None, help="Local SOCKS5 proxy port (default: 1080)")
    parser.add_argument("--proxy-host", type=str, default=None, help="Local SOCKS5 proxy bind address (default: 127.0.0.1)")
    parser.add_argument("--secret", "-s", type=str, default=None, help="AES encryption secret passphrase")
    parser.add_argument("--speed-duration", type=float, default=None, help="Duration of speed test per direction in seconds (default: 5.0)")
    parser.add_argument("--speed-direction", choices=["both", "caller_to_client", "client_to_caller"], default=None, help="Speed test direction (default: both)")
    parser.add_argument("--audio-only", action="store_true", default=False, help="Start call as audio-only instead of video call")
    parser.add_argument("--privkey", type=str, default=None, help="Asymmetric Curve25519 private key (hex)")
    parser.add_argument("--peer-pubkey", type=str, default=None, help="Relay Curve25519 public key (hex)")
    parser.add_argument("--gen-key", action="store_true", help="Generate Curve25519 keypair and exit")
    args = parser.parse_args()

    if args.gen_key:
        priv_hex, pub_hex = generate_keypair()
        print(f"Generated X25519 Keypair:")
        print(f"  Private Key: {priv_hex}")
        print(f"  Public Key:  {pub_hex}")
        sys.exit(0)

    cfg = load_or_create_config(args.config)

    token = args.token or cfg.get("token")
    if not token or token == "YOUR_CALLER_AUTH_TOKEN":
        print(
            f"ERROR: Caller auth token is missing!\n"
            f"Please specify --token <TOKEN> or set 'token' in {cfg.get('_config_path', 'config_caller.json')}.\n"
            f"You can get the token from browser LocalStorage on the caller's account: localStorage.getItem('__oneme_auth')",
            file=sys.stderr
        )
        sys.exit(1)

    callee_id = args.callee_id or cfg.get("callee_id")
    if not callee_id:
        print(
            "ERROR: Target callee ID is missing!\n"
            f"Please pass as argument: python3 oneme_caller.py <callee_user_id>\n"
            f"or set 'callee_id' in {cfg.get('_config_path', 'config_caller.json')}.",
            file=sys.stderr
        )
        sys.exit(1)

    try:
        callee_id = int(callee_id)
    except (ValueError, TypeError):
        pass

    device_id = args.device_id or cfg.get("device_id") or str(uuid.uuid4())
    secret = args.secret or cfg.get("tunnel_secret", "oneme_webrtc_aes_tunnel_key")
    priv_key = args.privkey or cfg.get("private_key")
    peer_pub_key = args.peer_pubkey or cfg.get("peer_public_key")
    proxy_port = args.proxy_port or cfg.get("proxy_port", 1080)
    proxy_host = args.proxy_host or cfg.get("proxy_host", "127.0.0.1")
    mode = args.mode or cfg.get("mode", "proxy")
    speed_duration = args.speed_duration or cfg.get("speed_test_duration", 5.0)
    speed_direction = args.speed_direction or cfg.get("speed_test_direction", "both")

    audio_only = args.audio_only if args.audio_only else cfg.get("audio_only", False)
    is_video = not audio_only

    caller = OneMeCaller(
        token=token,
        device_id=device_id,
        callee_id=callee_id,
        speed_test_duration=speed_duration,
        speed_test_direction=speed_direction,
        is_video=is_video,
        mode=mode,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        tunnel_secret=secret,
        private_key=priv_key,
        peer_public_key=peer_pub_key
    )
    try:
        asyncio.run(caller.run())
    except KeyboardInterrupt:
        logger.info("Caller terminated by user.")

if __name__ == "__main__":
    main()
