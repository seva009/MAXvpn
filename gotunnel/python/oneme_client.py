import asyncio
import json
import logging
import os
import sys
import uuid
import websockets
import oneme_proto
from webrtc_call import OKWebRTCSignaling
from tunnel_crypto import verify_knock_uuid, generate_keypair, parse_key

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("oneme_client")

CONFIG_FILE = "config.json"

def load_or_create_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    
    default_config = {
        "viewer_id": 0,
        "token": "YOUR_ONEME_AUTH_TOKEN",
        "device_id": str(uuid.uuid4())
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(default_config, f, indent=2)
    return default_config

class OneMeClient:
    def __init__(self, config: dict):
        self.config = config
        self.viewer_id = config.get("viewer_id")
        self.token = config.get("token")
        self.device_id = config.get("device_id", str(uuid.uuid4()))
        priv_str = config.get("private_key")
        self.priv_key = parse_key(priv_str) if priv_str else None
        allowed_list = config.get("allowed_peers", [])
        self.allowed_peers = [parse_key(p) for p in allowed_list] if allowed_list else []
        self.seq = 0
        self.ws = None
        self.pending_responses = {}

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

            # Start receiver task
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
            res_init = await self.send_cmd(oneme_proto.OPCODE_INIT, init_payload)
            logger.debug(f"Session initialized successfully: {res_init}")

            # Step 2: Login with token (Opcode 19)
            if not self.token or self.token == "YOUR_ONEME_AUTH_TOKEN":
                logger.error(
                    f"Please set your real auth token in {CONFIG_FILE}!\n"
                    "You can get it from browser LocalStorage: localStorage.getItem('__oneme_auth')"
                )
                recv_task.cancel()
                return

            logger.debug("Logging in with saved auth token (opcode 19)...")
            login_payload = {
                "token": self.token,
                "chatsCount": 15
            }
            res_login = await self.send_cmd(oneme_proto.OPCODE_LOGIN, login_payload)
            profile = res_login.get("profile", {}).get("contact", {}) if isinstance(res_login, dict) else {}
            if profile.get("id"):
                self.viewer_id = profile["id"]
            user_name = profile.get("name") or profile.get("firstName") or str(self.viewer_id)
            logger.info(f"Logged in successfully as '{user_name}' (ID: {self.viewer_id})! Listening for incoming calls...")

            # Keep alive loop
            try:
                while True:
                    await asyncio.sleep(25)
            except asyncio.CancelledError:
                pass
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

                # Handle error responses from server (cmd == 3)
                if cmd == 3:
                    logger.error(f"[OneMe Error RX] seq={seq} opcode={opcode}: {payload}")
                    if seq in self.pending_responses:
                        self.pending_responses[seq].set_exception(
                            RuntimeError(f"Server error for opcode {opcode}: {payload}")
                        )
                    continue

                # If this is a response to our request (cmd == 1):
                if cmd == 1 and seq in self.pending_responses:
                    self.pending_responses[seq].set_result(payload)
                    continue

                # Handle ping/keepalive from server (opcode 1)
                if opcode == 1:
                    pong = oneme_proto.encode_packet(cmd=1, seq=seq, opcode=1, payload=None)
                    await self.ws.send(pong)
                    continue

                # Handle incoming call!
                if opcode == oneme_proto.OPCODE_INCOMING_CALL:
                    logger.info(">>> INCOMING CALL RECEIVED (opcode 137)! <<<")
                    logger.info(f"Call payload: {payload}")
                    asyncio.create_task(self._handle_incoming_call(payload))

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in recv_loop: {e}", exc_info=True)

    async def _handle_incoming_call(self, call_info: dict):
        conv_id = call_info.get("conversationId")
        caller_id = call_info.get("callerId")
        vcp_raw = call_info.get("vcp")
        logger.info(f"Handling incoming call from caller={caller_id}, conv_id={conv_id}")

        # Step 0: Call Knock screening
        if self.priv_key and self.allowed_peers:
            if not verify_knock_uuid(self.priv_key, self.allowed_peers, conv_id, 60):
                logger.warning(f"[Auth] REJECTING call from caller={caller_id}, conv_id={conv_id}: knock verification failed! Line kept free.")
                return
            logger.info(f"[Auth] Call knock token VERIFIED successfully for conv_id={conv_id}")

        vcp_params = {}
        if vcp_raw:
            try:
                vcp_params = oneme_proto.decode_vcp(vcp_raw)
                logger.info(f"Decoded call params! STUN={vcp_params.get('stne')}, TURN={vcp_params.get('trne')}")
            except Exception as e:
                logger.warning(f"Failed to decode vcp: {e}")

        # Exact conversation token from vcp
        call_token = vcp_params.get("tkn")
        if not call_token:
            logger.info("Requesting WebRTC call token (opcode 158 fallback)...")
            token_res = await self.send_cmd(oneme_proto.OPCODE_GET_CALL_TOKEN, {})
            call_token = token_res.get("token")

        # Resolve user_id:
        # In vcp_params["trnu"], the format is "<timestamp>:<ok_calls_user_id>".
        # videowebrtc.okcdn.ru requires this OkCDN user ID, NOT the chat profile ID!
        user_id = None
        if vcp_params.get("trnu"):
            parts = vcp_params["trnu"].split(":")
            if len(parts) > 1:
                user_id = parts[1]

        if not user_id:
            user_id = self.viewer_id

        logger.info(f"Using call token: {call_token[:15]}... for OkCDN userId: {user_id}")

        # Run WebRTC session
        is_video = call_info.get("isVideo", True)
        speed_duration = self.config.get("speed_test_duration", 5.0)
        mode = self.config.get("mode", "proxy")
        tunnel_secret = self.config.get("tunnel_secret", "oneme_webrtc_aes_tunnel_key")
        logger.info(f"Incoming call media mode: isVideo={is_video}, tunnelMode={mode}")
        webrtc_session = OKWebRTCSignaling(
            user_id=str(user_id),
            conv_id=conv_id,
            token=call_token,
            is_caller=False,
            remote_participant_id=str(caller_id) if caller_id else None,
            vcp_params=vcp_params,
            speed_test_duration=speed_duration,
            is_video=is_video,
            mode=mode,
            tunnel_secret=tunnel_secret,
            private_key=self.config.get("private_key"),
            allowed_peers=self.config.get("allowed_peers"),
            allow_local=self.config.get("allow_local", False)
        )

        try:
            logger.info("Starting WebRTC connection and DataChannel listener...")
            await webrtc_session.run()
            logger.info("Call finished!")
        except Exception as e:
            logger.error(f"Error during WebRTC call: {e}", exc_info=True)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OneMe WebRTC Relay / Callee Client")
    parser.add_argument("--config", "-c", type=str, default="config.json", help="Path to config JSON file")
    parser.add_argument("--mode", choices=["proxy", "speedtest"], default=None, help="Mode: proxy or speedtest")
    parser.add_argument("--secret", "-s", type=str, default=None, help="AES encryption secret passphrase")
    parser.add_argument("--privkey", type=str, default=None, help="Asymmetric Curve25519 private key (hex)")
    parser.add_argument("--allowed-peers", type=str, default=None, help="Comma-separated allowed caller public keys (hex)")
    parser.add_argument("--allow-local", "--allow-private", dest="allow_local", action="store_true", default=None, help="Allow clients to connect to local/private addresses (bypasses SSRF protection)")
    parser.add_argument("--gen-key", action="store_true", help="Generate Curve25519 keypair and exit")
    args = parser.parse_args()

    if args.gen_key:
        priv_hex, pub_hex = generate_keypair()
        print(f"Generated X25519 Keypair:")
        print(f"  Private Key: {priv_hex}")
        print(f"  Public Key:  {pub_hex}")
        sys.exit(0)

    cfg = load_or_create_config()
    if args.mode:
        cfg["mode"] = args.mode
    if args.secret:
        cfg["tunnel_secret"] = args.secret
    if args.privkey:
        cfg["private_key"] = args.privkey
    if args.allowed_peers:
        cfg["allowed_peers"] = [p.strip() for p in args.allowed_peers.split(",") if p.strip()]
    if args.allow_local is not None:
        cfg["allow_local"] = args.allow_local

    if cfg.get("allow_local"):
        logger.warning("[SECURITY WARNING] SSRF protection is disabled: clients can connect to private and local network destinations.")
    if not cfg.get("private_key") or not cfg.get("allowed_peers"):
        logger.warning("[SECURITY WARNING] No X25519 private key or allowed peers configured!")
        logger.warning("[SECURITY WARNING] Running in PSK fallback mode without cryptographic caller identity.")
        logger.warning("[SECURITY WARNING] To generate a keypair, run: python3 oneme_client.py --gen-key")
    if cfg.get("tunnel_secret", "oneme_webrtc_aes_tunnel_key") == "oneme_webrtc_aes_tunnel_key":
        logger.warning("[SECURITY ALERT] Using default hardcoded tunnel secret! Change 'tunnel_secret' in config.json or specify -s <secret>.")

    client = OneMeClient(cfg)
    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        logger.info("Terminated by user.")
