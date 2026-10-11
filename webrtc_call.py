import asyncio
import json
import logging
import time
import traceback
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
import websockets
from aiortc import RTCPeerConnection, RTCSessionDescription, RTCDataChannel, RTCConfiguration, RTCIceServer
from aiortc.sdp import candidate_from_sdp
from aiortc.rtcdtlstransport import RTCDtlsTransport, RTCCertificate, State

from tunnel_crypto import (
    TunnelCrypto,
    DEFAULT_TUNNEL_SECRET,
    HandshakeInitiator,
    HandshakeResponder,
    parse_key,
)
from socks5_server import Socks5Server
from tunnel_relay import TunnelRelay

logger = logging.getLogger("webrtc_call")

# Silence verbose external libraries, but keep SCTP, DataChannel and ICE detailed
logging.getLogger("aiortc").setLevel(logging.WARNING)
logging.getLogger("aiortc.rtcsctptransport").setLevel(logging.DEBUG)
logging.getLogger("aiortc.rtcdatachannel").setLevel(logging.DEBUG)
logging.getLogger("aioice").setLevel(logging.INFO)
logging.getLogger("websockets").setLevel(logging.WARNING)

# Hook RTCPeerConnection.close
_orig_pc_close = RTCPeerConnection.close
async def _debug_pc_close(self):
    stack = "".join(traceback.format_stack())
    logger.warning(f"[RTCPeerConnection.close() CALLED]:\n{stack}")
    return await _orig_pc_close(self)
RTCPeerConnection.close = _debug_pc_close

# 1. Extend cipher list to support both ECDSA and RSA peer certificates
_orig_create_ssl_context = RTCCertificate._create_ssl_context
def _custom_create_ssl_context(self, srtp_profiles):
    ctx = _orig_create_ssl_context(self, srtp_profiles)
    ctx.set_cipher_list(
        b"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:"
        b"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:HIGH:!aNULL:!MD5"
    )
    return ctx
RTCCertificate._create_ssl_context = _custom_create_ssl_context

# 2. Hook DTLS state changes
_orig_dtls_set_state = RTCDtlsTransport._set_state
def _debug_dtls_set_state(self, state):
    logger.info(f"[WebRTC DTLS STATE] -> {state.name if hasattr(state, 'name') else state}")
    if state == State.FAILED or state == State.CLOSED:
        stack = "".join(traceback.format_stack())
        logger.warning(f"[WebRTC DTLS {state} TRIGGERED]:\n{stack}")
    return _orig_dtls_set_state(self, state)
RTCDtlsTransport._set_state = _debug_dtls_set_state

# 3. Hook DTLS handshake methods
_orig_do_handshake = RTCDtlsTransport._do_handshake
async def _debug_do_handshake(self):
    logger.debug(f"[DTLS] Starting handshake (role={self._role}, transport.role={self.transport.role})")
    try:
        await _orig_do_handshake(self)
        logger.debug(f"[DTLS] Handshake ended (encrypted={self.encrypted}, state={self._state})")
    except Exception as e:
        logger.error(f"[DTLS] Handshake exception: {e}", exc_info=True)
        raise
RTCDtlsTransport._do_handshake = _debug_do_handshake

_orig_validate_peer_identity = RTCDtlsTransport._validate_peer_identity
def _debug_validate_peer_identity(self, remoteParameters):
    logger.debug(f"[DTLS] Validating peer identity with {len(remoteParameters.fingerprints)} fingerprints")
    res = _orig_validate_peer_identity(self, remoteParameters)
    if self._state == State.FAILED:
        logger.error("[DTLS] FAILED during peer fingerprint validation!")
    return res
RTCDtlsTransport._validate_peer_identity = _debug_validate_peer_identity

_orig_setup_srtp = RTCDtlsTransport._setup_srtp
def _debug_setup_srtp(self):
    logger.debug(f"[DTLS] Setting up SRTP (selected={self._ssl.get_selected_srtp_profile()})")
    res = _orig_setup_srtp(self)
    if self._state == State.FAILED:
        logger.error("[DTLS] FAILED during SRTP setup!")
    return res
RTCDtlsTransport._setup_srtp = _debug_setup_srtp

from aiortc.rtcsctptransport import RTCSctpTransport
_orig_sctp_is_server = RTCSctpTransport.is_server.fget
@property
def _custom_sctp_is_server(self):
    if hasattr(self, "_force_is_server"):
        return self._force_is_server
    return _orig_sctp_is_server(self)
RTCSctpTransport.is_server = _custom_sctp_is_server

_orig_sctp_set_state = RTCSctpTransport._set_state
def _debug_sctp_set_state(self, state):
    old_state = getattr(self, "_association_state", None)
    if state != old_state:
        logger.info(f"[WebRTC SCTP state] -> {state.name if hasattr(state, 'name') else state}")
        if state == RTCSctpTransport.State.CLOSED:
            stack = "".join(traceback.format_stack())
            logger.warning(f"[WebRTC SCTP CLOSED TRIGGERED]:\n{stack}")
    return _orig_sctp_set_state(self, state)
RTCSctpTransport._set_state = _debug_sctp_set_state

_orig_sctp_abort = RTCSctpTransport._abort
async def _debug_sctp_abort(self):
    stack = "".join(traceback.format_stack())
    logger.warning(f"[WebRTC SCTP _abort() CALLED]:\n{stack}")
    return await _orig_sctp_abort(self)
RTCSctpTransport._abort = _debug_sctp_abort

_orig_receive_chunk = RTCSctpTransport._receive_chunk
async def _debug_receive_chunk(self, chunk):
    cname = type(chunk).__name__
    if cname in ("AbortChunk", "ErrorChunk", "ShutdownChunk", "ShutdownCompleteChunk"):
        params = getattr(chunk, "params", None)
        logger.warning(f"[WebRTC SCTP RX CRITICAL CHUNK] {cname}: params={params}")
    return await _orig_receive_chunk(self, chunk)
RTCSctpTransport._receive_chunk = _debug_receive_chunk

_orig_t1_expired = RTCSctpTransport._t1_expired
def _debug_t1_expired(self):
    logger.warning(f"[WebRTC SCTP T1 EXPIRED] failures={self._t1_failures}")
    return _orig_t1_expired(self)
RTCSctpTransport._t1_expired = _debug_t1_expired

_orig_t2_expired = RTCSctpTransport._t2_expired
def _debug_t2_expired(self):
    logger.warning(f"[WebRTC SCTP T2 EXPIRED] failures={self._t2_failures}")
    return _orig_t2_expired(self)
RTCSctpTransport._t2_expired = _debug_t2_expired

_orig_t3_expired = RTCSctpTransport._t3_expired
def _debug_t3_expired(self):
    logger.warning(f"[WebRTC SCTP T3 EXPIRED (packet loss / no SACK)] cwnd={self._cwnd} flight={self._flight_size}")
    return _orig_t3_expired(self)
RTCSctpTransport._t3_expired = _debug_t3_expired

# 4. Patch aioice Candidate.can_pair_with to prevent TURN 403 Forbidden IP on private IPs
import ipaddress
from aioice.candidate import Candidate
from aioice.ice import Connection, CandidatePair
import aioice.stun as stun

_orig_can_pair_with = Candidate.can_pair_with
def _custom_can_pair_with(self, other: "Candidate") -> bool:
    if not _orig_can_pair_with(self, other):
        return False
    try:
        a = ipaddress.ip_address(self.host)
        b = ipaddress.ip_address(other.host)
        # RFC 5766 / RFC 8656: Public TURN relays strictly forbid relaying to private/loopback/link-local IPv4/IPv6
        if self.type == "relay" and (b.is_private or b.is_loopback or b.is_link_local):
            return False
        if other.type == "relay" and (a.is_private or a.is_loopback or a.is_link_local):
            return False
    except ValueError:
        pass
    return True
Candidate.can_pair_with = _custom_can_pair_with

# 5. Patch aioice Connection.add_remote_candidate to immediately check trickled candidate pairs
_orig_add_remote_candidate = Connection.add_remote_candidate
async def _custom_add_remote_candidate(self, remote_candidate):
    await _orig_add_remote_candidate(self, remote_candidate)
    if remote_candidate is not None and self.remote_password is not None:
        for pair in self._check_list:
            if pair.remote_candidate == remote_candidate and pair.state in (CandidatePair.State.FROZEN, CandidatePair.State.WAITING):
                pair.state = CandidatePair.State.WAITING
                self.check_start_task(pair)
Connection.add_remote_candidate = _custom_add_remote_candidate

# 6. Patch aioice Connection.check_start to retry on temporary STUN error codes and handle pending remote_password
_orig_check_start = Connection.check_start
async def _custom_check_start(self, pair: CandidatePair) -> None:
    if self.remote_password is None:
        for _ in range(30):
            if self.remote_password is not None:
                break
            await asyncio.sleep(0.05)
        if self.remote_password is None:
            self.check_state(pair, CandidatePair.State.WAITING)
            return

    self.check_state(pair, CandidatePair.State.IN_PROGRESS)

    nominate = self.ice_controlling and not self.remote_is_lite
    request = self.build_request(pair, nominate=nominate)
    try:
        response, addr = await pair.protocol.request(
            request,
            pair.remote_addr,
            integrity_key=self.remote_password.encode("utf8"),
        )
    except stun.TransactionError as exc:
        if (
            exc.response
            and exc.response.attributes.get("ERROR-CODE", (None, None))[0] == 487
        ):
            if "ICE-CONTROLLING" in request.attributes:
                self.switch_role(ice_controlling=False)
            elif "ICE-CONTROLLED" in request.attributes:
                self.switch_role(ice_controlling=True)
            return await self.check_start(pair)
        elif (
            exc.response
            and exc.response.attributes.get("ERROR-CODE", (None, None))[0] in (400, 401, 431)
        ):
            retries = getattr(pair, "_temp_err_retries", 0)
            if retries < 4:
                pair._temp_err_retries = retries + 1
                logger.info(f"[aioice] Temporary STUN error on {pair}, retrying #{retries + 1} after 200ms...")
                await asyncio.sleep(0.2)
                return await self.check_start(pair)
            else:
                self.check_state(pair, CandidatePair.State.FAILED)
                self.check_complete(pair)
                return
        else:
            err_info = exc.response.attributes.get("ERROR-CODE") if exc.response else "No response"
            logger.warning(f"[aioice] STUN TransactionError on {pair}: {err_info}")
            self.check_state(pair, CandidatePair.State.FAILED)
            self.check_complete(pair)
            return
    except Exception as e:
        logger.warning(f"[aioice] Exception during check_start for {pair}: {e} ({type(e).__name__})")
        self.check_state(pair, CandidatePair.State.FAILED)
        self.check_complete(pair)
        return

    # check remote address matches
    if addr != pair.remote_addr:
        self.check_state(pair, CandidatePair.State.FAILED)
        self.check_complete(pair)
        return

    # success
    if nominate or pair.remote_nominated:
        pair.nominated = True
    elif self.ice_controlling and pair.component not in self._nominating:
        self._nominating.add(pair.component)
        request = self.build_request(pair, nominate=True)
        try:
            await pair.protocol.request(
                request,
                pair.remote_addr,
                integrity_key=self.remote_password.encode("utf8"),
            )
        except stun.TransactionError as exc:
            err_info = exc.response.attributes.get("ERROR-CODE") if exc.response else "No response"
            logger.warning(f"[aioice] STUN TransactionError nominating {pair}: {err_info}")
            self.check_state(pair, CandidatePair.State.FAILED)
            self.check_complete(pair)
            return
        except Exception as e:
            logger.warning(f"[aioice] Exception nominating {pair}: {e} ({type(e).__name__})")
            self.check_state(pair, CandidatePair.State.FAILED)
            self.check_complete(pair)
            return
        pair.nominated = True
    self.check_state(pair, CandidatePair.State.SUCCEEDED)
    self.check_complete(pair)
Connection.check_start = _custom_check_start

# 7. Hook aioice Connection.respond_error for detailed STUN diagnostics
_orig_respond_error = Connection.respond_error
def _custom_respond_error(self, request, addr, protocol, error_code):
    logger.warning(f"[aioice] Responding STUN ERROR {error_code} to {addr} (local_ufrag={self.local_username}, remote_ufrag={self.remote_username})")
    return _orig_respond_error(self, request, addr, protocol, error_code)
Connection.respond_error = _custom_respond_error

# 8. Hook aioice Connection.close for detailed ICE disconnect trace
_orig_aioice_close = Connection.close
async def _custom_aioice_close(self):
    stack = "".join(traceback.format_stack())
    logger.warning(f"[aioice Connection.close() CALLED]:\n{stack}")
    return await _orig_aioice_close(self)
Connection.close = _custom_aioice_close

# 9. Track incoming data and STUN packets to make STUN Consent Freshness resilient to bufferbloat/loss
_orig_aioice_data_received = Connection.data_received
def _custom_aioice_data_received(self, data, component):
    self._last_data_received_time = time.monotonic()
    return _orig_aioice_data_received(self, data, component)
Connection.data_received = _custom_aioice_data_received

_orig_aioice_request_received = Connection.request_received
def _custom_aioice_request_received(self, message, addr, protocol, raw_data):
    self._last_data_received_time = time.monotonic()
    return _orig_aioice_request_received(self, message, addr, protocol, raw_data)
Connection.request_received = _custom_aioice_request_received

# 10. Robust STUN Consent Freshness (RFC 7675)
# aiortc's default query_consent uses retransmissions=0 and 500ms timeout. Under heavy traffic
# (e.g. streaming/browsing), UDP packets easily experience queueing delays >500ms, triggering
# false timeouts. When 6 consecutive probes fail (30s), aioice unconditionally kills the call.
# We fix this by:
# 1) Allowing retransmissions=2 (giving each probe up to ~3.5s across 3 tries)
# 2) Checking if incoming data packets have been received recently. If traffic is active from peer,
#    consent is implicitly fresh per RFC 7675 Section 5.1.
# 3) Increasing failure threshold to 15 (~75s of silence) before declaring consent expired.
import random
from aioice.ice import CONSENT_INTERVAL

async def _custom_query_consent(self) -> None:
    failures = 0
    if not hasattr(self, "_last_data_received_time"):
        self._last_data_received_time = time.monotonic()

    while True:
        # randomize between 0.8 and 1.2 times CONSENT_INTERVAL
        await asyncio.sleep(CONSENT_INTERVAL * (0.8 + 0.4 * random.random()))

        for pair in list(self._nominated.values()):
            request = self.build_request(pair, nominate=False)
            try:
                await pair.protocol.request(
                    request,
                    pair.remote_addr,
                    integrity_key=self.remote_password.encode("utf8"),
                    retransmissions=2,
                )
                failures = 0
            except stun.TransactionError:
                last_rx = getattr(self, "_last_data_received_time", 0)
                time_since_rx = time.monotonic() - last_rx
                if time_since_rx < 30.0:
                    # Remote peer is actively sending data; consent is implicitly fresh (RFC 7675)
                    logger.debug(f"[aioice] Consent probe STUN timeout, but peer actively sending data (last rx {time_since_rx:.1f}s ago). Keeping consent alive.")
                    failures = 0
                else:
                    failures += 1
                    logger.warning(f"[aioice] Consent probe failed ({failures}/15), last rx {time_since_rx:.1f}s ago")
            except Exception as e:
                logger.debug(f"[aioice] Consent probe exception: {e}")
                failures += 1

            if failures >= 15:
                logger.warning(f"[aioice] Consent to send expired after {failures} consecutive failures! Closing connection.")
                self._query_consent_task = None
                return await self.close()

Connection.query_consent = _custom_query_consent


class OKWebRTCSignaling:
    """
    Handles signaling with wss://videowebrtc.okcdn.ru/ws2
    and manages the WebRTC RTCPeerConnection and RTCDataChannel.
    """
    def __init__(
        self,
        user_id: str,
        conv_id: str,
        token: str,
        is_caller: bool = False,
        remote_participant_id: str = None,
        vcp_params: dict = None,
        speed_test_duration: float = 5.0,
        speed_test_direction: str = "both",
        is_video: bool = True,
        mode: str = "proxy",
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 1080,
        tunnel_secret: str = DEFAULT_TUNNEL_SECRET,
        private_key: str = None,
        peer_public_key: str = None,
        allowed_peers: list[str] = None
    ):
        self.user_id = str(user_id)
        self.conv_id = conv_id
        self.token = token
        self.is_caller = is_caller
        self.speed_test_duration = float(speed_test_duration)
        self.speed_test_direction = str(speed_test_direction)
        self.is_video = bool(is_video)
        self.mode = str(mode).lower()
        self.proxy_host = str(proxy_host)
        self.proxy_port = int(proxy_port)
        self.tunnel_secret = str(tunnel_secret)
        self.tunnel = None
        self.seq = 1
        self.ws = None
        self.vcp_params = vcp_params or {}
        self.dc = None
        self.done_event = asyncio.Event()
        _orig_done_set = self.done_event.set
        def _debug_done_set():
            stack = "".join(traceback.format_stack())
            logger.warning(f"[WebRTC DONE_EVENT.set() CALLED]:\n{stack}")
            return _orig_done_set()
        self.done_event.set = _debug_done_set
        self.connected_event = asyncio.Event()
        self.remote_participant_id = str(remote_participant_id) if remote_participant_id else None
        self.remote_peer_id = None
        self._offer_sent = False

        # Asymmetric auth state
        self.priv_key = parse_key(private_key) if private_key else None
        self.peer_pub_key = parse_key(peer_public_key) if peer_public_key else None
        self.allowed_peers = [parse_key(p) for p in allowed_peers] if allowed_peers else []
        self.initiator = None
        self.responder = None
        self.handshake_done = asyncio.Event()
        self.watchdog_task = None

        # Speed test state
        self.speed_test_results = {}
        self._rx_bytes = 0
        self._rx_start_time = None
        self._rx_last_log_time = None
        self._rx_current_direction = None
        self._low_event = asyncio.Event()
        self._speed_test_running = False

        ice_servers = []
        # Callee format (vcp)
        if self.vcp_params.get("stne"):
            ice_servers.append(RTCIceServer(urls=self.vcp_params["stne"].split(",")))
        if self.vcp_params.get("trne"):
            ice_servers.append(RTCIceServer(
                urls=self.vcp_params["trne"].split(","),
                username=self.vcp_params.get("trnu"),
                credential=self.vcp_params.get("trnp")
            ))
        # Caller format (internalCallerParams)
        stun_dict = self.vcp_params.get("stun")
        if isinstance(stun_dict, dict) and stun_dict.get("urls"):
            ice_servers.append(RTCIceServer(urls=stun_dict["urls"]))
        turn_dict = self.vcp_params.get("turn")
        if isinstance(turn_dict, dict) and turn_dict.get("urls"):
            ice_servers.append(RTCIceServer(
                urls=turn_dict["urls"],
                username=turn_dict.get("username"),
                credential=turn_dict.get("credential")
            ))

        config = RTCConfiguration(iceServers=ice_servers) if ice_servers else None
        self.pc = RTCPeerConnection(configuration=config)

        # If caller, add standard audio transceiver and initialize DataChannel
        if self.is_caller:
            self.pc.addTransceiver("audio", direction="sendrecv")
            dc = self.pc.createDataChannel("tunnel_poc", ordered=True)
            if self.pc.sctp:
                self.pc.sctp._force_is_server = False
            self.setup_datachannel(dc)

        # Setup WebRTC listeners
        @self.pc.on("iceconnectionstatechange")
        def on_ice_state():
            logger.info(f"[WebRTC] ICE state: {self.pc.iceConnectionState}")
            if self.pc.iceConnectionState in ("failed", "closed"):
                self._handle_disconnect(f"ICE state: {self.pc.iceConnectionState}")

        @self.pc.on("connectionstatechange")
        def on_conn_state():
            logger.info(f"[WebRTC] Connection state: {self.pc.connectionState}")
            if self.pc.connectionState in ("failed", "closed"):
                self._handle_disconnect(f"Connection state: {self.pc.connectionState}")

        @self.pc.on("datachannel")
        def on_datachannel(channel: RTCDataChannel):
            logger.info(f"[WebRTC] Incoming DataChannel received: label={channel.label}")
            self.setup_datachannel(channel)

    def _handle_disconnect(self, reason: str = ""):
        if getattr(self, "_stopping", False):
            return
        self._stopping = True
        logger.info(f"[WebRTC] Session disconnect triggered ({reason}). Cleaning up...")
        if self.tunnel and hasattr(self.tunnel, "stop"):
            res = self.tunnel.stop()
            if asyncio.iscoroutine(res):
                asyncio.create_task(res)
        self.done_event.set()

    def send_channel_bytes(self, data: bytes) -> bool:
        """Sends raw bytes into the WebRTC DataChannel. Returns True on success."""
        if not self.dc:
            logger.warning(f"[DataChannel TX error]: dc is None, dropped {len(data)} bytes")
            return False
        if self.dc.readyState != "open":
            logger.warning(f"[DataChannel TX error]: readyState is '{self.dc.readyState}' (not open), dropped {len(data)} bytes")
            return False
        try:
            self.dc.send(data)
            return True
        except Exception as e:
            logger.error(f"[DataChannel TX error]: {e}")
            return False

    async def _start_proxy_tunnel(self):
        crypto = TunnelCrypto(self.tunnel_secret)
        if self.is_caller:
            self.tunnel = Socks5Server(
                crypto=crypto,
                send_packet_fn=self.send_channel_bytes,
                host=self.proxy_host,
                port=self.proxy_port,
                get_buffered_amount=lambda: self.dc.bufferedAmount if self.dc else 0
            )
            await self.tunnel.start()
            logger.info(
                f"\n{'='*70}\n"
                f"[SOCKS5 PROXY ACTIVE] Listening on {self.proxy_host}:{self.proxy_port}\n"
                f"Traffic is encrypted with AES-256-GCM and tunneled over WebRTC!\n"
                f"Test from another terminal:\n"
                f"  curl -x socks5h://{self.proxy_host}:{self.proxy_port} https://api.ipify.org\n"
                f"{'='*70}\n"
            )
        else:
            if not self.tunnel:
                self.tunnel = TunnelRelay(
                    crypto=crypto,
                    send_packet_fn=self.send_channel_bytes,
                    get_buffered_amount=lambda: self.dc.bufferedAmount if self.dc else 0
                )
                logger.info(
                    f"\n{'='*70}\n"
                    f"[REMOTE RELAY ACTIVE] Ready to forward decrypted traffic to Internet!\n"
                    f"{'='*70}\n"
                )

    def _handle_proxy_control_message(self, message: str):
        if message == "ping":
            if self.dc and self.dc.readyState == "open":
                try:
                    self.dc.send("pong")
                except Exception:
                    pass
        elif message == "pong":
            pass
        else:
            logger.debug(f"[WebRTC DataChannel text RX] {message}")

    async def _proxy_keepalive_loop(self):
        try:
            while not self.done_event.is_set():
                await asyncio.sleep(15.0)
                if self.dc and self.dc.readyState == "open":
                    try:
                        self.dc.send("ping")
                    except Exception:
                        pass
                if self.ws and not self.ws.closed:
                    try:
                        await self.ws.ping()
                    except Exception:
                        pass
        except asyncio.CancelledError:
            pass

    async def _start_asym_caller_handshake(self):
        try:
            self.initiator = HandshakeInitiator(self.priv_key, self.peer_pub_key)
            init_pkt = self.initiator.create_init_packet()
            logger.info("[Auth] Sending Curve25519 Handshake Init to relay...")
            self.send_channel_bytes(init_pkt)

            async def _waiter():
                try:
                    await asyncio.wait_for(self.handshake_done.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    if not self.tunnel:
                        logger.error("[Auth] Handshake response timeout (3s) from relay! Closing connection.")
                        self.done_event.set()
            asyncio.create_task(_waiter())
        except Exception as e:
            logger.error(f"[Auth] Error creating handshake init packet: {e}", exc_info=True)
            self.done_event.set()

    def setup_datachannel(self, channel: RTCDataChannel):
        self.dc = channel
        channel.bufferedAmountLowThreshold = 128 * 1024

        is_asym = bool(self.priv_key and (self.peer_pub_key if self.is_caller else self.allowed_peers))

        # For remote relay (client), initialize responder or TunnelRelay
        if self.mode == "proxy" and not self.is_caller:
            if is_asym:
                self.responder = HandshakeResponder(self.priv_key, self.allowed_peers)
                logger.info("[Auth] Asymmetric authentication enabled. Awaiting Handshake Init (3s timeout)...")
                async def _watchdog():
                    try:
                        await asyncio.sleep(3.0)
                        if not self.tunnel:
                            logger.warning("[Auth] Handshake timeout (3s)! Dropping unauthorized call.")
                            self.done_event.set()
                    except asyncio.CancelledError:
                        pass
                self.watchdog_task = asyncio.create_task(_watchdog())
            elif not self.tunnel:
                crypto = TunnelCrypto(self.tunnel_secret)
                self.tunnel = TunnelRelay(
                    crypto=crypto,
                    send_packet_fn=self.send_channel_bytes,
                    get_buffered_amount=lambda: self.dc.bufferedAmount if self.dc else 0
                )
                logger.info(
                    f"\n{'='*70}\n"
                    f"[REMOTE RELAY ACTIVE] Ready to forward decrypted traffic to Internet!\n"
                    f"{'='*70}\n"
                )

        channel_opened = False
        def trigger_channel_opened():
            nonlocal channel_opened
            if channel_opened:
                return
            channel_opened = True
            logger.info("[WebRTC DataChannel] OPENED successfully!")
            if self.mode == "proxy":
                if self.is_caller and not self.tunnel:
                    if is_asym:
                        asyncio.create_task(self._start_asym_caller_handshake())
                    else:
                        asyncio.create_task(self._start_proxy_tunnel())
            else:
                if self.is_caller:
                    logger.info("[WebRTC DataChannel] Sending 'ping'...")
                    channel.send("ping")

        @channel.on("bufferedamountlow")
        def on_low():
            self._low_event.set()

        @channel.on("open")
        def on_open():
            trigger_channel_opened()

        @channel.on("message")
        def on_message(message):
            if self.mode == "proxy":
                if isinstance(message, bytes):
                    if not self.tunnel:
                        if not self.is_caller and self.responder:
                            try:
                                resp_pkt, crypto = self.responder.process_init_packet(message)
                                self.send_channel_bytes(resp_pkt)
                                if self.watchdog_task:
                                    self.watchdog_task.cancel()
                                self.tunnel = TunnelRelay(
                                    crypto=crypto,
                                    send_packet_fn=self.send_channel_bytes,
                                    get_buffered_amount=lambda: self.dc.bufferedAmount if self.dc else 0
                                )
                                logger.info("[Auth] Handshake SUCCESSFUL! Caller authenticated.")
                                logger.info(
                                    f"\n{'='*70}\n"
                                    f"[REMOTE RELAY ACTIVE] Ready to forward decrypted traffic to Internet!\n"
                                    f"{'='*70}\n"
                                )
                            except Exception as e:
                                logger.error(f"[Auth] Handshake verification failed: {e}. Dropping call!")
                                self.done_event.set()
                            return
                        elif self.is_caller and self.initiator:
                            try:
                                crypto = self.initiator.process_resp_packet(message)
                                self.handshake_done.set()
                                logger.info("[Auth] Asymmetric mutual handshake successful! SOCKS5 proxy active.")
                                self.tunnel = Socks5Server(
                                    crypto=crypto,
                                    send_packet_fn=self.send_channel_bytes,
                                    host=self.proxy_host,
                                    port=self.proxy_port,
                                    get_buffered_amount=lambda: self.dc.bufferedAmount if self.dc else 0
                                )
                                asyncio.create_task(self.tunnel.start())
                                logger.info(
                                    f"\n{'='*70}\n"
                                    f"[SOCKS5 PROXY ACTIVE] Listening on {self.proxy_host}:{self.proxy_port}\n"
                                    f"Traffic is encrypted with mutual Curve25519 session keys and tunneled over WebRTC!\n"
                                    f"Test from another terminal:\n"
                                    f"  curl -x socks5h://{self.proxy_host}:{self.proxy_port} https://api.ipify.org\n"
                                    f"{'='*70}\n"
                                    )
                            except Exception as e:
                                logger.error(f"[Auth] Handshake response failed: {e}. Closing connection!")
                                self.done_event.set()
                            return
                        else:
                            logger.warning(f"[WebRTC DataChannel RX] Received {len(message)} bytes but tunnel is not ready yet!")
                    else:
                        self.tunnel.handle_channel_packet(message)
                elif isinstance(message, str):
                    self._handle_proxy_control_message(message)
            else:
                if isinstance(message, bytes):
                    self._handle_speed_test_chunk(message)
                elif isinstance(message, str):
                    self._handle_control_message(message)

        @channel.on("error")
        def on_error(error):
            logger.error(f"[WebRTC DataChannel ERROR]: {error}")

        @channel.on("close")
        def on_close():
            stack = "".join(traceback.format_stack())
            logger.info(f"[WebRTC DataChannel] Closed. Triggered from:\n{stack}")
            if self.mode == "proxy":
                self._handle_disconnect("DataChannel closed")

        # In aiortc, incoming DataChannel on callee already has readyState == 'open'
        if channel.readyState == "open":
            trigger_channel_opened()

    def _handle_speed_test_chunk(self, chunk: bytes):
        now = time.time()
        if self._rx_start_time is None:
            self._rx_start_time = now
            self._rx_last_log_time = now

        self._rx_bytes += len(chunk)

        if self._rx_last_log_time and (now - self._rx_last_log_time >= 1.0):
            elapsed = now - self._rx_start_time
            mb = self._rx_bytes / (1024 * 1024)
            mb_s = mb / max(elapsed, 0.001)
            mbps = (self._rx_bytes * 8) / (max(elapsed, 0.001) * 1_000_000)
            dir_label = "Caller -> Client" if self._rx_current_direction == "caller_to_client" else ("Client -> Caller" if self._rx_current_direction == "client_to_caller" else (self._rx_current_direction or "RX"))
            logger.info(f"[SpeedTest RX] Progress ({dir_label}): {mb:.2f} MB in {elapsed:.1f}s ({mb_s:.2f} MB/s | {mbps:.2f} Mbps)")
            self._rx_last_log_time = now

    def _handle_control_message(self, message: str):
        if message == "ping":
            logger.info("[WebRTC DataChannel] Received 'ping'. Replying with 'pong'...")
            self.dc.send("pong")
            return
        elif message == "pong":
            logger.info("[WebRTC DataChannel] 'pong' received! Handshake SUCCESSFUL!")
            if self.is_caller:
                logger.info("[WebRTC DataChannel] Initiating data transfer speed test...")
                asyncio.create_task(self._run_caller_speed_test())
            return

        try:
            ctrl = json.loads(message)
        except Exception:
            logger.info(f"[WebRTC DataChannel] Received text message: {message!r}")
            return

        msg_type = ctrl.get("type")
        if msg_type == "speedtest_start":
            direction = ctrl.get("direction", "unknown")
            duration = ctrl.get("duration", self.speed_test_duration)
            dir_label = "Caller -> Client" if direction == "caller_to_client" else ("Client -> Caller" if direction == "client_to_caller" else direction)
            logger.info(f"[SpeedTest RX] Speed test START received: {dir_label} (planned duration: {duration:.1f}s)")
            self._rx_bytes = 0
            self._rx_start_time = None
            self._rx_last_log_time = None
            self._rx_current_direction = direction

        elif msg_type == "speedtest_end":
            direction = ctrl.get("direction", self._rx_current_direction or "unknown")
            now = time.time()
            start = self._rx_start_time or now
            duration = max(now - start, 0.001)
            mb = self._rx_bytes / (1024 * 1024)
            mb_s = mb / duration
            mbps = (self._rx_bytes * 8) / (duration * 1_000_000)

            dir_label = "Caller -> Client" if direction == "caller_to_client" else ("Client -> Caller" if direction == "client_to_caller" else direction)
            logger.info(
                f"\n{'='*70}\n"
                f"[SPEED TEST RESULT] Direction: {dir_label}\n"
                f"  Transferred: {mb:.2f} MB ({self._rx_bytes:,} bytes)\n"
                f"  Duration:    {duration:.2f} s\n"
                f"  Speed:       {mb_s:.2f} MB/s ({mbps:.2f} Mbps)\n"
                f"{'='*70}"
            )

            report = {
                "type": "speedtest_report",
                "direction": direction,
                "bytes": self._rx_bytes,
                "duration": duration,
                "mb_s": mb_s,
                "mbps": mbps
            }
            self.speed_test_results[direction] = report
            try:
                self.dc.send(json.dumps(report))
            except Exception as e:
                logger.error(f"[SpeedTest] Failed to send report: {e}")

        elif msg_type == "speedtest_report":
            direction = ctrl.get("direction", "unknown")
            mb = ctrl.get("bytes", 0) / (1024 * 1024)
            duration = ctrl.get("duration", 0)
            mb_s = ctrl.get("mb_s", 0)
            mbps = ctrl.get("mbps", 0)

            dir_label = "Caller -> Client" if direction == "caller_to_client" else ("Client -> Caller" if direction == "client_to_caller" else direction)
            logger.info(
                f"\n{'='*70}\n"
                f"[SPEED TEST CONFIRMED by remote] Direction: {dir_label}\n"
                f"  Transferred: {mb:.2f} MB ({ctrl.get('bytes', 0):,} bytes)\n"
                f"  Duration:    {duration:.2f} s\n"
                f"  Speed:       {mb_s:.2f} MB/s ({mbps:.2f} Mbps)\n"
                f"{'='*70}"
            )
            self.speed_test_results[direction] = ctrl

        elif msg_type == "speedtest_request_reverse":
            duration = ctrl.get("duration", self.speed_test_duration)
            logger.info(f"[SpeedTest] Reverse speed test requested (Client -> Caller) for {duration:.1f}s...")
            asyncio.create_task(self._send_speed_stream("client_to_caller", duration))

        elif msg_type == "speedtest_done":
            logger.info("[SpeedTest] Remote signaled speed test completion.")
            self._print_speed_summary()
            asyncio.create_task(self._finish_after_delay(1.5))

    async def _send_speed_stream(self, direction: str, duration: float):
        chunk_size = 32768  # 32 KB chunk size
        chunk = b"\x00" * chunk_size
        total_sent = 0

        dir_label = "Caller -> Client" if direction == "caller_to_client" else ("Client -> Caller" if direction == "client_to_caller" else direction)
        logger.info(f"[SpeedTest TX] Starting data stream ({dir_label}) for {duration:.1f}s...")

        try:
            self.dc.send(json.dumps({
                "type": "speedtest_start",
                "direction": direction,
                "duration": duration
            }))
        except Exception as e:
            logger.error(f"[SpeedTest TX] Failed to send speedtest_start: {e}")
            return

        t0 = time.time()
        last_log = t0
        while time.time() - t0 < duration:
            if not self.dc or self.dc.readyState != "open":
                logger.warning("[SpeedTest TX] DataChannel closed during stream!")
                break

            # Backpressure control
            while self.dc.bufferedAmount > 256 * 1024:
                if self.dc.readyState != "open":
                    break
                self._low_event.clear()
                try:
                    await asyncio.wait_for(self._low_event.wait(), timeout=0.05)
                except asyncio.TimeoutError:
                    break

            try:
                self.dc.send(chunk)
                total_sent += len(chunk)
            except Exception as e:
                logger.error(f"[SpeedTest TX] Error sending chunk: {e}")
                break

            now = time.time()
            if now - last_log >= 1.0:
                elapsed = now - t0
                mb = total_sent / (1024 * 1024)
                mb_s = mb / max(elapsed, 0.001)
                mbps = (total_sent * 8) / (max(elapsed, 0.001) * 1_000_000)
                logger.info(f"[SpeedTest TX] Progress ({dir_label}): {mb:.2f} MB sent ({mb_s:.2f} MB/s | {mbps:.2f} Mbps)")
                last_log = now

        elapsed = time.time() - t0
        logger.info(f"[SpeedTest TX] Finished stream ({dir_label}): {total_sent/(1024*1024):.2f} MB in {elapsed:.2f}s")

        try:
            self.dc.send(json.dumps({
                "type": "speedtest_end",
                "direction": direction,
                "total_sent": total_sent,
                "duration": elapsed
            }))
        except Exception as e:
            logger.error(f"[SpeedTest TX] Failed to send speedtest_end: {e}")

    async def _run_caller_speed_test(self):
        if self._speed_test_running:
            return
        self._speed_test_running = True

        logger.info("\n" + "=" * 70)
        logger.info(">>> STARTING DATA CHANNEL THROUGHPUT SPEED TEST <<<")
        logger.info(f"Mode: {self.speed_test_direction} | Duration: {self.speed_test_duration}s per phase")
        logger.info("=" * 70 + "\n")

        # Phase 1: Caller -> Client
        if self.speed_test_direction in ("both", "caller_to_client"):
            await self._send_speed_stream("caller_to_client", self.speed_test_duration)

            # Wait for client's report
            wait_timeout = self.speed_test_duration + 5.0
            t_wait = time.time()
            while "caller_to_client" not in self.speed_test_results and (time.time() - t_wait < wait_timeout):
                await asyncio.sleep(0.1)

        # Phase 2: Client -> Caller
        if self.speed_test_direction in ("both", "client_to_caller"):
            logger.info("[SpeedTest] Requesting reverse test (Client -> Caller)...")
            try:
                self.dc.send(json.dumps({
                    "type": "speedtest_request_reverse",
                    "duration": self.speed_test_duration
                }))
            except Exception as e:
                logger.error(f"[SpeedTest] Failed to send speedtest_request_reverse: {e}")

            # Wait for client to stream and our RX report to be generated
            wait_timeout = self.speed_test_duration * 2 + 10.0
            t_wait = time.time()
            while "client_to_caller" not in self.speed_test_results and (time.time() - t_wait < wait_timeout):
                await asyncio.sleep(0.1)

        # Notify callee that speedtest is completely finished
        try:
            self.dc.send(json.dumps({"type": "speedtest_done"}))
        except Exception:
            pass

        self._print_speed_summary()
        await self._finish_after_delay(1.5)

    def _print_speed_summary(self):
        lines = [
            "",
            "=" * 70,
            f"          DATA CHANNEL SPEED TEST SUMMARY ({'Caller' if self.is_caller else 'Client'})",
            "-" * 70
        ]
        has_results = False
        if "caller_to_client" in self.speed_test_results:
            r = self.speed_test_results["caller_to_client"]
            mb = r.get("bytes", 0) / (1024 * 1024)
            dur = r.get("duration", 0)
            mb_s = r.get("mb_s", 0)
            mbps = r.get("mbps", 0)
            lines.append(f"  Caller -> Client:  {mb_s:6.2f} MB/s ({mbps:6.2f} Mbps)  [{mb:.2f} MB in {dur:.2f}s]")
            has_results = True

        if "client_to_caller" in self.speed_test_results:
            r = self.speed_test_results["client_to_caller"]
            mb = r.get("bytes", 0) / (1024 * 1024)
            dur = r.get("duration", 0)
            mb_s = r.get("mb_s", 0)
            mbps = r.get("mbps", 0)
            lines.append(f"  Client -> Caller:  {mb_s:6.2f} MB/s ({mbps:6.2f} Mbps)  [{mb:.2f} MB in {dur:.2f}s]")
            has_results = True

        if not has_results:
            lines.append("  No speed test results recorded.")

        lines.append("=" * 70)
        lines.append("")
        logger.info("\n".join(lines))

    async def _finish_after_delay(self, seconds: float):
        await asyncio.sleep(seconds)
        self.done_event.set()

    def _target_participant_id(self):
        if self.remote_participant_id and str(self.remote_participant_id).isdigit():
            return int(self.remote_participant_id)
        return self.remote_participant_id

    async def _send_offer(self):
        if self._offer_sent:
            return
        self._offer_sent = True
        logger.info(f"[WebRTC] Creating SDP offer for remote participant {self.remote_participant_id}...")
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)

        # Wait briefly for ICE gathering so all candidates are in the offer SDP
        try:
            for _ in range(30):
                if self.pc.iceGatheringState == "complete":
                    break
                await asyncio.sleep(0.05)
        except Exception:
            pass

        target_pid = self._target_participant_id()
        logger.info(f"[WebRTC] Sending SDP offer (gathering={self.pc.iceGatheringState}) to {target_pid}...")
        # Strip local candidates from the SDP offer to force routing through the server
        import re
        stripped_sdp = re.sub(r'(?m)^(a=candidate:|a=end-of-candidates).*\r?\n?', '', self.pc.localDescription.sdp)
        await self.send_command(
            "transmit-data",
            participantId=target_pid,
            data={
                "sdp": {
                    "type": "offer",
                    "sdp": stripped_sdp
                },
                "animojiVersion": 1
            }
        )

        # Trickle srflx and relay candidates. Skip host candidates to avoid
        # P2P connections that fail B2BUA ufrag auth.
        seen_cands = set()
        for line in self.pc.localDescription.sdp.splitlines():
            if line.startswith("a=candidate:"):
                c_line = line[2:].strip()
                if " typ host" in c_line:
                    continue
                if c_line in seen_cands:
                    continue
                seen_cands.add(c_line)
                await self.send_command(
                    "transmit-data",
                    participantId=target_pid,
                    data={
                        "candidate": {
                            "candidate": c_line,
                            "sdpMid": "0",
                            "sdpMLineIndex": 0
                        }
                    }
                )

    async def send_command(self, cmd_name: str, **params):
        if not self.ws:
            return
        payload = {
            "command": cmd_name,
            "sequence": self.seq,
            **params
        }
        self.seq += 1
        logger.debug(f"[Signaling TX] {payload}")
        await self.ws.send(json.dumps(payload))

    async def run(self):
        tgt = "start" if self.is_caller else "accept"
        params = {
            "userId": self.user_id,
            "entityType": "USER",
            "deviceIdx": "0",
            "conversationId": self.conv_id,
            "token": self.token,
            "platform": "WEB",
            "appVersion": "26.10.3",
            "version": "5",
            "device": "browser",
            "capabilities": "6A03F",
            "clientType": "one_me",
            "tgt": tgt
        }
        raw_endpoint = self.vcp_params.get("endpoint") or self.vcp_params.get("wse", "wss://videowebrtc.okcdn.ru/ws2")
        parsed = urlparse(raw_endpoint)
        existing_params = dict(parse_qsl(parsed.query))

        merged_params = {**params, **existing_params}
        for k in ["tgt", "appVersion", "platform", "version", "device", "capabilities", "clientType", "deviceIdx"]:
            merged_params[k] = params[k]

        ws_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(merged_params), parsed.fragment))
        logger.info(f"Connecting to WebRTC signaling: {ws_url[:100]}...")

        async with websockets.connect(ws_url) as ws:
            self.ws = ws
            logger.info("[Signaling] Connected to ws2!")

            # Start listening immediately
            listen_task = asyncio.create_task(self._listen_loop())

            # Accept call if we are callee (wait for server connection greeting first)
            if not self.is_caller:
                try:
                    await asyncio.wait_for(self.connected_event.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    logger.warning("[Signaling] Timeout waiting for 'connection' greeting, sending accept-call anyway...")

                logger.info(f"[Signaling] Sending accept-call (isAudioEnabled=True, isVideoEnabled={self.is_video})...")
                await self.send_command(
                    "accept-call",
                    mediaSettings={"isAudioEnabled": True, "isVideoEnabled": self.is_video}
                )

            if self.mode == "proxy":
                logger.info("[Signaling] WebRTC proxy session established and running indefinitely.")
                keepalive_task = asyncio.create_task(self._proxy_keepalive_loop())
                try:
                    await self.done_event.wait()
                except asyncio.CancelledError:
                    pass
                finally:
                    keepalive_task.cancel()
                    if self.tunnel:
                        if hasattr(self.tunnel, "stop"):
                            res = self.tunnel.stop()
                            if asyncio.iscoroutine(res):
                                try:
                                    await asyncio.wait_for(res, timeout=2.0)
                                except Exception:
                                    pass
            else:
                total_timeout = max(120.0, self.speed_test_duration * 4 + 30.0)
                try:
                    await asyncio.wait_for(self.done_event.wait(), timeout=total_timeout)
                except asyncio.TimeoutError:
                    logger.warning("[Signaling] Call timed out waiting for DataChannel completion.")

            # Send hangup
            logger.info("[Signaling] Sending hangup...")
            try:
                await self.send_command("hangup", reason="HUNGUP", hangupType="HUNGUP")
                await asyncio.sleep(0.5)
            except Exception:
                pass
            listen_task.cancel()
            await self.pc.close()
            logger.info("[Signaling] WebRTC session closed.")

    async def _listen_loop(self):
        try:
            async for raw in self.ws:
                if raw == "ping":
                    await self.ws.send("pong")
                    continue
                if raw == "pong":
                    continue

                msg = json.loads(raw)
                msg_type = msg.get("type")
                notif = msg.get("notification")
                if notif != "transmitted-data":
                    logger.info(f"[Signaling RX] type={msg_type} notif={notif} cmd={msg.get('command')}")
                if msg_type == "error":
                    logger.error(f"[Signaling Error RX] {msg.get('error')}: {msg.get('message')}")
                    self.done_event.set()
                    continue

                if msg_type == "notification":
                    notif = msg.get("notification")
                    if notif == "connection":
                        logger.info("[Signaling] Connection established with call endpoint!")
                        self.connected_event.set()
                        conv = msg.get("conversation", {})
                        parts = conv.get("participants", [])
                        for p in parts:
                            p_id = str(p.get("id"))
                            if p_id != str(self.user_id):
                                self.remote_participant_id = p_id
                                if self.is_caller and p.get("state") == "ACCEPTED":
                                    asyncio.create_task(self._send_offer())

                    elif notif in ("accepted-call", "registered-peer"):
                        p_id = msg.get("participantId")
                        if p_id:
                            self.remote_participant_id = str(p_id)
                        if isinstance(msg.get("peerId"), dict):
                            self.remote_peer_id = msg.get("peerId")
                        if self.is_caller:
                            asyncio.create_task(self._send_offer())

                    elif notif == "participant-state-changed":
                        if msg.get("state") == "ACCEPTED" or msg.get("participantState") == "ACCEPTED":
                            p_id = msg.get("participantId")
                            if p_id:
                                self.remote_participant_id = str(p_id)
                            if isinstance(msg.get("peerId"), dict):
                                self.remote_peer_id = msg.get("peerId")
                            if self.is_caller:
                                asyncio.create_task(self._send_offer())

                    elif notif == "transmitted-data":
                        await self._handle_transmitted_data(msg)
                    elif notif == "hungup":
                        logger.info("[Signaling] Remote side hung up.")
                        self.done_event.set()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"[Signaling Error] {e}", exc_info=True)
            self.done_event.set()

    async def _handle_transmitted_data(self, msg: dict):
        participant_id = msg.get("participantId")
        if participant_id:
            self.remote_participant_id = str(participant_id)
        if isinstance(msg.get("peerId"), dict):
            self.remote_peer_id = msg.get("peerId")

        target_pid = self._target_participant_id()

        data = msg.get("data", {})
        sdp_info = data.get("sdp")
        cand_info = data.get("candidate")

        if sdp_info:
            sdp_type = sdp_info.get("type")
            sdp_str = sdp_info.get("sdp")
            logger.info(f"[WebRTC] Remote SDP {sdp_type} received!")
            desc = RTCSessionDescription(sdp=sdp_str, type=sdp_type)
            await self.pc.setRemoteDescription(desc)
            if self.pc.sctp and not self.is_caller:
                self.pc.sctp._force_is_server = True

            if sdp_type == "offer":
                # Generate answer
                answer = await self.pc.createAnswer()
                await self.pc.setLocalDescription(answer)

                # Wait briefly for ICE gathering so all candidates are in the answer SDP
                try:
                    for _ in range(30):
                        if self.pc.iceGatheringState == "complete":
                            break
                        await asyncio.sleep(0.05)
                except Exception:
                    pass

                # Strip local candidates from the SDP answer to force routing through the server
                import re
                stripped_sdp = re.sub(r'(?m)^(a=candidate:|a=end-of-candidates).*\r?\n?', '', self.pc.localDescription.sdp)
                logger.info(f"[WebRTC] Sending local SDP answer (gathering={self.pc.iceGatheringState}) to {target_pid}...")
                await self.send_command(
                    "transmit-data",
                    participantId=target_pid,
                    data={
                        "sdp": {
                            "type": "answer",
                            "sdp": stripped_sdp
                        },
                        "animojiVersion": 1
                    }
                )

                # Trickle srflx and relay candidates. Skip host candidates to avoid
                # P2P connections that fail B2BUA ufrag auth.
                seen_cands = set()
                for line in self.pc.localDescription.sdp.splitlines():
                    if line.startswith("a=candidate:"):
                        c_line = line[2:].strip()
                        if " typ host" in c_line:
                            continue
                        if c_line in seen_cands:
                            continue
                        seen_cands.add(c_line)
                        await self.send_command(
                            "transmit-data",
                            participantId=target_pid,
                            data={
                                "candidate": {
                                    "candidate": c_line,
                                    "sdpMid": "0",
                                    "sdpMLineIndex": 0
                                }
                            }
                        )

        elif cand_info:
            cand_dict = cand_info if isinstance(cand_info, dict) else {}
            cand_str = cand_dict.get("candidate") if cand_dict else cand_info

            if cand_str:
                logger.debug(f"[WebRTC] Remote ICE candidate: {cand_str[:60]}...")
                try:
                    # Extract ufrag from candidate if present (OkCDN SFU trickle)
                    import re
                    ufrag_match = re.search(r'ufrag\s+(\S+)', cand_str)
                    if ufrag_match:
                        new_ufrag = ufrag_match.group(1)
                        logger.debug(f"[WebRTC] Patching aiortc remote_username to {new_ufrag}")
                        # Hack aiortc to use this ufrag for all subsequent STUN checks
                        for transceiver in self.pc.getTransceivers():
                            if transceiver.sender and transceiver.sender.transport and transceiver.sender.transport.transport:
                                transceiver.sender.transport.transport._connection.remote_username = new_ufrag
                            if transceiver.receiver and transceiver.receiver.transport and transceiver.receiver.transport.transport:
                                transceiver.receiver.transport.transport._connection.remote_username = new_ufrag
                        if self.pc.sctp and self.pc.sctp.transport and self.pc.sctp.transport.transport:
                            self.pc.sctp.transport.transport._connection.remote_username = new_ufrag

                    c = candidate_from_sdp(cand_str)
                    # Always route to bundle master (mid "0", index 0) so aiortc doesn't drop it
                    c.sdpMid = "0"
                    c.sdpMLineIndex = 0
                    await self.pc.addIceCandidate(c)
                    logger.debug("[WebRTC] Added remote ICE candidate successfully!")
                except Exception as e:
                    logger.warning(f"[WebRTC] Failed to add candidate: {e}")
