from aiortc.sdp import candidate_from_sdp
from aiortc.rtcicetransport import candidate_from_aioice, candidate_to_aioice
remote = candidate_from_sdp("candidate:468136283 1 udp 658217562 155.212.207.121 43210 typ host generation 0")
local = candidate_from_sdp("candidate:ef2b2942bd8f39189dc94a57b60ea826 1 udp 2130706431 192.168.0.106 55810 typ host")
remote_aio = candidate_to_aioice(remote)
local_aio = candidate_to_aioice(local)
print("can pair:", local_aio.can_pair_with(remote_aio))
