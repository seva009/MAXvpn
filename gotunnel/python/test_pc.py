import asyncio
from aiortc import RTCPeerConnection, RTCSessionDescription
async def test():
    pc = RTCPeerConnection()
    pc.addTransceiver("audio")
    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    t = pc.getTransceivers()[0].sender.transport.transport
    print(t)
    print(t._connection.remote_username)
asyncio.run(test())
