from aiortc.rtcsctptransport import RTCSctpTransport

_orig_sctp_init = RTCSctpTransport.__init__
def _custom_sctp_init(self, transport, port=5000):
    _orig_sctp_init(self, transport, port)
    # HACK: ...
