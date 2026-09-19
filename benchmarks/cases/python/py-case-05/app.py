from dataclasses import dataclass

from session_codec import SessionCodec


@dataclass(frozen=True)
class SessionRestoreRequest:
    payload: bytes


class SessionEndpoint:
    def __init__(self, codec: SessionCodec) -> None:
        self._codec = codec

    def restore(self, request: SessionRestoreRequest):
        return self._codec.decode(request.payload)


def restore_session(payload: bytes):
    return SessionEndpoint(SessionCodec()).restore(SessionRestoreRequest(payload))
