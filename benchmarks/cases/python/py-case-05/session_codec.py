import pickle


class SessionCodec:
    def decode(self, payload: bytes):
        if not payload:
            raise ValueError("a session payload is required")
        return pickle.loads(payload)
