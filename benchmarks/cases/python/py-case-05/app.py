import pickle

def restore_session(payload: bytes):
    return pickle.loads(payload)
