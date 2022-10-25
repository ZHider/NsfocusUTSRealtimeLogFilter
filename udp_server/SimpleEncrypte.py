from itertools import cycle


def encrypt(msg_plain: str, key: str) -> str:
    return ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(msg_plain, cycle(key))])


def decrypt(msg_encrypted: str, key: str) -> str:
    return ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(msg_encrypted, cycle(key))])
