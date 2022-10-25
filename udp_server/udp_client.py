import json
import socket
from itertools import cycle

# 在这里修改配置
PORT = 10517  # 监听端口
ADDR = ""  # 监听地址，留空表示全部
key = ""  # 密钥，留空则不加密


# key = "a-simple+password"


def decrypt(msg_encrypted: str, _key: str) -> str:
    return ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(msg_encrypted, cycle(_key))])


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

s.bind((ADDR, PORT))
print('Listening for broadcast at ', s.getsockname())

while True:
    data, address = s.recvfrom(65535)

    js = data.decode('utf-16')
    if key:
        js = decrypt(js, key)

    msg = json.loads(js)

    print(msg[0], end=msg[1])
