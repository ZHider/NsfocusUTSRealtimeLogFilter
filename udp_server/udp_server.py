import socket
import udp_server.SimpleEncrypte as SimpleEncrypte
import json

from Config import config


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

print('UDP Server 初始化成功。')


def send(msg: str, end: str):
    _AF_INET = (config.udp_broadcast_addr, config.udp_port)
    key = config.udp_simple_password

    data = json.dumps((msg, end))

    if key:
        s.sendto(SimpleEncrypte.encrypt(data, key).encode('utf-16'), _AF_INET)
    else:
        s.sendto(data.encode('utf-16'), _AF_INET)
