import socket

from Decoder import *
from STATIC import *


class IPHeaderData():  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
    def __init__(self, data):
        self.versionHeaderLength = data[0]
        self.priority = data[1]
        self.totLength = data[2]
        self.identification = data[3]
        self.flag = data[4]
        self.ttl = data[5]
        self.autype = data[6]
        self.protocol = data[7]
        self.checksum = data[8]
        self.sourceIP = data[9]
        self.destinationIP = data[10]


class IPHeaderOperator(Operator):
    def __init__(self):
        super().__init__()
        # 解包OSPF头部 (version, type, length, router_id, area_id, checksum, autype, authentication)
        self.fields += [
            ('B', 'versionHeaderLength'),
            ('B', 'priority'),
            ('H', 'totLength'),
            ('H', 'identification'),
            ('H', 'flag'),
            ('B', 'ttl'),
            ('B', 'protocol'),
            ('H', 'checksum'),
            ('4s', 'sourceIP'),
            ('4s', 'destinationIP')
        ]

    def decode(self, data: bytes) -> IPHeaderData:  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
        res = super().decode(data)
        res.sourceIP = socket.inet_ntoa(res.sourceIP)
        res.destinationIP = socket.inet_ntoa(res.destinationIP)
        return res

    def encode(self, sourceIP: str, desIP: str,
               identification: int = 54321,
               flag: int = 0,
               ttl: int = 1,
               protocol: int = 89,
               checksum: int = 0):
        sourceIP = socket.inet_aton(sourceIP)
        desIP = socket.inet_aton(desIP)
        return super().encode((4 << 4) + 5, IPPriority.NetworkControl, 0, identification, flag, ttl, protocol,
                              checksum, sourceIP, desIP)
