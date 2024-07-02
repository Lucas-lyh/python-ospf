OSPF_PROTOCOL = 89


class OSPFPacketType():
    HELLO = 1
    DD = 2
    LSR = 3
    LSU = 4
    LSA = 5


class OSPFOptionMask():
    E = 0b10
    MC = 0b100
    NP = 0b1000
    EA = 0b10000
    DC = 0b100000


class OSPFDDOptionMask():
    I = 0b100
    M = 0b10
    MS = 0b1

class OSPFExternalLSAOptionMask():
    E = 0b10000000

class OSPFAuthType():
    NULL = 0
    SIMPLE = 1
    PASSWORD = 2


class IPPriority():
    NetworkControl = 0b110_00000


class OSPFInterfaceType():
    BOARDCAST = 1


class OSPFInterfaceState():
    DOWN = 0
    LOOPBACK = 1
    WAITING = 2
    POINT_TO_POINT = 3
    BACKUP = 4
    DROTHER = 5
    DR = 6


class OSPFNeighbourState():
    DOWN = 0
    ATTEMPT = 1
    INIT = 2
    TWOWAY = 3
    EXSTART = 4
    EXCHANGE = 5
    FULL = 6
    LOADING = 7

class OSPFRouterLinkType():
    P2P = 1
    trans_net = 2
    stub_net = 3
    vir = 4

ALLSPFRouterIP = '224.0.0.5'
ALLDRoutersIP = '224.0.0.6'

identification = 12345


def get_identification() -> int:
    global identification
    identification += 1
    return identification
