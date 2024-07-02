import logging
import threading

import pyroute2
import pydantic
from typing import List

from STATIC import OSPFOptionMask

logging.basicConfig(level=logging.DEBUG  # 设置日志输出格式
                    # ,filename="runlog.log" #log日志输出的文件位置和文件名
                    # ,filemode="w" #文件的写入格式，w为重新写入文件，默认是追加
                    , format="%(asctime)s - %(name)s - %(levelname)-9s - %(filename)-8s : %(lineno)s line - %(message)s"
                    # 日志输出的格式
                    # -8表示占位符，让输出左对齐，输出长度都为8位
                    , datefmt="%Y-%m-%d %H:%M:%S"  # 时间输出的格式
                    )


def cal_checksum(data):  # 校验和不计算验证信息field，故首先跳过。 此处传入整个OSPF包，但是不包括IP部分。
    if len(data) % 2:
        data += b'\x00'
    res = 0
    for i in range(len(data) >> 1):
        res += ((data[i * 2] << 8) + data[i * 2 + 1])
        while res > 0xffff:
            res = (res & 0xffff) + (res >> 16)
    return (~res) & 0xffff


import socket
import struct
import fcntl


class Route_item(pydantic.BaseModel):
    destination: str
    mask_len: int
    next_hop: str
    priority: int = 123
    def __str__(self):
        return f'des: {self.destination}, mask_len: {self.mask_len}, next_hop: {self.next_hop}'


def mask_to_mask_len(mask):
    mask = ip_to_list(mask)
    ret = 0
    for n in mask:
        if n == 255:
            ret += 8
        else:
            n1 = n
            while n1 > 0 and n1 % 2 == 0:
                n1 >>= 1
            while n1:
                ret += 1
                n1 >>= 1
    return ret


def get_ip_address(interface_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packed_interface_name = struct.pack('256s', interface_name[:15].encode('utf-8'))
    try:
        ip_address = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            packed_interface_name
        )[20:24])
        return ip_address
    except IOError as e:
        print(f"Error retrieving IP address for interface {interface_name}: {e}")
        return None


def get_netmask(interface_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packed_interface_name = struct.pack('256s', interface_name[:15].encode('utf-8'))
    try:
        netmask = socket.inet_ntoa(fcntl.ioctl(
            sock.fileno(),
            0x891b,  # SIOCGIFNETMASK
            packed_interface_name
        )[20:24])
        return netmask
    except IOError as e:
        print(f"Error retrieving netmask for interface {interface_name}: {e}")
        return None


def get_all_routes(priority=123) -> List[Route_item]:
    ip = pyroute2.IPRoute()
    routes = ip.get_routes()
    res = []
    for route in routes:
        route = dict(route)
        if 'attrs' in route:
            dic = dict(route['attrs'])
            if 'RTA_PRIORITY' in dic and dic['RTA_PRIORITY'] == priority:
                res.append(Route_item(priority=priority,
                                      destination=dic['RTA_DST'],
                                      next_hop=dic['RTA_GATEWAY'],
                                      mask_len=route['dst_len']))
    return res


def gen_dst_for_route(route: Route_item):
    return route.destination + "/{}".format(route.mask_len)


def add_route(route: Route_item):
    ip = pyroute2.IPRoute()
    ip.route("add", dst=gen_dst_for_route(route),
             gateway=route.next_hop,
             priority=route.priority)
    logging.debug("add route to {}".format(route.destination))

net_lock = threading.Lock()

def del_route(route: Route_item):
    ip = pyroute2.IPRoute()
    ip.route('del', dst=gen_dst_for_route(route), priority=route.priority)
    logging.debug("delete route to {}".format(route.destination))


def refresh_routing_table(routes: List[Route_item],
                          priority=123):
    net_lock.acquire()
    all_routes = get_all_routes(priority)
    for route in all_routes:
        try:
            del_route(route)
        except:
            logging.error(f'error in removing route: {route}')
    for route in routes:
        if route.next_hop == '0.0.0.0':
            continue
        try:
            add_route(route)
        except:
            logging.error(f'error in adding route: {route}')
    net_lock.release()


def ip_to_list(ip):
    return [int(x) for x in ip.split('.')]


def list_to_ip(ip_list):
    return '.'.join([str(x) for x in ip_list])


def ip_mask_to_net(ip, mask):
    ip = ip_to_list(ip)
    mask = ip_to_list(mask)
    net = [ip[i] & mask[i] for i in range(4)]
    return list_to_ip(net)


def ip_in_net(ip, net, mask):
    ip = ip_to_list(ip)
    net = ip_to_list(net)
    mask = ip_to_list(mask)
    for i in range(4):
        if (ip[i] & mask[i]) != (net[i] & mask[i]):
            return False
    return True


def compare_router_id_bigger(routerid1, routerid2):
    routerid1 = ip_to_list(routerid1)
    routerid2 = ip_to_list(routerid2)
    for i in range(4):
        if routerid1[i] > routerid2[i]:
            return 1
        if routerid1[i] < routerid2[i]:
            return -1
    return 0


def gen_options(E, MC, NP, EA, DC):
    return E * OSPFOptionMask.E + MC * OSPFOptionMask.MC + NP * OSPFOptionMask.NP + EA * OSPFOptionMask.EA + DC * OSPFOptionMask.DC


def gen_DD_options(I: bool, M: bool, MS: bool):
    I = 1 if I else 0
    M = 1 if M else 0
    MS = 1 if MS else 0
    return (I << 2) + (M << 1) + MS


def c_style_mod(a, b):
    result = a % b
    if (result != 0 and (a < 0) != (b < 0) and b < 0):
        result += b
    return result


def fletcher16(data):
    L = len(data)
    n = 15  # 假设校验和字段最初设为0，并用0表示位置
    C0, C1 = 0, 0

    for i in range(L):
        C0 = (C0 + data[i]) % 255
        C1 = (C1 + C0) % 255
    X = - C1 + (L - n) * C0
    Y = C1 - (L - n + 1) * C0

    X = c_style_mod(X, 255)
    Y = c_style_mod(Y, 255)
    if X == 0:
        X = 255
    if Y == 0:
        Y = 255

    return (X << 8) + Y


if __name__ == '__main__':
    # 测试能否获取网卡对应的ip和mask
    # interface = 'ens33'
    # ip_address = get_ip_address(interface)
    # netmask = get_netmask(interface)
    # print(f"Interface: {interface}, IP: {ip_address}, Netmask: {netmask}")
    # res = get_all_routes(123)
    # print(res)
    #
    # import sender
    # from OSPFRole.LSA import Router_LSA
    # refresh_routing_table([Route_item(destination='100.0.1.0', mask_len=24, next_hop='127.0.0.1'), ])
    # lsa = Router_LSA(gen_options(1,0,0,0,0), '2.2.2.2','2.2.2.2',
    #                   -2147483648+4,False,False,False)
    # lsa.add_stub_network(
    #     '192.168.204.0','255.255.255.0',1, None
    # )
    # sender.send_lsa_to('192.168.204.3', '192.168.204.4',
    #                    '2.2.2.2', '0.0.0.0', lsa)
    print(mask_to_mask_len('255.255.255.0'))
