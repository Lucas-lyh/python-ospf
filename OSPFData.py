import logging
import socket
from typing import List

from Decoder import *
from STATIC import *


class OSPFHeaderData():  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
    def __init__(self, data):
        self.version = data[0]
        self.type = data[1]
        self.length = data[2]
        self.router_id = data[3]
        self.area_id = data[4]
        self.checksum = data[5]
        self.autype = data[6]
        self.authentication = data[7]


class OSPFHeaderOperator(Operator):
    def __init__(self):
        super().__init__()
        # 解包OSPF头部 (version, type, length, router_id, area_id, checksum, autype, authentication)
        self.fields += [
            ('B', 'version'),
            ('B', 'type'),
            ('H', 'length'),
            ('4s', 'router_id'),
            ('4s', 'area_id'),
            ('H', 'checksum'),
            ('H', 'autype'),
            ('Q', 'authentication')
        ]

    def decode(self, data: bytes) -> OSPFHeaderData:  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
        res = super().decode(data)
        res.router_id = socket.inet_ntoa(res.router_id)
        res.area_id = socket.inet_ntoa(res.area_id)
        return res

    def encode(self, type: int, packetLenth: int, router_id: str, area_id: str, checksum: int,
               autype: int = OSPFAuthType.NULL,
               version: int = 2,
               authentication: int = 0):
        router_id = socket.inet_aton(router_id)
        area_id = socket.inet_aton(area_id)
        return super().encode(version, type, packetLenth, router_id, area_id, checksum, autype, authentication)


class OSPFHelloData():  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
    def __init__(self, data):
        self.network_mask = data[0]
        self.hello_interval = data[1]
        self.options = data[2]
        self.router_priority = data[3]
        self.router_dead_interval = data[4]
        self.dr = data[5]
        self.bdr = data[6]
        self.neighbours = data[7]


class OSPFHelloOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('4s', 'network_mask'),
            ('H', 'hello_interval'),
            ('B', 'options'),
            ('B', 'router_priority'),
            ('I', 'router_dead_interval'),
            ('4s', 'dr'),
            ('4s', 'bdr')
        ]
        # neighbour will be added in encode/decode

    def decode(self, data: bytes) -> OSPFHelloData:  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
        neighbour_cnt = 0
        while struct.calcsize(self.FMT) < len(data):
            self.fields.append(('4s', 'neighbour{}'.format(neighbour_cnt)))
            neighbour_cnt += 1
        logging.debug("find {} neighbours in hello packet".format(neighbour_cnt))
        res = super().decode(data)
        res['neighbours'] = []
        for i in range(neighbour_cnt):
            res['neighbours'].append(socket.inet_ntoa(res['neighbour{}'.format(i)]))
        res.network_mask = socket.inet_ntoa(res.network_mask)
        res.dr = socket.inet_ntoa(res.dr)
        res.bdr = socket.inet_ntoa(res.bdr)
        return res

    def encode(self, network_mask, hello_interval, options,
               router_priority, router_dead_interval, dr, bdr,
               neighbours):
        network_mask = socket.inet_aton(network_mask)
        dr = socket.inet_aton(dr)
        bdr = socket.inet_aton(bdr)
        self.fields += ([('4s', 'neighbour')] * len(neighbours))
        Nneighbours = [socket.inet_aton(nei) for nei in neighbours]
        res = super().encode(network_mask, hello_interval, options, router_priority, router_dead_interval,
                             dr, bdr, *Nneighbours)
        return res


class OSPFDDData():  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
    def __init__(self, data):
        self.interface_mtu = data[0]
        self.options = data[1]
        self.DD_options = data[2]
        self.DD_seq = data[3]
        self.LSA_headers = data[4]


class OSPFDDOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('H', 'interface_mtu'),
            ('B', 'options'),
            ('B', 'DD_options'),
            ('I', 'DD_seq')
        ]

    def decode(self, data: bytes) -> OSPFDDData:  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
        res = super().decode(data)
        return res

    def encode(self, interface_mtu, options, DD_options, DD_seq):
        res = super().encode(interface_mtu, options, DD_options, DD_seq)
        return res


class OSPFLSAHeaderData():  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
    def __init__(self, data):
        self.age = data[0]
        self.options = data[1]
        self.type = data[2]
        self.id = data[3]
        self.advertising_router = data[4]
        self.seq = data[5]
        self.checksum = data[6]
        self.length = data[7]


class OSPFLSAHeaderOperator(Operator):
    def __init__(self):
        super().__init__()
        # 解包OSPF头部 (version, type, length, router_id, area_id, checksum, autype, authentication)
        self.fields += [
            ('H', 'age'),
            ('B', 'options'),
            ('B', 'type'),
            ('4s', 'id'),
            ('4s', 'advertising_router'),
            ('i', 'seq'),
            ('H', 'checksum'),
            ('H', 'length')
        ]

    def decode(self, data: bytes) -> OSPFLSAHeaderData:  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
        res = super().decode(data)
        res.advertising_router = socket.inet_ntoa(res.advertising_router)
        res.id = socket.inet_ntoa(res.id)
        return res

    def encode(self, age, options, type, id, advertising_router, seq, checksum, length):
        advertising_router = socket.inet_aton(advertising_router)
        id = socket.inet_aton(id)
        res = super().encode(age, options, type, id, advertising_router, seq, checksum, length)
        return res


class OSPFTosData():
    def __init__(self, data):
        self.tos = data[0]
        self.metric = data[1]


class OSPFTosOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('B', 'tos'),
            ('B', '_'),
            ('H', 'metric')
        ]

    def decode(self, data: bytes) -> OSPFTosData:
        return super().decode(data)

    def encode(self, tos, metric):
        return super().encode(tos, 0, metric)


class OSPFRouterLinkData():
    def __init__(self, data):
        self.type = data[0]
        self.id = data[1]
        self.data = data[2]
        self.tos_num = data[3]
        self.metric = data[4]
        self.toss = data[5]


class OSPFRouterLinkOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('4s', 'id'),
            ('4s', 'data'),
            ('B', 'type'),
            ('B', 'tos_num'),
            ('H', 'metric')
        ]

    def decode(self, data: bytes) -> OSPFRouterLinkData:
        res = super().decode(data)
        res.data = socket.inet_ntoa(res.data)
        res.id = socket.inet_ntoa(res.id)
        data_toss = super().next_data(data)
        res['toss'] = []
        self.tos_operators = []
        for i in range(res.tos_num):
            tos_operator = OSPFTosOperator()
            self.tos_operators.append(tos_operator)
            res.toss.append(tos_operator.decode(data_toss))
            data_toss = tos_operator.next_data(data_toss)
        return res

    def next_data(self, data):
        data1 = super().next_data(data)
        for tos_operator in self.tos_operators:
            data1 = tos_operator.next_data(data1)
        return data1

    def encode(self, id, data, type, metric, toss):
        data = socket.inet_aton(data)
        id = socket.inet_aton(id)
        data1 = super().encode(id, data, type, len(toss), metric)
        for tos in toss:
            data1 += OSPFTosOperator().encode(tos['tos'], tos['metric'])
        return data1


class OSPFRouterLSADATA():
    def __init__(self, data):
        self.options = data[0]
        self.link_num = data[1]
        self.links:List[OSPFRouterLinkData] = data[2]


class OSPFRouterLSAOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('B', 'options'),
            ('B', '_'),
            ('H', 'link_num')
        ]

    def decode(self, data: bytes, lsa_len):
        res = super().decode(data)
        links_data = super().next_data(data)
        res['links'] = []
        self.router_link_operators = []
        for i in range(res.link_num):
            operator = OSPFRouterLinkOperator()
            self.router_link_operators.append(operator)
            res['links'].append(operator.decode(links_data))
            links_data = operator.next_data(links_data)
        return res

    def next_data(self, data):
        data1 = super().next_data(data)
        for operator in self.router_link_operators:
            data1 = operator.next_data(data1)
        return data1

    def encode(self, options, links):
        data1 = super().encode(options, 0, len(links))
        for link in links:
            operator = OSPFRouterLinkOperator()
            data1 += operator.encode(link['id'], link['data'], link['type'], link['metric'], link['toss'])
        return data1


class OSPFNetworkLSAAttachedData():
    def __init__(self, data):
        self.attached_router = data[0]


class OSPFNetworkLSAAttachedOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('4s', 'attached_router')
        ]

    def decode(self, data: bytes) -> OSPFNetworkLSAAttachedData:
        res = super().decode(data)
        res.attached_router = socket.inet_ntoa(res.attached_router)
        return res

    def encode(self, attached_router):
        attached_router = socket.inet_aton(attached_router)
        return super().encode(attached_router)


class OSPFNetworkLSADATA():
    def __init__(self, data):
        self.network_mask = data[0]
        self.attached_routers = data[1]


class OSPFNetworkLSAOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('4s', 'network_mask')
        ]

    def decode(self, data: bytes, lsa_len) -> OSPFNetworkLSADATA:
        res = super().decode(data)
        res.network_mask = socket.inet_ntoa(res.network_mask)
        data = super().next_data(data)
        self.attached_operators = []
        res.attached_routers = []
        for i in range((lsa_len - 24) // 4):
            operator = OSPFNetworkLSAAttachedOperator()
            self.attached_operators.append(operator)
            res.attached_routers.append(operator.decode(data).attached_router)
            data = operator.next_data(data)
        return res

    def next_data(self, data):
        data = super().next_data(data)
        for operator in self.attached_operators:
            data = operator.next_data(data)
        return data

    def encode(self, mask, attached_routers: List[str]):
        mask = socket.inet_aton(mask)
        data = super().encode(mask)
        for router in attached_routers:
            data += OSPFNetworkLSAAttachedOperator().encode(router)
        return data


class OSPFSummaryLSADATA():
    def __init__(self, data):
        self.network_mask = data[0]
        self.metric = data[1]


class OSPFSummaryLSAOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('4s', 'network_mask'),
            ('I', 'metric')
        ]

    def encode(self, mask, metric):
        mask = socket.inet_aton(mask)
        super().encode(mask, metric)

    def decode(self, data: bytes,  lsa_len):
        res = super().decode(data)
        res.network_mask = socket.inet_ntoa(res.network_mask)
        return res


class OSPFExternalLSADATA():
    def __init__(self, data):
        self.network_mask = data[0]
        self.options = data[1]
        self.metric = data[2]
        self.forwarding_address = data[3]
        self.external_routing_tag = data[4]


class OSPFExternalLSAOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('4s', 'network_mask'),
            ('B', 'options'),
            ('B', '_'),
            ('H', 'metric'),
            ('4s', 'forwarding_address'),
            ('4s', 'external_routing_tag')
        ]

    def decode(self, data: bytes, lsa_len):
        res = super().decode(data)
        res.network_mask = socket.inet_ntoa(res.network_mask)
        res.forwarding_address = socket.inet_ntoa(res.forwarding_address)
        res.external_routing_tag = socket.inet_ntoa(res.external_routing_tag)
        return res

    def encode(self, network_mask, options, metric, forwarding_address='0.0.0.0', external_routing_tag='0.0.0.0'):
        network_mask = socket.inet_aton(network_mask)
        forwarding_address = socket.inet_aton(forwarding_address)
        external_routing_tag = socket.inet_aton(external_routing_tag)
        return super().encode(network_mask, options, 0, metric, forwarding_address, external_routing_tag)


class OSPFLSRLSAIdentDATA():
    def __init__(self, data):
        self.type = data[0]
        self.id = data[1]
        self.advertising_router = data[2]


class OSPFLSRLSAIdentOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('I', 'type'),
            ('4s', 'id'),
            ('4s', 'advertising_router')
        ]

    def decode(self, data: bytes) -> OSPFDDData:  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
        res = super().decode(data)
        res.id = socket.inet_ntoa(res.id)
        res.advertising_router = socket.inet_ntoa(res.advertising_router)
        return res

    def encode(self, type, id, advertising_router):
        id = socket.inet_aton(id)
        advertising_router = socket.inet_aton(advertising_router)
        res = super().encode(type, id, advertising_router)
        return res


class OSPFLSRDATA():
    def __init__(self, data):
        self.lsa_idents: List[OSPFLSRLSAIdentDATA] = data[0]


class OSPFLSROperator(Operator):
    def __init__(self):
        super().__init__()

    def decode(self, data: bytes) -> OSPFLSRDATA:  # 为了能够在编写过程中进行代码提示，故使用该容器类，以提供代码提示。
        res = super().decode(data)
        res.lsa_idents = []
        data1 = data
        self.ident_operators = []
        while len(data1):
            operator = OSPFLSRLSAIdentOperator()
            self.ident_operators.append(operator)
            _ = operator.decode(data1)
            res.lsa_idents.append(_)
            data1 = operator.next_data(data1)
        return res

    def encode(self, lsa_idents: List[OSPFLSRLSAIdentDATA]):
        res = ''.encode()
        for ident in lsa_idents:
            operator = OSPFLSRLSAIdentOperator()
            res += operator.encode(ident.type, ident.id, ident.advertising_router)
        return res


class OSPFLSUDATA():
    def __init__(self):
        self.lsa_headers:List[OSPFLSAHeaderData] = []
        self.lsa_datas = []


class OSPFLSUOperator(Operator):
    def __init__(self):
        super().__init__()
        self.fields += [
            ('I', 'lsa_num')
        ]

    def decode(self, data: bytes)->OSPFLSUDATA:
        res = super().decode(data)
        res.lsa_headers = []
        res.lsa_datas = []
        data = super().next_data(data)
        for i in range(res.lsa_num):
            header_operator = OSPFLSAHeaderOperator()
            header = header_operator.decode(data)
            res.lsa_headers.append(header)
            data = header_operator.next_data(data)
            class_map = {1: OSPFRouterLSAOperator,
                         2: OSPFNetworkLSAOperator,
                         3: OSPFSummaryLSAOperator,
                         4: OSPFSummaryLSAOperator,
                         5: OSPFExternalLSAOperator}
            operator = class_map[header.type]()
            res.lsa_datas.append(operator.decode(data, header.length))
            data = operator.next_data(data)
        return res

    def encode(self, lsa_num):
        return super().encode(lsa_num)


class OSPFLSAckDATA():
    def __init__(self):
        self.lsa_headers = []


class OSPFLSAckOperator(Operator):
    def __init__(self):
        super().__init__()

    def decode(self, data: bytes)->OSPFLSAckDATA:
        res = super().decode(data)
        res.lsa_headers = []
        while len(data):
            header_operator = OSPFLSAHeaderOperator()
            header = header_operator.decode(data)
            res.lsa_headers.append(header)
            data = header_operator.next_data(data)
        return res

    def encode(self, lsas):
        res = ''.encode()
        for lsa in lsas:
            res += lsa.gen_packet_header()
        return res
