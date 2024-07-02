import time

from tools import *
from OSPFData import *


class LSA:
    def __init__(self, options, type, id, advertising_router, seq):
        self.born = int(time.time())
        self.options = options
        self.type = type
        self.id = id
        self.advertising_router = advertising_router
        self.seq = seq

    def __str__(self):
        return f'LSA type {self.type}, id {self.id}, advertising_router {self.advertising_router}'

    def is_same(self, lsa):
        return self.type == lsa.type and self.id == lsa.id and self.advertising_router == lsa.advertising_router

    def __len__(self):
        return 20

    def gen_packet_body(self) -> bytes:
        logging.error('call original gen_lsa_packet_body, something wrong!')
        return ''.encode()

    def gen_packet_header(self):
        retdic = self.gen_header_dict()
        lsa = easydict.EasyDict(retdic)
        lsa_header_operator = OSPFLSAHeaderOperator()
        _ = lsa_header_operator.encode(age=0,
                                       options=lsa.options,
                                       type=lsa.type,
                                       id=lsa.id,
                                       advertising_router=lsa.advertising_router,
                                       seq=lsa.seq,
                                       checksum=0,
                                       length=lsa.length)
        full_data = _ + self.gen_packet_body()
        checksum = fletcher16(full_data[2:])
        return lsa_header_operator.encode(age=lsa.age,
                                          options=lsa.options,
                                          type=lsa.type,
                                          id=lsa.id,
                                          advertising_router=lsa.advertising_router,
                                          seq=lsa.seq,
                                          checksum=checksum,
                                          length=lsa.length)

    def gen_header_dict(self):
        retdic = {
            'age': int(time.time()) - self.born,
            'options': self.options,
            'type': self.type,
            'id': self.id,
            'advertising_router': self.advertising_router,
            'seq': self.seq,
            'checksum': 0,
            'length': len(self)
        }
        return easydict.EasyDict(retdic)


class Router_link():
    def __init__(self, type, data, id, metric, interface = None):
        self.type = type
        self.data = data
        self.id = id
        self.metric = metric
        self.interface = interface
    def __str__(self):
        return f'type: {self.type} \tdata: {self.data} \tmetric: {self.metric} \tid: {self.id}'


class Router_LSA(LSA):
    def __init__(self, options, ls_id, advertising_router, ls_seq, v, e, b):
        self.V = v
        self.ASBR = e
        self.ABR = b
        super().__init__(options, 1, ls_id, advertising_router, ls_seq)
        self.links: List[Router_link] = []

    def __str__(self):
        res = super().__str__()
        for link in self.links:
            res += '\n'
            res += str(link)
        return res
    @classmethod
    def options2dict(cls, data_options):
        V = (data_options & 0b100) > 0
        ASBR = (data_options & 0b10) > 0
        ABR = (data_options & 0b1) > 0
        return {'v':V, 'e':ASBR, 'b':ABR}


    def add_link(self, type, data, id, metric, interface=None):
        self.links.append(Router_link(type, data, id, metric, interface))

    def add_stub_network(self, net_ip, net_mask, metric, interface):
        self.links.append(Router_link(3, net_mask, net_ip, metric, interface))

    def add_trans_network(self, dr_ip, interface_ip, metric, interface):
        self.links.append(Router_link(2, interface_ip, dr_ip, metric, interface))

    def get_link_for_interface(self, interface):
        res = []
        for link in self.links:
            if link.type == OSPFRouterLinkType.stub_net:
                if link.id == interface.get_net_address() and link.data == interface.mask:
                    res.append(link)
            elif link.type == OSPFRouterLinkType.trans_net:
                if link.data == interface.ip:
                    res.append(link)
        return res

    def gen_packet_body(self):
        operator = OSPFRouterLSAOperator()
        v = 1 if self.V else 0
        e = 1 if self.ASBR else 0
        b = 1 if self.ABR else 0
        options = (v << 2) + (e << 1) + b
        links = []
        for link in self.links:
            links.append(easydict.EasyDict(
                {
                    'id': link.id,
                    'data': link.data,
                    'type': link.type,
                    'metric': link.metric,
                    'toss': []
                }
            ))
        return operator.encode(options, links)

    def __len__(self):
        return 24 + len(self.links) * 12


class Network_LSA(LSA):
    def __init__(self, options, interface_ip, advertising_router, seq, mask, attached_routers):
        super().__init__(options, 2, interface_ip, advertising_router, seq)
        self.network_mask = mask
        self.attached_routers = attached_routers
    def __len__(self):
        return 24 + len(self.attached_routers)*4

    def gen_packet_body(self):
        operator = OSPFNetworkLSAOperator()
        data = operator.encode(self.network_mask, self.attached_routers)
        return data

    def __str__(self):
        res = super().__str__()
        res += f'\nnetwork_mask: {self.network_mask}\nattached_routers:{self.attached_routers}'
        return res
