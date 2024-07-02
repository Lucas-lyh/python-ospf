import sender
from OSPFRole.interface import BoardcastInterface
from calculator import *


class Area:
    def __init__(self, id="0.0.0.0", router_id='1.1.1.1', as_external_lsa=[]):
        self.id = id  # Area Id
        self.router_id = router_id
        self.router_lsa: List[Router_LSA] = [] # LSDB中的RouterLSA
        self.network_lsa: List[Network_LSA] = [] # LSDB中的NetworkLSA
        self.summary_lsa = [] # LSDB中的SummaryLSA
        self.as_external_lsa = as_external_lsa # LSDB中的asExternalLSA
        self.TransitCapability = False
        self.ExternalRouterCapability = True
        self.stabDefaultCost = 10
        self.interfaces: List[BoardcastInterface] = []
        self.lsa_seq = -(2 ** 31) + 1

    def gen_lsa_seq(self):
        ret = self.lsa_seq
        self.lsa_seq += 1
        return ret

    def debug(self, str):
        logging.debug(f'[area {self.id}]: {str}')

    def info(self, str):
        logging.info(f'[area {self.id}]: {str}')

    def get_lsa_by_ident(self, ident):
        search_range = self.network_lsa + self.summary_lsa + self.router_lsa
        for lsa in search_range:
            if lsa.type == ident.type and lsa.id == ident.id and lsa.advertising_router == ident.advertising_router:
                return lsa
        return None

    @property
    def address_range(self):
        pass

    def add_interface(self, interface_name):
        newinterface = BoardcastInterface(interface_name, self)
        self.interfaces.append(newinterface)

    def find_lsa_by_interface(self, interface_ip) -> LSA:
        ret = []
        for lsa in self.router_lsa:
            for link in lsa.links:
                if link.interface.ip == interface_ip:
                    ret.append(lsa)
                    break
        return ret

    def get_mine_router_lsa(self):
        for lsa in self.router_lsa:
            if lsa.advertising_router == self.router_id:
                return lsa
        return None

    def gen_router_lsa(self):
        self.info('gen router LSA!')
        router_lsa = Router_LSA(gen_options(1, 0, 0, 0, 0), self.router_id, self.router_id,
                                self.gen_lsa_seq(),
                                False,
                                False,
                                False)
        return router_lsa

    def fresh_router_lsa(self):
        self.info('fresh lsa')
        my_router_lsa = self.get_mine_router_lsa()
        if not my_router_lsa:
            my_router_lsa = self.gen_router_lsa()
            self.router_lsa.append(my_router_lsa)
        self.debug(f'gotten router lsa with link_num: {len(my_router_lsa.links)}')
        for interface in self.interfaces:
            self.debug(f'checking interface: {interface.ip}')
            ori_links = my_router_lsa.get_link_for_interface(interface)
            if interface.STATE == OSPFInterfaceState.DOWN:
                self.debug(f'interface: {interface.ip} is down, continue')
                continue
            isstub = False
            if (interface.STATE == OSPFInterfaceState.WAITING):
                isstub = True
            elif not interface.can_be_trans_net():
                isstub = True
            if isstub:
                if len(ori_links) == 0:
                    self.debug('no ori stub network, add new')
                    my_router_lsa.add_stub_network(interface.get_net_address(), interface.mask, interface.cost,
                                                   interface)
                elif len(ori_links) == 1:
                    if ori_links[0].type != OSPFRouterLinkType.stub_net:
                        my_router_lsa.links.remove(ori_links[0])
                        my_router_lsa.add_stub_network(interface.get_net_address(), interface.mask, interface.cost,
                                                       interface)
                else:
                    logging.error('more than 1 link for this interface')
            else:
                if len(ori_links) == 0:
                    self.debug('no ori stub network, add new')
                    my_router_lsa.add_trans_network(dr_ip=interface.transform_neighbour_id_to_ip(interface.dr),
                                                    interface_ip=interface.ip,
                                                    metric=interface.cost,
                                                    interface=interface)
                elif len(ori_links) == 1:
                    my_router_lsa.links.remove(ori_links[0])
                    my_router_lsa.add_trans_network(dr_ip=interface.transform_neighbour_id_to_ip(interface.dr),
                                                    interface_ip=interface.ip,
                                                    metric=interface.cost,
                                                    interface=interface)
                else:
                    logging.error('more than 1 link for this interface')
        my_router_lsa.seq = self.gen_lsa_seq()
        self.add_lsa_to_area(my_router_lsa, None)

    def flooding_lsa(self, lsa: LSA, source_interface):
        for interface in self.interfaces:
            if interface == source_interface:
                continue
            if interface.STATE <= OSPFInterfaceState.WAITING:
                continue
            sender.send_lsa_to(interface.ip,
                               ALLSPFRouterIP if (interface.STATE == OSPFInterfaceState.DR or
                                                  interface.STATE == OSPFInterfaceState.BACKUP) else ALLDRoutersIP,
                               self.router_id,self.id,
                               lsa)

    def add_lsa_to_area(self, lsa: LSA, source_interface):
        if lsa.type == 1:
            self.router_lsa = [x for x in self.router_lsa if not x.is_same(lsa)]
            self.router_lsa.append(lsa)
        elif lsa.type == 2:
            self.network_lsa = [x for x in self.network_lsa if not x.is_same(lsa)]
            self.network_lsa.append(lsa)
        elif lsa.type == 3 or lsa.type == 4:
            self.summary_lsa = [x for x in self.summary_lsa if not x.is_same(lsa)]
            self.summary_lsa.append(lsa)
        else:
            self.as_external_lsa = [x for x in self.as_external_lsa if not x.is_same(lsa)]
            self.as_external_lsa.append(lsa)
        self.flooding_lsa(lsa, source_interface)
        route_items = cal_path(self.router_lsa, self.network_lsa, self.get_mine_router_lsa())
        refresh_routing_table(route_items)

    def lsdb_text(self):
        print(f'|LSDB----Area {self.id}')
        print(f'|Router----------')
        for lsa in self.router_lsa:
            lsa_str = str(lsa)
            lsa_str = lsa_str.replace('\n', '\n|--')
            print('|--'+lsa_str)
        print(f'|Network---------')
        for lsa in self.network_lsa:
            lsa_str = str(lsa)
            lsa_str = lsa_str.replace('\n', '\n|--')
            print('|--'+lsa_str)
        print(f'|----------------')

