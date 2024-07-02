import functools
from OSPFRole.neighbour import Neighbor
from IPData import IPHeaderData
from sender import send_hello_packet, send_lsack_packet
from OSPFRole.LSA import *


class BoardcastInterface:
    def __init__(self, interface_name, area, hello_interval: int = 10, router_dead_interval=40,
                 inf_trans_delay: int = 1, router_priority: int = 1, cost: int = 1, retrans_interval: int = 5,
                 auth_type: int = OSPFAuthType.NULL, auth_key: str = ''):
        self.type = OSPFInterfaceType.BOARDCAST
        self.area = area
        self.timer = 0
        self.hello_interval = hello_interval
        self.router_dead_interval = router_dead_interval
        self.inf_trans_delay = inf_trans_delay
        self.router_priority = router_priority
        self.cost = cost
        self.retrans_interval = retrans_interval
        self.auth_type = auth_type
        self.auth_key = auth_key
        self.neighbours: List[Neighbor] = []
        self.dr = ''
        self.bdr = ''
        self.STATE = OSPFInterfaceState.DOWN
        self.ip = get_ip_address(interface_name)
        self.mask = get_netmask(interface_name)
        self.interface_name = interface_name

    def get_net_address(self):
        ip = ip_to_list(self.ip)
        mask = ip_to_list(self.mask)
        net_add = [ip[i] & mask[i] for i in range(4)]
        return list_to_ip(net_add)

    def transform_neighbour_id_to_ip(self, router_id):
        if router_id == self.area.router_id:
            return self.ip
        for nei in self.neighbours:
            if nei.router_id == router_id:
                return nei.ip_address
        return '0.0.0.0'

    def transform_neighbour_ip_to_id(self, router_ip):
        if router_ip == self.ip:
            return self.area.router_id
        for nei in self.neighbours:
            if nei.ip_address == router_ip:
                return nei.router_id
        return '0.0.0.0'

    def debug(self, str):
        logging.debug(f'[interface {self.interface_name}]: {str}')

    def info(self, str):
        logging.info(f'[interface {self.interface_name}]: {str}')

    def create_hello_timer(self):
        self.hello_timer = threading.Timer(self.hello_interval, self.hello_timer_callback)
        self.hello_timer.start()
        self.debug("hello timer created")

    def hello_timer_callback(self):
        self.debug("hello_timer_callback, send hello packet")
        send_hello_packet(source_id=self.ip,
                          destination_ip=ALLSPFRouterIP,
                          router_id=self.area.router_id,
                          area_id=self.area.id,
                          network_mask=self.mask,
                          hello_interval=self.hello_interval,
                          options=gen_options(1, 0, 0, 0, 0),
                          priority=self.router_priority,
                          dead_interval=self.router_dead_interval,
                          designated_router=self.transform_neighbour_id_to_ip(self.dr),
                          backup_designated_router=self.transform_neighbour_id_to_ip(self.bdr),
                          neighbours=[nei.router_id for nei in self.neighbours])
        self.create_hello_timer()

    def create_wait_timer(self):
        self.wait_timer = threading.Timer(self.router_dead_interval, self.wait_timer_callback)
        self.wait_timer.start()
        logging.debug('wait timer created')

    def wait_timer_callback(self):
        self.debug("wait_timer_callback")
        self.event_wait_timer()

    def event_interface_up(self):
        self.debug("event_interface_up")
        if self.STATE == OSPFInterfaceState.DOWN:
            self.create_hello_timer()
            if self.type == OSPFInterfaceType.BOARDCAST:
                if self.router_priority == 0:
                    self.debug('interface self can not be DR because priority is 0.')
                    self.STATE = OSPFInterfaceState.DROTHER
                else:
                    self.debug('interface self can be DR, into WAITING state.')
                    self.STATE = OSPFInterfaceState.WAITING
                    self.dr = '0.0.0.0'
                    self.bdr = '0.0.0.0'
                    self.create_wait_timer()

    def event_wait_timer(self):
        self.debug("event_waitTimer: {}".format(self.area.router_id))
        self.elevate_dr_and_bdr()

    def create_phantom_neighbour(self):
        phantom_neighbour = Neighbor(self.area.router_id, self.ip, self,
                                     options=gen_options(1, 0, 0, 0, 0))
        phantom_neighbour.dr = self.transform_neighbour_id_to_ip(self.dr)
        phantom_neighbour.bdr = self.transform_neighbour_id_to_ip(self.bdr)
        phantom_neighbour.priority = self.router_priority
        phantom_neighbour.ip_address = self.ip
        return phantom_neighbour

    def elevate_dr_and_bdr(self):
        two_way_neighbours = [neigh for neigh in self.neighbours if (neigh.STATE >= OSPFNeighbourState.TWOWAY)]
        phantom_nei = self.create_phantom_neighbour()
        two_way_neighbours.append(phantom_nei)
        self.debug(f"before elevating DR and BDR, list is {[nei.router_id for nei in two_way_neighbours]}")
        two_way_neighbours = [nei for nei in two_way_neighbours if nei.priority > 0]
        ori_dr = self.dr
        ori_bdr = self.bdr
        self.debug(f"start elevating DR and BDR, list is {[nei.router_id for nei in two_way_neighbours]},"
                   f"cur DR is {ori_dr}, cur BDR is {ori_bdr}")

        # select BDR:
        def my_cmp(a, b):
            if a.priority > b.priority:
                return 1
            if b.priority > a.priority:
                return -1
            return compare_router_id_bigger(a.router_id, b.router_id)

        bdr_list = [nei for nei in two_way_neighbours if nei.dr != nei.ip_address]
        bdr_list.sort(key=functools.cmp_to_key(my_cmp), reverse=True)
        self.debug(f'bdr list is {[x.router_id for x in bdr_list]}')
        selected_bdr = None
        for bdr_nei in bdr_list:
            if bdr_nei.bdr == bdr_nei.ip_address:
                selected_bdr = bdr_nei
                break
        if not selected_bdr and len(bdr_list) > 0:
            selected_bdr = bdr_list[0]
        self.debug(f'select bdr is {selected_bdr.router_id if selected_bdr else '0.0.0.0'}')
        # select DR
        dr_list = [nei for nei in two_way_neighbours if nei.dr == nei.ip_address]
        dr_list.sort(key=functools.cmp_to_key(my_cmp), reverse=True)
        self.debug(f'dr list is {[x.router_id for x in dr_list]}')
        selected_dr = None
        if len(dr_list) > 0:
            selected_dr = dr_list[0]
        else:
            selected_dr = selected_bdr
        self.debug(f'selected dr is {selected_dr.router_id}')
        if selected_dr != None and selected_dr.router_id == self.area.router_id:
            # 自身成为了DR，重新选举BDR，以避免自己被选举成BDR
            bdr_list = [nei for nei in two_way_neighbours if nei.dr != nei.ip_address and nei != phantom_nei]
            self.debug(f"start re-elevating BDR, list is {[nei.router_id for nei in bdr_list]}")
            bdr_list.sort(key=functools.cmp_to_key(my_cmp), reverse=True)
            selected_bdr = None
            for bdr_nei in bdr_list:
                if bdr_nei.bdr == bdr_nei.ip_address:
                    selected_bdr = bdr_nei
                    break
            if not selected_bdr and len(bdr_list) > 0:
                selected_bdr = bdr_list[0]
        self.info(f'select result: DR is {selected_dr.router_id if selected_dr else '0.0.0.0'},'
                  f' BDR is {selected_bdr.router_id if selected_bdr else '0.0.0.0'}, update interface.dr/bdr')
        self.dr = selected_dr.router_id if selected_dr else '0.0.0.0'
        self.bdr = selected_bdr.router_id if selected_bdr else '0.0.0.0'
        if (selected_dr.router_id if selected_dr else '0.0.0.0') == self.area.router_id:
            self.STATE = OSPFInterfaceState.DR
            self.info('self into DR state')
            self.flesh_network_lsa()
        elif selected_bdr.router_id if selected_bdr else '0.0.0.0' == self.area.router_id:
            self.STATE = OSPFInterfaceState.BACKUP
            self.info('self into BDR state')
        else:
            self.STATE = OSPFInterfaceState.DROTHER
            self.info('self into DR-OTHER')
        for nei in two_way_neighbours:
            if nei != phantom_nei:
                nei.check_adj()
        self.area.fresh_router_lsa()
    def flesh_network_lsa(self):
        if self.STATE == OSPFInterfaceState.DR:
            network_lsa = self.gen_network_lsa()
            self.area.add_lsa_to_area(network_lsa, None)
    def event_backup_seen(self):
        self.debug("backup_seen")
        self.elevate_dr_and_bdr()

    def event_neighbour_change(self):
        self.debug("event_neighbour_change: {}".format(self.area.router_id))
        self.elevate_dr_and_bdr()

    def event_loopback(self):
        self.debug("event_loopback: {}".format(self.area.router_id))
        pass

    def event_unloopback(self):
        self.debug("event_unloopback: {}".format(self.area.router_id))

    def event_interface_down(self):
        self.debug("event_interface_down: {}".format(self.area.router_id))
        for neighbour in self.neighbours:
            neighbour.kill_neighbour(self)
        self.neighbours = []
        self.dr = ''
        self.bdr = ''
        self.STATE = OSPFInterfaceState.DOWN

    def receive_hello_packet(self, ip_header: IPHeaderData, ospf_header: OSPFHeaderData, hello_packet: OSPFHelloData):
        self.debug("receive hello packet, start checking")
        self.debug(f'hello packet info dr: {hello_packet.dr}  bdr: {hello_packet.bdr}  neis:{hello_packet.neighbours}')
        if not self.area.ExternalRouterCapability == bool(hello_packet.options & OSPFOptionMask.E):
            self.info(f'E bit not match with mine E:{self.area.ExternalRouterCapability}, stop.')
            return
        self.debug('checking pass')
        is_match = False
        matched_neighbour = None
        for neighbour in self.neighbours:
            if neighbour.ip_address == ip_header.sourceIP:
                self.debug(f'match neighbour of router_id:{neighbour.router_id}, ip_address:{neighbour.ip_address}')
                is_match = True
                matched_neighbour = neighbour
                break
        if not is_match:
            new_neighbour = Neighbor(router_id=ospf_header.router_id, interface=self, ip_address=ip_header.sourceIP,
                                     options=hello_packet.options)
            new_neighbour.priority = hello_packet.router_priority
            self.neighbours.append(new_neighbour)
            matched_neighbour = new_neighbour
        self.debug(f'save ori priority {matched_neighbour.priority} of neighbour')
        ori_priority = matched_neighbour.priority
        ori_dr = matched_neighbour.dr
        ori_bdr = matched_neighbour.bdr
        need_continue = matched_neighbour.receive_hello_packet(ip_header, ospf_header, hello_packet)
        if not need_continue:
            self.info('shutup hello process because 1-way')
            return
        if matched_neighbour.priority != ori_priority:
            self.info(f'neighbour {matched_neighbour.router_id} priority changed, trigger neighbour change event.')
            self.event_neighbour_change()
        if (matched_neighbour.dr == matched_neighbour.ip_address) and matched_neighbour.bdr == '0.0.0.0' and \
                (self.STATE == OSPFInterfaceState.WAITING):
            self.info(f'neighbour {matched_neighbour.router_id} claim self be DR, interface is Waiting, backup seen.')
            self.event_backup_seen()
        elif ((ori_dr == matched_neighbour.ip_address) and (matched_neighbour.dr != matched_neighbour.ip_address)) or \
                ((ori_dr != matched_neighbour.ip_address) and (matched_neighbour.dr == matched_neighbour.ip_address)):
            self.info(f'neighbour {matched_neighbour.router_id} dr self-claim changed, trigger neighbour change event.')
            self.event_neighbour_change()
        if (matched_neighbour.bdr == matched_neighbour.ip_address) and (self.STATE == OSPFInterfaceState.WAITING):
            self.info(f'neighbour {matched_neighbour.router_id} claim self be BDR, interface is Waiting, backup seen.')
            self.event_backup_seen()
        elif ((ori_bdr == matched_neighbour.ip_address) and (matched_neighbour.bdr != matched_neighbour.ip_address)) or \
                ((ori_bdr != matched_neighbour.ip_address) and (matched_neighbour.bdr == matched_neighbour.ip_address)):
            self.info(
                f'neighbour {matched_neighbour.router_id} bdr self-claim changed, trigger neighbour change event.')
            self.event_neighbour_change()
        self.info('finished receiving hello packet.')

    def receive_dd_packet(self, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                          dd_data: OSPFDDData, lsa_headers: List[OSPFLSAHeaderData]):
        for nei in self.neighbours:
            self.debug(f'checking dispatch dd for nei {nei.router_id}')
            if nei.ip_address == ip_header.sourceIP:
                self.debug(f'neighbour {nei.router_id} \'s ip address match, dispatch to this neighbour')
                nei.receive_dd_packet(ip_header, ospf_header, dd_data, lsa_headers)
                return
        self.debug('dispatch dd failed in this interface')

    def get_dr_neighbour(self):
        for nei in self.neighbours:
            if nei.router_id == self.dr:
                return nei

        return None

    def get_bdr_neighbour(self):
        for nei in self.neighbours:
            if nei.router_id == self.bdr:
                return nei

    def can_be_trans_net(self):
        if (nei := self.get_dr_neighbour()) and nei.STATE == OSPFNeighbourState.FULL:
            return True
        if self.STATE == OSPFInterfaceState.DR:
            for nei in self.neighbours:
                if nei.STATE == OSPFNeighbourState.FULL:
                    return True
        return False

    def receive_lsr_packet(self, area, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                           lsr_data: OSPFLSRDATA):
        for nei in self.neighbours:
            if nei.ip_address == ip_header.sourceIP:
                self.debug(f'neighbour {nei.router_id} receive this packet, dispatch to this neighbour')
                nei.receive_lsr_packet(area, ip_header, ospf_header, lsr_data)
                return
        self.debug('dispatch lsr packet failed')

    def receive_lsack_packet(self, area, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                        lsa_headers: List[OSPFLSAHeaderData]):
        for nei in self.neighbours:
            if ip_header.sourceIP == nei.ip_address:
                self.debug(f'neibour {nei.router_id} receive ack packet')
                nei.receive_lsack_packet(area, ip_header, ospf_header, lsa_headers)



    def gen_network_lsa(self):
        if not self.STATE == OSPFInterfaceState.DR:
            self.info('ERROR!')
            logging.error('this interface is not dr but gen network_lsa is called.')
            return
        attached_routers = []  # full state neighbour
        for nei in self.neighbours:
            if nei.STATE == OSPFNeighbourState.FULL:
                attached_routers.append(nei.router_id)
        attached_routers.append(self.area.router_id)
        lsa = Network_LSA(gen_options(1, 0, 0, 0, 0),
                          self.ip,
                          self.area.router_id,
                          self.area.gen_lsa_seq(),
                          self.mask,
                          attached_routers)
        return lsa

    def send_ack_for_lsa(self, lsa:LSA):
        self.info(f'sending lsack for lsa: {lsa}')
        send_lsack_packet(self.ip,
                          ALLSPFRouterIP if (self.STATE == OSPFInterfaceState.DR or
                                                      self.STATE == OSPFInterfaceState.BACKUP) else ALLDRoutersIP,
                          self.area.router_id,
                          self.area.id,
                          [lsa]
                          )
