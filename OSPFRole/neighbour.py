import random
from threading import Timer
from IPData import *
from sender import *
from OSPFRole.LSA import *


class Neighbor():
    def __init__(self, router_id, ip_address, interface, options, is_master: bool = False):
        self.router_id = router_id
        self.ip_address = ip_address
        self.STATE: OSPFNeighbourState = OSPFNeighbourState.DOWN
        self.isMaster = is_master
        self.dd_seq = 0
        self.receive_dd_M = False
        self.receive_dd_MS = False
        self.receive_dd_I = False
        self.options = options
        self.dr = ''
        self.bdr = ''
        self.sending_lsas = {}
        self.request_needed_lsas: List[OSPFLSAHeaderData] = []
        self.database_summary_list: List[LSA] = []
        self.inactive_timer: Timer = None
        self.interface = interface
        self.priority = -1
        self.retrans_timer: Timer = None

    def debug(self, str):
        logging.debug(f'[neighbour {self.router_id}]: {str}')

    def info(self, str):
        logging.info(f'[neighbour {self.router_id}]: {str}')

    def reset_all(self):
        if self.inactive_timer:
            self.inactive_timer.cancel()
            self.inactive_timer = None
        self.info('self reset')
        self.dd_seq = 0
        self.receive_dd_M = False
        self.receive_dd_MS = False
        self.receive_dd_I = False
        self.options = None  # todo: fill
        self.dr = ''
        self.bdr = ''
        self.sending_lsas = {}  # lsa, timer
        self.request_needed_lsas = []
        self.inactive_timer: Timer = None

    def kill_neighbour(self, interface):
        self.info('self killed')
        # todo:send kill packet
        self.STATE = OSPFNeighbourState.DOWN

    def inactive_timer_callback(self):
        self.debug('neighbour inactive timer callback')
        self.inactive_timer = None
        self.STATE = OSPFNeighbourState.DOWN
        self.reset_all()

    def create_inactive_timer(self):
        self.debug('neighbour create inactive_timer')
        self.inactive_timer = Timer(self.interface.router_dead_interval, self.inactive_timer_callback)

    def resend_exstart_dd_callback(self):
        self.debug(f'resend dd callback! resending DD packet to neighbour, interval {self.interface.retrans_interval}')
        send_dd_packet(self.interface.ip, self.ip_address, self.interface.area.router_id,
                       self.interface.area.id, 1500, gen_options(1, 0, 0, 0, 0),
                       gen_DD_options(True, True, True), self.dd_seq, [])
        self.retrans_timer = Timer(self.interface.retrans_interval, self.resend_exstart_dd_callback)
        self.retrans_timer.start()

    def resend_dd_callback(self, source_id, destination_ip, router_id, area_id, mtu, options, dd_options, dd_seq, lsas):
        self.debug('resend dd callback general! resending dd packet')
        send_dd_packet(source_id, destination_ip, router_id, area_id, mtu, options, dd_options, dd_seq, lsas)
        self.retrans_timer = Timer(self.interface.retrans_interval, self.resend_dd_callback,
                                   args=[source_id, destination_ip, router_id, area_id,
                                         mtu, options, dd_options, dd_seq, lsas])
        self.retrans_timer.start()

    def event_hello_received(self):
        if self.STATE == OSPFNeighbourState.DOWN:
            self.STATE = OSPFNeighbourState.INIT
            self.info('self from Down to Init')
            self.create_inactive_timer()
        else:
            if self.inactive_timer:
                self.inactive_timer.cancel()
                self.create_inactive_timer()

    def exstart(self):
        self.dd_seq = random.choice(range(1000))  # 初始化自己的DD序号
        self.info(f'sending dd packet and create resend timer, choose dd seq is {self.dd_seq}')
        self.resend_exstart_dd_callback()

    def need_adj(self) -> bool:
        drs = []
        if len(self.interface.dr):
            drs.append(self.interface.dr)
        if len(self.interface.bdr):
            drs.append(self.interface.bdr)
        if len(self.dr):
            drs.append(self.interface.transform_neighbour_ip_to_id(self.dr))
        if len(self.bdr):
            drs.append(self.interface.transform_neighbour_ip_to_id(self.bdr))
        self.debug(f'checking adj with {drs}')
        if (self.router_id in drs) or (self.interface.area.router_id in drs):  # 该邻居是DR/BDR或者本机是DR/BDR，则产生邻接
            return True
        return False

    def check_adj(self):
        self.debug('self check adj')
        if self.STATE == OSPFNeighbourState.TWOWAY:
            if self.need_adj():
                self.STATE = OSPFNeighbourState.EXSTART
                self.exstart()
                self.debug('need adj')
        elif self.STATE > OSPFNeighbourState.TWOWAY:
            if not self.need_adj():
                self.STATE = OSPFNeighbourState.TWOWAY
                # todo 拆除邻接关系？

    def event_two_way_received(self):
        self.info('event two wawy received')
        if self.STATE == OSPFNeighbourState.INIT:
            if self.need_adj():
                self.STATE = OSPFNeighbourState.EXSTART
                self.info('from Init to Exstart')
                self.exstart()
            else:
                self.STATE = OSPFNeighbourState.TWOWAY
                self.info('from Init to TwoWay')

    def event_one_way_received(self):
        self.info('event one wawy received')
        pass  # todo

    def event_negotiation_done(self):
        self.info('event negotiation down, start listing all area lsas')
        self.retrans_timer.cancel()
        self.debug('retrans timer cancel')
        self.database_summary_list = []
        self.database_summary_list += self.interface.area.router_lsa
        self.database_summary_list += self.interface.area.network_lsa
        self.database_summary_list += self.interface.area.summary_lsa
        self.info(f'self database_summary_list len is {len(self.database_summary_list)}')
        self.info('self into Exchange')
        self.STATE = OSPFNeighbourState.EXCHANGE

    def receive_hello_packet(self, ip_header: IPHeaderData, ospf_header: OSPFHeaderData, hello_packet: OSPFHelloData):
        oripri = self.priority
        self.router_id = ospf_header.router_id
        self.priority = hello_packet.router_priority
        self.dr = hello_packet.dr
        self.bdr = hello_packet.bdr

        # 检查其余部分，生成事件
        self.event_hello_received()
        # 检查自己是否出现在hello的neighbour中
        if self.interface.area.router_id in hello_packet.neighbours:
            self.event_two_way_received()
        else:
            self.event_one_way_received()
            return False
        return True

    def event_seq_number_mismatch(self):
        self.info('seq number mismatch event.')
        # todo

    def event_exchange_done(self):
        self.info('exchange done event')
        self.retrans_timer.cancel()
        if self.STATE == OSPFNeighbourState.EXCHANGE:
            if len(self.request_needed_lsas):
                self.info('self into LOADING')
                self.STATE = OSPFNeighbourState.LOADING
                send_lsr_packet(self.interface.ip, self.ip_address,
                                self.interface.area.router_id,
                                self.interface.area.id,
                                self.request_needed_lsas
                                )
                self.info('sending lsr to neighbour.')
            else:
                self.info('self into FULL')
                self.STATE = OSPFNeighbourState.FULL

    def send_dd_in_exchange(self):
        self.info('sending dd in exchange')
        self.retrans_timer.cancel()
        self.debug('retrans timer cancel')
        lsas_to_send = []
        if len(self.database_summary_list):
            lsas_to_send.append(self.database_summary_list[-1])
            self.database_summary_list = self.database_summary_list[:-1]
        self.resend_dd_callback(self.interface.ip, self.ip_address, self.interface.area.router_id,
                                self.interface.area.id, 1500,
                                gen_options(1, 0, 0, 0, 0),
                                gen_DD_options(
                                    False,
                                    True if len(self.database_summary_list) > 0 else False,
                                    False if self.isMaster else True
                                ), self.dd_seq, lsas_to_send)

    def receive_dd_packet(self, ip_header, ospf_header: OSPFHeaderData, dd_data: OSPFDDData, lsa_headers):
        self.receive_dd_I = dd_data.DD_options & OSPFDDOptionMask.I
        self.receive_dd_M = dd_data.DD_options & OSPFDDOptionMask.M
        self.receive_dd_MS = dd_data.DD_options & OSPFDDOptionMask.MS
        self.debug(f'receiving dd packet of I={self.receive_dd_I}, M={self.receive_dd_M}, MS={self.receive_dd_MS}')
        if self.STATE == OSPFNeighbourState.DOWN or \
                self.STATE == OSPFNeighbourState.ATTEMPT or \
                self.STATE == OSPFNeighbourState.TWOWAY:
            self.info('self State ignore this dd packet')
            return
        if self.STATE == OSPFNeighbourState.INIT:
            self.event_two_way_received()
        elif self.STATE == OSPFNeighbourState.EXSTART:
            # if not (dd_data.options == self.options):
            #     self.info(f'option is {dd_data.options}, not match {self.options}')
            #     return
            if (self.receive_dd_I and self.receive_dd_MS and self.receive_dd_M and len(lsa_headers) == 0 and
                    compare_router_id_bigger(self.router_id, self.interface.area.router_id) > 0):
                self.retrans_timer.cancel()
                self.isMaster = True
                self.dd_seq = dd_data.DD_seq
                self.info('this neighbour is Master')
                # should send dd packet
                send_dd_packet(self.interface.ip, self.ip_address, self.interface.area.router_id,
                               self.interface.area.id, 1500, gen_options(1, 0, 0, 0, 0),
                               gen_DD_options(False, True, False), self.dd_seq, [])
                self.event_negotiation_done()
            elif (self.receive_dd_I == 0 and self.receive_dd_MS == 0 and dd_data.DD_seq == self.dd_seq
                  and compare_router_id_bigger(self.interface.area.router_id, self.router_id) > 0):
                self.isMaster = False
                self.info('this neighbour is Slave, this router is Master')
                self.event_negotiation_done()
                self.debug(f'checking lsa headers (numbers: {len(lsa_headers)})')

                now_lsa_id = set([header.id for header in self.request_needed_lsas])

                self.debug(f'now wait requesting lsa list is {now_lsa_id}')
                for lsa_header in lsa_headers:
                    if lsa_header.id not in now_lsa_id:
                        self.request_needed_lsas.append(lsa_header)
                        self.debug(f'adding wait requesting lsa with id: {lsa_header.id}')
                self.dd_seq += 1
                self.send_dd_in_exchange()
        elif self.STATE == OSPFNeighbourState.EXCHANGE:
            if ((dd_data.DD_options & OSPFDDOptionMask.MS and not self.isMaster) or
                    (not (dd_data.DD_options & OSPFDDOptionMask.MS) and self.isMaster)):
                self.debug('master claim mismatch')
                self.event_seq_number_mismatch()
                return
            # if dd_data.options != self.options:
            #     self.debug('options mismatch')
            #     self.event_seq_number_mismatch()
            #     return
            if self.isMaster and dd_data.DD_seq != self.dd_seq + 1:
                self.debug(f'master neighbour seq not match, packet seq is {dd_data.DD_seq}, self seq is {self.dd_seq}')
                self.event_seq_number_mismatch()
                return
            if not self.isMaster and dd_data.DD_seq != self.dd_seq:
                self.debug('slave neighbour seq not match')
                self.event_seq_number_mismatch()
                return
            self.debug(f'checking lsa headers (numbers: {len(lsa_headers)})')

            now_lsa_id = set([header.id for header in self.request_needed_lsas])
            self.retrans_timer.cancel()
            self.debug(f'now wait requesting lsa list is {now_lsa_id}')
            self.debug(f'now summary list is {self.database_summary_list}')
            for lsa_header in lsa_headers:
                if lsa_header.id not in now_lsa_id:
                    self.request_needed_lsas.append(lsa_header)
                    self.debug(f'adding wait requesting lsa with id: {lsa_header.id}')
            if not self.isMaster:
                self.dd_seq += 1
                if len(self.database_summary_list) == 0 and dd_data.DD_options & OSPFDDOptionMask.M == 0:
                    self.event_exchange_done()
                else:
                    self.send_dd_in_exchange()
            else:
                self.dd_seq = dd_data.DD_seq
                self.send_dd_in_exchange()
                if len(self.database_summary_list) == 0 and dd_data.DD_options & OSPFDDOptionMask.M == 0:
                    self.event_exchange_done()
            self.debug(f'self seq now is {self.dd_seq}')
        else:
            if ((dd_data.DD_options & OSPFDDOptionMask.MS and not self.isMaster) or
                    (not (dd_data.DD_options & OSPFDDOptionMask.MS) and self.isMaster)):
                self.debug('master claim mismatch')
                self.event_seq_number_mismatch()
                return
            # if dd_data.options != self.options:
            #     self.debug('options mismatch')
            #     self.event_seq_number_mismatch()
            #     return
            if self.isMaster and dd_data.DD_seq != self.dd_seq + 1:
                self.debug(f'master neighbour seq not match, packet seq is {dd_data.DD_seq}, self seq is {self.dd_seq}')
                self.event_seq_number_mismatch()
                return
            if not self.isMaster and dd_data.DD_seq != self.dd_seq:
                self.debug('slave neighbour seq not match')
                self.event_seq_number_mismatch()
                return
            self.retrans_timer.cancel()

    def event_bad_ls_req(self):
        self.info('event bad_ls_seq')

    def lsa_resend_callback(self, lsa):
        # send lsu with lsa
        self.info(f'resending lsa: {lsa}')
        send_lsa_to(source_ip=self.interface.ip,
                    destination_ip=ALLSPFRouterIP if (self.interface.STATE == OSPFInterfaceState.DR or
                                                      self.interface.STATE == OSPFInterfaceState.BACKUP) else ALLDRoutersIP,
                    # destination_ip=self.ip_address,
                    router_id=self.interface.area.router_id,
                    area_id=self.interface.area.id,
                    lsa=lsa
                    )
        self.sending_lsas[lsa] = Timer(self.interface.retrans_interval, self.lsa_resend_callback, args=[lsa])
        self.sending_lsas[lsa].start()

    def receive_lsr_packet(self, area, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                           lsr_data: OSPFLSRDATA):
        for ident in lsr_data.lsa_idents:
            if (find_res := self.interface.area.get_lsa_by_ident(ident)):
                self.debug(f'sending lsu for {find_res}')
                self.lsa_resend_callback(find_res)
                return
            else:
                self.event_bad_ls_req()

    def receive_lsack_packet(self, area, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                             lsa_headers: List[OSPFLSAHeaderData]):
        if len(self.sending_lsas) == 0:
            return
        for lsa_head in lsa_headers:
            orikeys = [x for x in self.sending_lsas]
            for lsa in orikeys:
                if lsa.type == lsa_head.type and lsa.advertising_router == lsa_head.advertising_router and \
                        lsa.id == lsa_head.id:
                    self.sending_lsas[lsa].cancel()
                    del self.sending_lsas[lsa]
                    self.debug(f'receiving ack of lsa: {lsa}, cancel retrans timer')
                    break
        if len(self.sending_lsas) == 0 and self.STATE == OSPFNeighbourState.LOADING:
            self.STATE = OSPFNeighbourState.FULL
            self.info('self into FULL, loading done. trigger flash area lsa')
            self.interface.area.fresh_router_lsa()
            self.interface.flesh_network_lsa()
