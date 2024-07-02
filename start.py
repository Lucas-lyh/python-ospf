import signal
import os
from IPData import *
import OSPFRole.area as area
from OSPFRole.LSA import *
from calculator import cal_path


def handle_hello_packet(area: area.Area, ip_header: IPHeaderData, header: OSPFHeaderData, packet: OSPFHelloData, interface):
    logging.debug('[handle hello] dispatch hello data packet with: ' + str(packet))
    logging.debug(f'[handle hello] checking for interface {interface.interface_name}')
    if interface.router_dead_interval != packet.router_dead_interval:
        logging.debug(f'packet dead interval of {packet.router_dead_interval} '
                      f'not match {interface.router_dead_interval}')
        return
    if interface.hello_interval != packet.hello_interval:
        logging.debug(f'packet hello interval of {packet.hello_interval}'
                      f'not match {interface.hello_interval}')
        return
    if interface.mask != packet.network_mask:
        logging.debug(f'packet network mask of {packet.network_mask}'
                      f'not match {interface.mask}')
        return
    if interface.ip == ip_header.sourceIP:
        logging.debug('mine ip, pass!')
        return
    logging.debug(f'[handle hello] pass packet check for interface {interface.interface_name},'
                  f'move control to interface')
    interface.receive_hello_packet(ip_header, header, packet)


def handle_dd_packet(area: area.Area, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                     dd_data: OSPFDDData, lsa_headers: List[OSPFLSAHeaderData], interface):
    logging.debug('[handle dd] dispatching packet')
    logging.debug(f'[handle dd] continue checking in interface {interface.interface_name}')
    interface.receive_dd_packet(ip_header, ospf_header, dd_data, lsa_headers)


def handle_lsr_packet(area: area.Area, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                      lsr_data: OSPFLSRDATA,interface):
    logging.debug(f'[handle lsr] dispatching packet with lsr_number:{len(lsr_data.lsa_idents)}')
    logging.debug(f'[handle lsr] continue checking in interface {interface.interface_name}')
    interface.receive_lsr_packet(area, ip_header, ospf_header, lsr_data)


def handle_lsu_packet(area: area.Area, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                      lsas: List[LSA],interface):
    source_interface = None
    if ip_in_net(ip_header.sourceIP, interface.ip, interface.mask):
        if ip_header.sourceIP == interface.ip:
            logging.debug('mine ip, pass')
            return
        source_interface = interface
    if not source_interface:
        logging.error('ERROR, source interface of lsu packet is not sure')
        return
    for lsa in lsas:
        source_interface.send_ack_for_lsa(lsa)
        area.add_lsa_to_area(lsa, source_interface)
        interface.receive_lsack_packet(area, ip_header, ospf_header,
                                       [OSPFLSAHeaderOperator().decode(lsa.gen_packet_header())])


def handle_lsack_packet(area: area.Area, ip_header: IPHeaderData, ospf_header: OSPFHeaderData,
                        lsa_headers: List[OSPFLSAHeaderData], interface):
    interface.receive_lsack_packet(area, ip_header, ospf_header, lsa_headers)


def receive_loop(area: area.Area, interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface.interface_name, 0))
    os.system(f'ifconfig {interface.interface_name} promisc')
    os.system(f'sysctl net.ipv4.conf.{interface.interface_name}.forwarding=1')
    ip_operator = IPHeaderOperator()
    ospf_header_operator = OSPFHeaderOperator()
    while True:
        packet, addr = sock.recvfrom(65535)
        # 检查IP协议是否为OSPF
        data = packet[14:]  # 跳过链路层
        ip_header = ip_operator.decode(data)
        data = ip_operator.next_data(data)
        if ip_header.protocol != OSPF_PROTOCOL:
            continue
        logging.info('[receive loop] receive packet from {} to {}'.format(ip_header.sourceIP, ip_header.destinationIP))
        ospf_header = ospf_header_operator.decode(data)
        data = ospf_header_operator.next_data(data)
        if ospf_header.version != 2:
            logging.warning('[receive loop][ospf header check] version {} need to be 2'.format(ospf_header.version))
            continue
        logging.debug('[receive loop] received ospf packet of |type:{}, routerID:{}, areaID:{}, auType:{}'
                      .format(ospf_header.type, ospf_header.router_id, ospf_header.area_id, ospf_header.autype))
        logging.info('[receive loop] received ospf packet of type:{}'.format(ospf_header.type))
        if ospf_header.type == OSPFPacketType.HELLO:
            operator = OSPFHelloOperator()
            hello_data = operator.decode(data)
            handle_hello_packet(area, ip_header, ospf_header, hello_data, interface)
        elif ospf_header.type == OSPFPacketType.DD:
            operator = OSPFDDOperator()
            dd_data = operator.decode(data)
            data = operator.next_data(data)
            lsa_headers = []
            while len(data):
                try:
                    lsa_header_operator = OSPFLSAHeaderOperator()
                    lsa_headers.append(lsa_header_operator.decode(data))
                    data = lsa_header_operator.next_data(data)
                except:
                    logging.warning(f'now data len is {len(data)}, can\'t decode as lsa_header')
            handle_dd_packet(area, ip_header, ospf_header, dd_data, lsa_headers, interface)
        elif ospf_header.type == OSPFPacketType.LSR:
            operator = OSPFLSROperator()
            lsr_data = operator.decode(data)
            handle_lsr_packet(area, ip_header, ospf_header, lsr_data, interface)
        elif ospf_header.type == OSPFPacketType.LSU:
            lsas: List[LSA] = []
            operator = OSPFLSUOperator()
            lsu_data = operator.decode(data)
            logging.debug('receiving lsu packet')
            for i in range(len(lsu_data.lsa_headers)):
                lsa_header = lsu_data.lsa_headers[i]
                lsa_data: LSA = lsu_data.lsa_datas[i]
                if lsa_header.type == 1:
                    lsa_data: OSPFRouterLSADATA = lsa_data
                    lsa = Router_LSA(lsa_header.options, lsa_header.id, lsa_header.advertising_router, lsa_header.seq,
                                     **Router_LSA.options2dict(lsa_data.options))
                    for link in lsa_data.links:
                        lsa.add_link(link.type, link.data, link.id, link.metric)
                    lsas.append(lsa)
                elif lsa_header.type == 2:
                    lsa_data: OSPFNetworkLSADATA = lsa_data
                    lsa = Network_LSA(lsa_header.options, lsa_header.id, lsa_header.advertising_router, lsa_header.seq,
                                      lsa_data.network_mask,
                                      lsa_data.attached_routers)
                    lsas.append(lsa)
                elif lsa_header.type == 3 or lsa_header.type == 4:
                    logging.warning('receiving summary lsa, not yet support')
                elif lsa_header.type == 5:
                    logging.warning('receiving as-external lsa not yet support')
            handle_lsu_packet(area, ip_header, ospf_header, lsas, interface)
        elif ospf_header.type == OSPFPacketType.LSA:
            operator = OSPFLSAckOperator()
            lsa_packet = operator.decode(data)
            handle_lsack_packet(area, ip_header, ospf_header, lsa_packet.lsa_headers, interface)


as_external_lsas = []
import yaml
with open('./config.yaml', 'r') as f:
    result = yaml.load(f.read(), Loader=yaml.FullLoader)

thisarea = area.Area(id=result['area_id'], router_id=result['router_id'], as_external_lsa=as_external_lsas)
for interface_name in result['interfaces']:
    thisarea.add_interface(interface_name)

receive_threads = [threading.Thread(target=receive_loop, kwargs={'area': thisarea, 'interface': interface})
                   for interface in thisarea.interfaces]
for thread in receive_threads:
    thread.start()


def term_sig_handler(a, b):
    for thread in receive_threads:
        signal.pthread_kill(thread.native_id, 15)


signal.signal(signal.SIGTERM, term_sig_handler)  # kill pid
signal.signal(signal.SIGINT, term_sig_handler)  # ctrl -c
for interface in thisarea.interfaces:  # 启动没有启动的interface
    if interface.STATE == OSPFInterfaceState.DOWN:
        interface.event_interface_up()
thisarea.fresh_router_lsa()

def start():
    while True:
        for i in range(len(thisarea.interfaces)):
            if not receive_threads[i].is_alive():
                logging.error('receive thread is DEAD, restart')
                receive_thread = threading.Thread(target=receive_loop,
                                                  kwargs={'area': thisarea, 'interface': thisarea.interfaces[i]})
                receive_thread.start()
                receive_threads[i] = receive_thread
        command = input()
        if command == 'lsdb':
            print(thisarea.lsdb_text())
        elif command == 'cal':
            print(cal_path(thisarea.router_lsa, thisarea.network_lsa, thisarea.get_mine_router_lsa()))
print("main process exit")

start()
