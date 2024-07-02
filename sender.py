from OSPFData import *
from IPData import IPHeaderOperator
from tools import cal_checksum
from STATIC import *


def send_packet_on(packet, source, destination):
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        sock.bind((source, 0))
        sock.sendto(packet, (destination, 0))

def send_hello_packet(source_id, destination_ip, router_id, area_id, network_mask, hello_interval, options, priority,
                      dead_interval,
                      designated_router,
                      backup_designated_router, neighbours):
    ip_header_operator = IPHeaderOperator()
    ip_header = ip_header_operator.encode(source_id, destination_ip, identification=get_identification())
    hello_operator = OSPFHelloOperator()
    ospf_hello = hello_operator.encode(network_mask, hello_interval, options, priority, dead_interval,
                                       designated_router,
                                       backup_designated_router, neighbours)
    packet_len = len(ospf_hello) + 24  # 24是OSPF头的长度

    operator = OSPFHeaderOperator()

    # 构建OSPF头(无校验和)
    ospf_header = operator.encode(type=1, packetLenth=packet_len, router_id=router_id, area_id=area_id, checksum=0)
    # 完整的OSPF HELLO包
    ospf_packet = ospf_header + ospf_hello
    ospf_header = operator.encode(type=1, packetLenth=packet_len, router_id=router_id, area_id=area_id,
                                  checksum=cal_checksum(ospf_packet))
    ospf_packet = ospf_header + ospf_hello

    # 将IP头和OSPF HELLO包结合在一起
    packet = ip_header + ospf_packet
    send_packet_on(packet, source_id, destination_ip)



def send_dd_packet(source_id, destination_ip, router_id, area_id, mtu, options, dd_options, dd_seq, lsas):
    ip_header_operator = IPHeaderOperator()
    ip_header = ip_header_operator.encode(source_id, destination_ip, identification=get_identification())
    dd_operator = OSPFDDOperator()
    ospf_dd = dd_operator.encode(mtu, options, dd_options, dd_seq)
    lsas_data = []
    for lsa in lsas:
        _ = lsa.gen_packet_header()
        lsas_data.append(_)

    packet_len = len(ospf_dd) + 20 * len(lsas_data) + 24  # 24是OSPF头的长度

    operator = OSPFHeaderOperator()

    # 构建OSPF头(无校验和)
    ospf_header = operator.encode(type=2, packetLenth=packet_len, router_id=router_id, area_id=area_id, checksum=0)
    # 完整的OSPF HELLO包
    ospf_packet = ospf_header + ospf_dd
    for lsa_data in lsas_data:
        ospf_packet += lsa_data

    ospf_header = operator.encode(type=2, packetLenth=packet_len, router_id=router_id, area_id=area_id,
                                  checksum=cal_checksum(ospf_packet))
    ospf_packet = ospf_header + ospf_dd
    for lsa_data in lsas_data:
        ospf_packet += lsa_data

    # 将IP头和OSPF HELLO包结合在一起
    packet = ip_header + ospf_packet
    send_packet_on(packet, source_id, destination_ip)


def send_lsr_packet(source_ip, destination_ip, router_id, area_id, lsa_headers):
    ip_header_operator = IPHeaderOperator()
    ip_header = ip_header_operator.encode(source_ip, destination_ip, identification=get_identification())
    lsr_operator = OSPFLSROperator()
    idents = [easydict.EasyDict(
        {'type': header.type,
         'id': header.id,
         'advertising_router':header.advertising_router}
    ) for header in lsa_headers]
    ospf_lsr = lsr_operator.encode(idents)

    packet_len = len(ospf_lsr) + 24  # 24是OSPF头的长度

    operator = OSPFHeaderOperator()

    # 构建OSPF头(无校验和)
    ospf_header = operator.encode(type=3, packetLenth=packet_len, router_id=router_id, area_id=area_id, checksum=0)
    # 完整的OSPF HELLO包
    ospf_packet = ospf_header + ospf_lsr

    ospf_header = operator.encode(type=3, packetLenth=packet_len, router_id=router_id, area_id=area_id,
                                  checksum=cal_checksum(ospf_packet))
    ospf_packet = ospf_header + ospf_lsr

    # 将IP头和OSPF HELLO包结合在一起
    packet = ip_header + ospf_packet
    send_packet_on(packet, source_ip, destination_ip)

def send_lsa_to(source_ip, destination_ip, router_id, area_id, lsa):
    logging.info('sending lsa to interface')
    ip_header_operator = IPHeaderOperator()
    ip_header = ip_header_operator.encode(source_ip, destination_ip, identification=get_identification())
    lsu_operator = OSPFLSUOperator()
    lsu_data = lsu_operator.encode(1)
    lsa_data = lsa.gen_packet_header()+lsa.gen_packet_body()

    packet_len = len(lsu_data) + len(lsa_data) + 24  # 24是OSPF头的长度

    operator = OSPFHeaderOperator()

    # 构建OSPF头(无校验和)
    ospf_header = operator.encode(type=4, packetLenth=packet_len, router_id=router_id, area_id=area_id, checksum=0)
    # 完整的OSPF HELLO包
    ospf_packet = ospf_header + lsu_data + lsa_data

    ospf_header = operator.encode(type=4, packetLenth=packet_len, router_id=router_id, area_id=area_id,
                                  checksum=cal_checksum(ospf_packet))
    ospf_packet = ospf_header + lsu_data + lsa_data

    # 将IP头和OSPF HELLO包结合在一起
    packet = ip_header + ospf_packet
    send_packet_on(packet, source_ip, destination_ip)

def send_lsack_packet(source_ip, destination_ip, router_id, area_id, lsas):
    ip_header_operator = IPHeaderOperator()
    ip_header = ip_header_operator.encode(source_ip, destination_ip, identification=get_identification())
    lsack_operator = OSPFLSAckOperator()
    ospf_lsack = lsack_operator.encode(lsas)

    packet_len = len(ospf_lsack) + 24  # 24是OSPF头的长度

    operator = OSPFHeaderOperator()

    # 构建OSPF头(无校验和)
    ospf_header = operator.encode(type=5, packetLenth=packet_len, router_id=router_id, area_id=area_id, checksum=0)
    # 完整的OSPF HELLO包
    ospf_packet = ospf_header + ospf_lsack

    ospf_header = operator.encode(type=5, packetLenth=packet_len, router_id=router_id, area_id=area_id,
                                  checksum=cal_checksum(ospf_packet))
    ospf_packet = ospf_header + ospf_lsack

    # 将IP头和OSPF HELLO包结合在一起
    packet = ip_header + ospf_packet
    send_packet_on(packet, source_ip, destination_ip)