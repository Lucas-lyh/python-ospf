from OSPFData import *
from IPData import *
# 定义OSPF协议号
from tools import *
# 创建原始套接字
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# 绑定到特定的网络接口
sock.bind(('ens33', 0))  # 将 'eth0' 替换为您捕获数据包的网络接口名称
ipOperator = IPHeaderOperator()
def parse_ospf_hello(packet):
    ospfHeaderOperator = OSPFHeaderOperator()
    ospf_hello_operator = OSPFHelloOperator()
    # 偏移量14跳过以太网头，20跳过IP头
    ospf_data = packet[0x22:]
    # 解包OSPF头部 (version, type, length, router_id, area_id, checksum, autype, authentication)
    logging.debug("packet len {}".format(len(ospf_data)))
    ospf_header = ospfHeaderOperator.decode(ospf_data)
    ospf_data = ospfHeaderOperator.next_data(ospf_data)
    ospf_hello_data = ospf_hello_operator.decode(ospf_data)



    # 检查是否为OSPF Hello包
    if ospf_header.type == 1:
        logging.debug("Received OSPF Hello Packet")
        router_id = ospf_header.router_id
        area_id = ospf_header.area_id
        logging.debug(f"Router ID: {router_id}")
        logging.debug(f"Area ID: {area_id}")
        # 此处可以根据需要继续解析Hello包的其他字段
        for k in ospf_hello_data:
            logging.debug("key:{}, value:{}".format(k, ospf_hello_data[k]))
        logging.debug("=== end of receiving ===")

while True:
    packet, addr = sock.recvfrom(65535)
    # 检查IP协议是否为OSPF
    ip_header_data = packet[14:34]
    ip_header = ipOperator.decode(ip_header_data)
    if ip_header.protocol == 89:
        logging.debug('receive!')
        parse_ospf_hello(packet)
