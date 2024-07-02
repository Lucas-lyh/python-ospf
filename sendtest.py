from sender import *
total = 0

# 设置源和目标IP地址
src_ip = '192.168.204.3'
dst_ip = '224.0.0.5'

# OSPF HELLO包的具体参数
router_id = '5.4.3.2'
area_id = '0.0.1.0'
network_mask = '255.255.255.0'
hello_interval = 10
options = 0x02
priority = 1
dead_interval = 40
designated_router = '192.168.1.1'
backup_designated_router = '192.168.1.2'

send_hello_packet(src_ip, dst_ip, router_id, area_id, network_mask, hello_interval, options, priority, dead_interval, designated_router,
                  backup_designated_router, [])
