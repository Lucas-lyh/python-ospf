from OSPFRole.area import Area
from OSPFRole.interface import BoardcastInterface
from time import *

area = Area()
interface = BoardcastInterface('eth0', area)
interface.event_interface_up()
sleep(20)

