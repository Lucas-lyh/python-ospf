from OSPFRole.LSA import *
from tools import Route_item


class Node:
    def __init__(self, lsa):
        self._lsa = lsa
        self.is_router = (lsa.type == 1)
        self.is_network = (lsa.type == 2)
        self.router_lsa: Router_LSA = self._lsa
        self.network_lsa: Network_LSA = self._lsa
        self.adj = []
        self.cost = []


def gen_route_item_to(minlength_adj, next_hop, hop_node: Node):
    ret = []
    if hop_node.is_network:
        ret.append(Route_item(
            destination=ip_mask_to_net(hop_node.network_lsa.id,
                                       hop_node.network_lsa.network_mask),
            mask_len=mask_to_mask_len(hop_node.network_lsa.network_mask),
            next_hop=next_hop
        ))
        for node in minlength_adj[hop_node]:
            ret += gen_route_item_to(minlength_adj, next_hop, node)
    else:
        for link in hop_node.router_lsa.links:
            if link.type == OSPFRouterLinkType.stub_net:
                ret.append(Route_item(destination=link.id,
                                      mask_len=mask_to_mask_len(link.data),
                                      next_hop=next_hop))
        for node in minlength_adj[hop_node]:
            ret += gen_route_item_to(minlength_adj, next_hop, node)

    return ret


def cal_path(router_lsas: List[Router_LSA], network_lsas: List[Network_LSA], root: Router_LSA):
    routerid2node = {}
    networkdr2node = {}
    nodes = []
    for lsa in router_lsas:
        node = Node(lsa)
        nodes.append(node)
        routerid2node[lsa.id] = node
    for lsa in network_lsas:
        node = Node(lsa)
        nodes.append(node)
        networkdr2node[lsa.id] = node
    for node in nodes:
        if node.is_router:
            for link in node.router_lsa.links:
                if link.type == OSPFRouterLinkType.trans_net and link.id in networkdr2node:
                    node.adj.append(networkdr2node[link.id])
                    node.cost.append(link.metric)
        else:
            for router_id in node.network_lsa.attached_routers:
                if router_id in routerid2node:
                    node.adj.append(routerid2node[router_id])
                    node.cost.append(0)
    root_node = routerid2node[root.id]
    minlength = {}
    minlength[root_node] = 0
    cmp_path = {}
    for i in range(len(root_node.adj)):
        cmp_path[root_node.adj[i]] = (root_node.cost[i], root_node)
    minlength_adj = {}
    for node in nodes:
        minlength_adj[node] = []

    while len(cmp_path):
        min_path = None
        min_cost = 1000000
        for node in cmp_path:
            _cost, _father = cmp_path[node]
            if _cost < min_cost:
                min_cost = _cost
                min_path = (_father, node)
        del cmp_path[min_path[1]]
        minlength[min_path[1]] = min_cost
        minlength_adj[min_path[0]].append(min_path[1])
        for i in range(len(min_path[1].adj)):
            node = min_path[1].adj[i]
            cost = min_path[1].cost[i]
            if node in minlength:
                continue
            if node not in minlength:
                if (node not in cmp_path) or (cost + minlength[min_path[1]] < cmp_path[node][0]):
                    cmp_path[node] = cost + minlength[min_path[1]], min_path[1]
    route_items = []
    for link in root_node.router_lsa.links:
        if link.type == OSPFRouterLinkType.stub_net:
            route_items.append(Route_item(destination=link.id,
                                          mask_len=mask_to_mask_len(link.data),
                                          next_hop='0.0.0.0'))
    for net_node in minlength_adj[root_node]:
        net_ip = ip_mask_to_net(net_node.network_lsa.id,
                                net_node.network_lsa.network_mask)
        net_mask_len = mask_to_mask_len(net_node.network_lsa.network_mask)
        net_mask = net_node.network_lsa.network_mask
        route_items.append(Route_item(destination=net_ip,
                                      mask_len=net_mask_len,
                                      next_hop='0.0.0.0'))

        for router_node in minlength_adj[net_node]:
            next_hop_ip = None
            for link in router_node.router_lsa.links:
                if ip_in_net(link.data, net_ip, net_mask):
                    next_hop_ip = link.data
                    break
            if not next_hop_ip:
                continue
            route_items += gen_route_item_to(minlength_adj, next_hop_ip, router_node)
    return route_items
