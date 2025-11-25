import sys

sys.path.insert(1, '.')
from source import wsnlab_vis as wsn
import math
from source import config
from collections import Counter
import csv

from roles import Roles
from tracking_containers import *
from csv_utils import write_clusterhead_distances_csv

from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class NodeCapabilities:
    CAPABLE_CLUSTER_HEAD: bool = False
    CAPABLE_ROUTER: bool = False
    CAPABLE_ROOT_NODE: bool = False
    CAPABLE_GATEWAY: bool = False

# Neighbor Table entry data class
@dataclass(slots=True)
class NeighborTableEntry: # indexed by dynamic address
    uid: int | None # uid of the neighbor node
    nextHopAddr: wsn.Addr # address of next hop en route to nodeAddr (NET.NODE)
    hops: int  # hop count to reach this nodeAddr
    capabilities: NodeCapabilities | None  # capability Flags
    role: Roles | None # role
    lastHeard: float  # timesteps we last heard the node active
    rx_cost: float  # distance to next hop node
    path_cost: float | None = None  # cumulative cost to root advertised by this neighbor
    join_rejected_until: int = 0  # reject rejoin attempts to this neighbor until this time

# Member Table entry data class
@dataclass(slots=True)
class MemberTableEntry: # indexed by dynamic address
    uid: int  # uid of the member node
    renewal_valid: bool  # HIGH=Address renewal valid, LOW=Address renewal not valid (in progress)
    ack_seq_no: int  # last acknowledged sequence number, for renewal validation
    expiry_time: float  # time until which the membership is valid
    tx_power_level: int

# Child Network Table entry data class
@dataclass(slots=True)
class ChildNetworkEntry: # indexed by network id
    next_hop_addr: wsn.Addr # address of next hop en route to child network
    hops: int # hop count to reach this child network
    net_state: str # state "VALID", "PENDING", "STALE"
    last_heard: float  # timestamp of last heard from child network
    ack_seq_no: int  # seq number of NETID_RESP pending validation
    requester_uid: int  # uid of node requesting/owning this network

# for energy calc
def _estimate_packet_size_bytes(pck: dict) -> int:
    base = 64
    per_field = 4 # bytes per field
    field_count = sum(1 for key in pck.keys() if pck[key] is not None)
    return base + per_field * max(field_count, 0)

class SensorNode(wsn.Node):
    # Initialization of SensorNode
    def init(self):
        super().init()
        self.scene.nodecolor(self.id, 1, 1, 1)  # sets self color to white
        self.sleep()

        # ROOT
        self.root_addr: wsn.Addr = None  # root address (if we are not root this is None)
        self.is_root_eligible = True if self.id == ROOT_ID else False  # only one node is root eligible

        # CLUSTER HEAD
        self.ch_addr: wsn.Addr = None  # our cluster head address (if we are cluster head, this is our (x.254) address)
        self.tx_range_shape = None

        # REGISTERED/CLUSTER HEAD/ROUTER
        self.addr: wsn.Addr = None  # our dynamic child address (net_addr.node_addr)
        self.parent_address: wsn.Addr = None # parent address (x.254)
        self.parent_gui = None  # parent global unique id
        self.downstream_ch_addr = None  # downstream cluster head address for router
        self.downstream_ch_gui = None  # downstream cluster head gui id

        # TABLES
        self.neighbors_table = {}  # dictionary of NeighborTableEntry (keyed by dynamic address)
        self.child_networks_table = {}  # keeps child network info (keyed by network id)
        self.members_table = {}  # keeps members information (keyed by dynamic address)
        self.received_JR_guis = []  # keeps received Join Request global unique ids
        self.pending_netid_last_hops = {}  # tracks last hop addresses for pending NETID_RESPs (keyed by requester uid)

        self.set_role(Roles.UNDISCOVERED)  # setting role to UNDISCOVERED initially

        self.is_root_eligible = True if self.id == ROOT_ID else False  # only one node is root eligible
        self.c_probe = 0  # c means counter and probe is the name of counter
        self.th_probe = len(config.NODE_TX_RANGES) * 6  # 6 messages per power level (CH, CM, router)
        self.hop_count = 99999  # hop count to root, initialized to a large number
        self.probes_sent = 0  # number of probes sent

        self.tx_power_level = 0  # transmission power level,
        self.tx_range = config.NODE_TX_RANGES[self.tx_power_level] # set initial tx range

        self.seq_no = 0  # monotonic packet sequence number (wraps at 2^16)
        self.path_cost = None  # cumulative cost to root (rx_cost sum)

        # energy stuff
        self.battery_mj = config.BATTERY_CAPACITY_MJ
        self.is_alive = True

        # ad hoc routing
        self.broadcast_id = 0 # our id for routing requests
        self.rreq_seen = set() # (addr, rreq_id) tuples of seen RREQs
        self.pending_route_discovery = set() # prevent RREQs for the same target
        self.pending_ch_promotion = None  # track in-flight CH promotion (seq, target)
        self.last_parent_check = 0
        self.parent_set_time = 0
        self.router_links = set()  # uids of CHs we draw bridge lines to

        # debug counters
        self.debug_promote_attempts = 0
        self.debug_last_promote_log = 0
        self.debug_last_parent_hb_log = -999
        self.last_join_target: wsn.Addr | None = None  # last join attempt destination
        self.last_join_time: float = 0
        self.heartbeat_counter = 0  # tracks heartbeat invocations for periodic maintenance

    def build_common_packet(self, p_type="NULL", ack=False, dst_addr=wsn.BROADCAST_ADDR,
                            add_roles=False, add_capabilities=False):
        # if we are a cluster head (or root), our source address should be our CH address
        src_addr = self.addr
        if self.role is Roles.CLUSTER_HEAD or self.role is Roles.ROOT:
            src_addr = self.ch_addr

        # build common packet fields for this node
        packet = {
            'type': p_type,
            'addr_type': 0,  # 0/1 for standard/extended addressing (0 for now)
            'ack': ack, # ack back flag
            'hop_count': 0,  # hop count of packet, router will increment this when we send

            'seq_no': -1, # packet sequence number, filled in after send

            'dst_addr': dst_addr, # destination address
            'next_hop_addr': None, # next hop address (filled in by routing)
            'src_addr': src_addr, # source address

            # tracking fields
            'origin_uid': self.id,  # origin uid for tracing
            'created_time': self.now,  # trace latency from creation
            'path': [self.id]  # path trace seeded with sender
        }

        # add role attributes if requested
        if add_roles:
            packet.update({'role': self.role})
        if add_capabilities:
            packet.update({
                'capabilities': NodeCapabilities(
                    CAPABLE_CLUSTER_HEAD=True,  # all nodes can be cluster heads
                    CAPABLE_ROUTER=True,  # all nodes can be routers
                    CAPABLE_ROOT_NODE=(self.role == Roles.ROOT),  # only root node is capable root
                    CAPABLE_GATEWAY=(self.role == Roles.ROOT),  # only root node is capable gateway
                )
            })

        packet.update({'use_mesh': True})
        packet.update({'use_tree': True})

        return packet

    # check if packet should be dropped due to missing fields
    def _should_drop_packet(self, pck):
        p_type = pck.get('type', None)
        dst_addr = pck.get('dst_addr', None)
        next_hop_addr = pck.get('next_hop_addr', None)

        # missing type or destination
        if p_type is None or dst_addr is None:
            self.log(f"dropping packet with missing type or dst_addr: type={p_type} dst={dst_addr}")
            return True

        # ttl exceeded, drop
        if pck.get('hop_count', 0) >= config.ROUTING_MAX_HOPS:
            self.log(f"ttl exceeded {config.ROUTING_MAX_HOPS} type={pck.get('type')}"
                     f" uid={pck.get('uid')} dst={pck.get('dst_addr', -1)} path={pck.get('path')}")
            return True

        # if next hop is set, and it's not us, drop
        if next_hop_addr is not None:
            # drop only if it's not equal to ANY of our addresses
            if next_hop_addr not in (self.addr, self.ch_addr, self.root_addr, wsn.BROADCAST_ADDR):
                return True

        return False

    # check if packet is for us or if we should try to forward it
    def _is_packet_at_destination(self, pck):
        dest = pck.get('dst_addr', None)

        # broadcast is for us
        if dest == wsn.BROADCAST_ADDR:
            return True

        # destination is us, then it's for us
        if self.addr is not None and dest == self.addr:
            return True
        if self.ch_addr is not None and dest == self.ch_addr:
            return True
        if self.root_addr is not None and dest == self.root_addr:
            return True

        # network broadcast to our network (if in same network and node addr is broadcast)
        if self.addr is not None and dest.net_addr == self.addr.net_addr and dest.node_addr == config.BROADCAST_NODE_ADDR:
            return True
        if self.ch_addr is not None and dest.net_addr == self.ch_addr.net_addr and dest.node_addr == config.BROADCAST_NODE_ADDR:
            return True
        if self.root_addr is not None and dest.net_addr == self.root_addr.net_addr and dest.node_addr == config.BROADCAST_NODE_ADDR:
            return True

        # if we are here, not for us so we should try to forward
        return False

    def record_packet_delivery(self, pck, trace_decision: bool | None = None):
        created = pck.get('created_time')
        if created is None:
            return

        delivered = pck.get('arrival_time', self.now)
        path_list = pck.get('path', [])
        if isinstance(path_list, list):
            stored_path = path_list.copy()
        else:
            stored_path = [path_list]

        PACKET_DELIVERY_LOGS.append({
            "seq_no": pck.get("seq_no"),
            "type": pck.get("type"),
            "src_uid": pck.get("origin_uid", pck.get("uid")),
            "dst": str(pck.get("dst_addr", "")),
            "final_uid": self.id,
            "created": created,
            "delivered": delivered,
            "delay": delivered - created,
            "hop_count": pck.get("hop_count"),
            "path": stored_path,
        })

    def get_tx_power_level_for_dist(self, distance):
        if distance is None:
            return len(config.NODE_TX_RANGES) - 1

        target = distance  # find best tx power to match distance
        for idx, rng in enumerate(config.NODE_TX_RANGES):
            if rng >= target:
                return idx

        # fallback to max
        return len(config.NODE_TX_RANGES) - 1

    def set_tx_power_for_distance(self, distance):
        level = self.get_tx_power_level_for_dist(distance)
        self.tx_power_level = level
        self.tx_range = config.NODE_TX_RANGES[level]
        return level

    def compute_path_cost(self):
        # recompute our cumulative cost to root using parent path_cost + link cost through the tree
        if self.role == Roles.ROOT:
            self.path_cost = 0
            return 0
        if self.parent_address is None:
            self.path_cost = None
            return None
        p_entry = self.neighbors_table.get(self.parent_address)
        if p_entry is None or p_entry.path_cost is None or p_entry.rx_cost is None:
            self.path_cost = None
            return None
        self.path_cost = p_entry.path_cost + p_entry.rx_cost
        return self.path_cost

    # get a neighbors role
    def get_neighbor_role(self, addr: wsn.Addr):
        # TODO we need to handle if addr is a CH address (x.254), that needs to be documented in the neighbor table or handled here
        entry: NeighborTableEntry = self.neighbors_table.get(addr)
        if entry is None:
            return None
        return entry.role

    # def draw_parent(self):
    #     # skip parent arrow when upstream is a pure router; routers use bridge links instead
    #     if self._parent_is_router():
    #         self.erase_parent()
    #         return
    #     super().draw_parent()
    #
    # def update_parent_visual(self):
    #     # Only draw parent arrow when parent is not a pure router
    #     if self._parent_is_router() or self.parent_gui is None:
    #         self.erase_parent()
    #         return
    #     self.draw_parent()

    # send a packet, specify tx power level if desired
    def send(self, pck, tx_level=None):
        # don't send if dead
        if not self.is_alive:
            return -1

        # drop packet if missing fields
        if pck.get('dst_addr') is None:
            self.log(f"not sending packet with missing dst_addr: type={pck.get('type')} uid={pck.get('uid')}")
            return -1

        # if we got here and our next hop is still none, set to dst
        if pck.get('next_hop_addr', None) is None:
            # self.log("warning: packet next_hop_addr not set, defaulting to dst_addr")
            pck['next_hop_addr'] = pck.get('dst_addr')

        # pick tx power to next hop for this packet
        if tx_level is None:
            # broadcast goes out at max power
            if pck.get('dst_addr') == wsn.BROADCAST_ADDR:
                tx_level = len(config.NODE_TX_RANGES) - 1
            else:
                # try to size power for the selected next hop/destination
                next_hop_addr = pck.get('next_hop_addr', None)
                if next_hop_addr is not None:
                    entry = self.neighbors_table.get(next_hop_addr, None)
                    if entry is not None:
                        tx_level = self.get_tx_power_level_for_dist(entry.rx_cost)

        # validate/adjust tx level
        try:
            tx_level = int(tx_level)
        except (TypeError, ValueError):
            tx_level = len(config.NODE_TX_RANGES) - 1

        # compute energy cost and deduct from battery
        self.battery_mj -= ((_estimate_packet_size_bytes(pck) * config.TX_ENERGY_PER_BYTE_UJ[tx_level]) + config.TX_OVERHEAD_UJ) / 1000.0

        # did we die?
        if self.battery_mj <= config.MIN_BATTERY_MJ:
            self.is_alive = False
            return -1  # node died, packet not sent

        # monotonic sequence number
        seq_no = self.seq_no
        pck.update({'seq_no': seq_no})
        self.seq_no = (seq_no + 1) % (2 ** 16)  # inc and wrap at 65536

        # increase hop count
        pck.update({'hop_count': pck.get('hop_count', 0) + 1})

        # stamp the last hop and uid into the packet
        if self.role is Roles.CLUSTER_HEAD or self.role is Roles.ROOT:
            pck.update({'last_router': self.ch_addr, 'last_tx_uid': self.id})
        else:
            pck.update({'last_router': self.addr, 'last_tx_uid': self.id})

        # apply tx range for this packet
        self.tx_power_level = tx_level
        self.tx_range = config.NODE_TX_RANGES[tx_level]

        super().send(pck)

        return seq_no

    # arrival event handler
    def run(self):
        self.set_timer('TIMER_ARRIVAL', self.arrival)

    # runs to set the node role
    def set_role(self, new_role, *, recolor=True):
        # update global role counts
        old_role = getattr(self, "role", None)
        if old_role is not None:
            ROLE_COUNTS[old_role] -= 1
            if ROLE_COUNTS[old_role] <= 0:
                ROLE_COUNTS.pop(old_role, None)
        ROLE_COUNTS[new_role] += 1

        self.role = new_role

        if recolor:
            if new_role == Roles.UNDISCOVERED:
                self.scene.nodecolor(self.id, 1, 1, 1)
            elif new_role == Roles.UNREGISTERED:
                self.scene.nodecolor(self.id, 1, 1, 0)
            elif new_role == Roles.REGISTERED:
                self.scene.nodecolor(self.id, 0, 1, 0)
                # parent arrow drawn on join ack
            elif new_role == Roles.CLUSTER_HEAD:
                self.scene.nodecolor(self.id, 0, 0, 1)
                self.tx_power_level = len(config.NODE_TX_RANGES) - 1
                self.tx_range = config.NODE_TX_RANGES[self.tx_power_level]
                self.draw_tx_range()
                # parent arrow drawn later via update_parent_visual() after HEART_BEAT confirms parent role
            elif new_role == Roles.ROUTER:
                self.scene.nodecolor(self.id, 1, 0, 0)
                self.tx_power_level = len(config.NODE_TX_RANGES) - 1
                self.tx_range = config.NODE_TX_RANGES[self.tx_power_level]
                # routers draw bridge links only (no tx range circle)
                self.clear_tx_range()
                # self.update_parent_visual()
            elif new_role == Roles.ROOT:
                self.scene.nodecolor(self.id, 0, 0, 0)
                self.tx_power_level = len(config.NODE_TX_RANGES) - 1
                self.tx_range = config.NODE_TX_RANGES[self.tx_power_level]
                self.draw_tx_range()
                self.set_timer('TIMER_EXPORT_CH_CSV', config.EXPORT_CH_CSV_INTERVAL)
                self.set_timer('TIMER_EXPORT_NEIGHBOR_CSV', config.EXPORT_NEIGHBOR_CSV_INTERVAL)

        # record join complete time
        if new_role in (Roles.REGISTERED, Roles.CLUSTER_HEAD, Roles.ROUTER, Roles.ROOT):
            if self.id not in JOIN_COMPLETE_TIMES:
                JOIN_COMPLETE_TIMES[self.id] = self.now
            self.kill_timer('TIMER_PROBE') # stop probing if we joined

        # if we just became cluster head, start routerable checks
        if new_role == Roles.CLUSTER_HEAD:
            self.set_timer('TIMER_ROUTERABLE_CHECK', config.ROUTERABLE_CHECK_INTERVAL)

        # start sensor timer for registered, cluster head, and router roles
        if new_role in (Roles.REGISTERED, Roles.CLUSTER_HEAD, Roles.ROUTER) and new_role != Roles.ROOT:
            self.kill_timer('TIMER_SENSOR')
            self.set_timer('TIMER_SENSOR', config.SENSOR_BASE_INTERVAL)

        # start/refresh heartbeat timer for all active roles
        if new_role in (Roles.REGISTERED, Roles.CLUSTER_HEAD, Roles.ROUTER, Roles.ROOT):
            self.send_heart_beat()
            self.kill_timer('TIMER_HEART_BEAT')
            self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)

        # clean up when becoming unregistered
        if new_role is Roles.UNREGISTERED:
            self.kill_timer('TIMER_SENSOR')
            self.kill_timer('TIMER_ROUTERABLE_CHECK')
            self.clear_tx_range()
            self.erase_parent()

        # keep parent visuals in sync with role changes
        # self.update_parent_visual()

    # Runs to become unregistered
    def become_unregistered(self, *, preserve_neighbors=False):
        self.kill_timer('TIMER_PROBE')
        old_parent = self.parent_address
        if self.role != Roles.UNDISCOVERED:
            self.kill_all_timers()
            if self.role != Roles.UNREGISTERED:
                self.log(f'{self.id} became UNREGISTERED')

        self.scene.nodecolor(self.id, 1, 1, 0)
        self.erase_parent()

        self.addr = None

        self.ch_addr = None

        self.parent_address = None
        self.parent_gui = None  # parent global unique id

        self.root_addr = None  # root address
        self.parent_set_time = self.now
        self.downstream_ch_addr = None
        self.downstream_ch_gui = None

        self.set_role(Roles.UNREGISTERED)
        self.c_probe = 0
        self.th_probe = len(config.NODE_TX_RANGES) * 6
        self.hop_count = 99999
        self.probes_sent = 0
        self.tx_power_level = 0
        self.tx_range = config.NODE_TX_RANGES[self.tx_power_level]
        self.pending_ch_promotion = None
        self.last_parent_check = 0
        self.last_join_target = None
        self.last_join_time = 0

        if not preserve_neighbors:
            self.neighbors_table = {}
            self.child_networks_table = {}
            self.members_table = {}

        self.received_JR_guis = [] # TODO see if we need to preserve this ???

        self.send_probe()
        next_try = config.TIMER_JOIN_REQ_INTERVAL + random.uniform(-1, 1)
        self.set_timer('TIMER_JOIN_REQ', next_try)
        # keep probing periodically until we find a parent
        self.set_timer('TIMER_PROBE', 1)

    # runs to snoop/update tables based on packet type
    def update_routing_info(self, pck):
        ptype = pck.get('type', None)  # packet type
        uid = pck.get('uid', None)
        child_addr = pck.get('child_addr', None)
        src_addr: wsn.Addr = pck.get('src_addr', None) # who sent the packet
        last_hop_addr = pck.get('last_router', None) # who we heard it from # TODO this might not be necessary
        hop_count = pck.get('hop_count', None) # hops to target
        arrival_time = pck.get('arrival_time', None)  # time we received the packet
        dist = pck.get('distance', None)  # distance to last hop sender
        role = pck.get('role', None) # sender role
        capabilities = pck.get('capabilities', None)
        path_cost = pck.get('path_cost', None)

        if ptype == 'HEART_BEAT':
            if hop_count is None or hop_count != 1:
                self.log(f"heartbeat with hop_count={hop_count}, expected 1")

            # here we are updating info about the sender
            entry: NeighborTableEntry | None = self.neighbors_table.get(src_addr)
            if entry is None:
                self.neighbors_table[src_addr] = NeighborTableEntry(
                    uid=uid,
                    nextHopAddr=src_addr,
                    hops=hop_count,
                    capabilities=capabilities,
                    role=role,
                    lastHeard=arrival_time, # time we last heard from this neighbor
                    rx_cost=dist, # distance to next hop node
                    path_cost=path_cost,
                    join_rejected_until=0
                )
            else:
                entry.uid = uid
                entry.nextHopAddr = src_addr
                entry.lastHeard = arrival_time
                entry.hops = hop_count
                entry.capabilities = capabilities
                entry.role = role
                entry.rx_cost = dist
                entry.path_cost = path_cost

            # update member info if we are cluster head or root and the sender is our member
            if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT) and self.ch_addr is not None \
                    and child_addr is not None and child_addr.net_addr == self.ch_addr.net_addr:
                member_entry: MemberTableEntry | None = self.members_table.get(child_addr, None)
                if member_entry is not None:
                    if member_entry.uid == uid:
                        member_entry.expiry_time = self.now + config.MEMBER_STALE_INTERVAL
                        member_entry.tx_power_level = self.get_tx_power_level_for_dist(dist)

                    else:
                        self.log(f"member uid changed for {child_addr} in CH {self.ch_addr}, was {member_entry.uid}, now {uid}"
                                 f"expiring old entry")
                        # uid changed, delete old entry
                        self.members_table.pop(child_addr, None)

                else:
                    self.log(f"heartbeat from non-member {child_addr} on CH {self.ch_addr} network")
                    self.send_join_nack(uid)

            # update child network info if the src addr is from a 254 address and it came from one of our children
            if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT) and self.ch_addr is not None \
                    and src_addr is not None and src_addr.net_addr != self.ch_addr.net_addr \
                    and child_addr is not None and child_addr.net_addr == self.ch_addr.net_addr \
                    and src_addr.node_addr == 254:
                child_entry: ChildNetworkEntry | None = self.child_networks_table.get(src_addr.net_addr, None)

                if child_entry is None:
                    self.log(f'no child network entry for {src_addr.net_addr} from HEART_BEAT, should have been created on netid response')
                    # TODO do something?
                else:
                    child_entry.next_hop_addr = child_addr
                    child_entry.hops = hop_count
                    child_entry.last_heard = self.now

                    # update requester uid if changed
                    if child_entry.requester_uid != uid:
                        self.log(f'child network {src_addr.net_addr} requester uid changed from {child_entry.requester_uid} to {uid}')
                        child_entry.requester_uid = uid

        elif ptype == 'NETID_REQ' and self.role is Roles.CLUSTER_HEAD:
            # if we are a cluster head, track last hop so when the response comes back we know where to send it
            target_uid = pck.get('target_uid', None)
            if target_uid is not None and src_addr is not None:
                self.log(f'Tracking NETID_REQ from target_uid {target_uid} via last hop {last_hop_addr}')
                self.pending_netid_last_hops.update({target_uid: last_hop_addr})
            else:
                self.log(f'NETID_REQ missing target_uid, cannot track last hop')
            pass

        elif ptype == 'NETID_RESP' and self.role is Roles.CLUSTER_HEAD:
            # snoop info from 'NETID_RESP' packet as a CH, root does its own handling when responding to the request
            promoted_to_ch_bool = pck.get('promoted_ch', False)
            target_uid = pck.get('target_uid', None)
            ch_addr = pck.get('ch_addr', None)
            new_child_net_addr = ch_addr.net_addr if ch_addr is not None else None
            reverse_hop_count = pck.get('reverse_hop_count', None)
            request_last_hop = self.pending_netid_last_hops.pop(target_uid, None)

            # check reverse hop count
            if reverse_hop_count is None:
                self.log(f'NETID_RESP missing reverse_hop_count')
                return
            pck['reverse_hop_count'] = max(0, reverse_hop_count - 1)

            # if promoted to CH, add/update child network entry
            if promoted_to_ch_bool is not None and promoted_to_ch_bool:
                if new_child_net_addr is None:
                    self.log(f'NETID_RESP missing ch_addr for promoted CH')
                    return

                if request_last_hop is None:
                    # TODO unsure what to do here, likely the NETID_REQ went a different route than the RESP
                    self.log(f'NETID_RESP missing last hop for requester uid {target_uid}')
                    return

                entry: ChildNetworkEntry | None = self.child_networks_table.get(new_child_net_addr, None)
                if entry is None:
                    self.child_networks_table[new_child_net_addr] = ChildNetworkEntry(
                        next_hop_addr=request_last_hop,
                        hops=reverse_hop_count,
                        net_state="VALID",
                        last_heard=arrival_time,
                        ack_seq_no=-1,  # no pending validation
                        requester_uid=target_uid
                    )
                    self.log(f'{self.ch_addr} added child network entry for {new_child_net_addr} from NETID_RESP')
                else:
                    self.log(f'{self.ch_addr} CH updated child network entry for new network addr: {new_child_net_addr} from NETID_RESP')
                    entry.next_hop_addr = request_last_hop
                    entry.hops = reverse_hop_count
                    entry.net_state = "VALID"
                    entry.last_heard = arrival_time
                    # update requester uid if changed
                    if entry.requester_uid != target_uid:
                        # TODO this probably shouldn't happen, log it
                        self.log(f'child network {new_child_net_addr} requester uid changed from {entry.requester_uid} to {target_uid}')
                        entry.requester_uid = target_uid

        # TODO update ROUTE_REQ and ROUTE_RESP handling
        # elif ptype == 'ROUTE_REQ':
        #     if last_hop_addr is None:
        #         return
        #
        #     entry = self.neighbors_table.get(last_hop_addr)
        #     if entry is None:
        #         self.neighbors_table[last_hop_addr] = NeighborTableEntry(
        #             uid=None, # we don't know uid of last hop
        #             nextHopAddr=last_hop_addr,
        #             hops=1,
        #             capabilities=None,
        #             role=pck.get('role', None),
        #             lastHeard=self.now,
        #             rx_cost=pck.get('distance', 999999),
        #             path_cost=None,
        #             join_rejected_until=0 # no need to preserve
        #         )
        #         self.log(f'Add neighbor entry for {last_hop_addr} from ROUTE_REQ')
        #     else:
        #         entry.lastHeard = self.now
        #         # Update cost if this path is better
        #         if pck.get('distance', 999999) < entry.rx_cost:
        #             entry.rx_cost = pck.get('distance')
        #         entry.upstream_addr = pck.get('upstream_addr', entry.upstream_addr)
        #
        # elif ptype == 'ROUTE_RESP':
        #     target_addr = pck.get('target_addr')
        #     last_hop_entry = self.neighbors_table.get(last_hop_addr)
        #     target_entry = self.neighbors_table.get(target_addr)
        #
        #     # ensure we have an entry for the last hop neighbor
        #     if last_hop_entry is None:
        #         self.neighbors_table[last_hop_addr] = NeighborTableEntry(
        #             uid=None, # we don't know uid of last hop
        #             nextHopAddr=last_hop_addr,
        #             hops=1,
        #             capabilities=None,
        #             role=pck.get('role', None),
        #             lastHeard=self.now,
        #             rx_cost=pck.get('distance', 999999),
        #             join_rejected_until=0
        #         )
        #         self.log(f'add neighbor entry for {last_hop_addr} from ROUTE_RESP')
        #     else:
        #         last_hop_entry.lastHeard = self.now
        #         last_hop_entry.rx_cost = pck.get('distance', last_hop_entry.rx_cost)
        #         last_hop_entry.upstream_addr = pck.get('upstream_addr', last_hop_entry.upstream_addr)
        #
        #     if target_addr is None:
        #         return
        #
        #     if target_entry is None:
        #         # new entry
        #         self.neighbors_table[target_addr] = NeighborTableEntry(
        #             uid=pck.get('target_uid', -1),
        #             nextHopAddr=last_hop_addr, # via this neighbor
        #             hops=hop_count,
        #             capabilities=pck.get('capabilities', None),
        #             role=pck.get('role', None),
        #             lastHeard=self.now,
        #             rx_cost=pck.get('distance', 999999),
        #             path_cost=pck.get('path_cost', None),
        #             join_rejected_until=0 # no need to preserve
        #         )
        #         self.log(f'Add neighbor entry for {target_addr} via {last_hop_addr} from ROUTE_RESP')
        #     else:
        #         # check criteria to update route:
        #         update_route = False
        #         # if lower hop count,
        #         if hop_count < target_entry.hops:
        #             update_route = True
        #         # if same hops and lower rx cost to next hop
        #         if (hop_count == target_entry.hops) and (pck.get('distance', 999999) < target_entry.rx_cost):
        #             update_route = True
        #         # if the next/last hop changed and the route is stale
        #         if target_entry.nextHopAddr != last_hop_addr:
        #             if (self.now - target_entry.lastHeard) > config.HEARTH_BEAT_TIME_INTERVAL * 3:
        #                 update_route = True
        #         # also if capabilities or roles changed, update
        #         if target_entry.capabilities != pck.get('capabilities', target_entry.capabilities):
        #             update_route = True
        #         if target_entry.knownRoles != pck.get('role_attributes', target_entry.knownRoles):
        #             update_route = True
        #         # if the target uid changed, update
        #         if target_entry.uid != pck.get('target_uid', target_entry.uid):
        #             update_route = True
        #
        #         # update if needed
        #         if update_route:
        #             target_entry.uid = pck.get('target_uid', target_entry.uid)
        #             target_entry.nextHopAddr = last_hop_addr
        #             target_entry.hops = hop_count
        #             target_entry.rx_cost = pck.get('distance', target_entry.rx_cost)
        #             target_entry.capabilities = pck.get('capabilities', target_entry.capabilities)
        #             target_entry.knownRoles = pck.get('role_attributes', target_entry.knownRoles)
        #             target_entry.lastHeard = self.now
        #             target_entry.path_cost = pck.get('path_cost', target_entry.path_cost)
        #             target_entry.upstream_addr = pck.get('upstream_addr', target_entry.upstream_addr)
        #             self.log(f'Updated neighbor entry for {target_addr} via {last_hop_addr} from ROUTE_RESP')
        #
        #         # clear pending discovery for this node if we had one
        #         self.pending_route_discovery.discard((target_addr.net_addr, target_addr.node_addr))

    # find best member to promote to cluster head
    def _find_ch_promotion_candidate(self):
        # if we are not a cluster head, we cannot promote anyone
        if self.role != Roles.CLUSTER_HEAD:
            self.log("_find_ch_promotion_candidate called when not CLUSTER_HEAD")
            return None

        best_addr = None
        best_score = -1

        # score every member by their rx_cost
        self.maintain_tables()
        for member_addr, member_entry in self.members_table.items():
            # find its neighbor entry
            n_entry = self.neighbors_table.get(member_addr, None)

            # for router push cost higher
            score = n_entry.rx_cost
            if score > best_score:
                best_score = score
                best_addr = member_addr

        return best_addr

    # select best candidate parent for an unregistered node to join
    def choose_join_candidate(self, require_cluster_head, allow_router=True):
        best_addr_local = None
        best_rx_strength_local = 999999

        for addr, entry in self.neighbors_table.items():
            # pass over missing entries or non-1-hop neighbors
            if entry is None or entry.hops != 1:
                continue

            # skip the ones that rejected us recently
            if entry.join_rejected_until and (self.now < entry.join_rejected_until):
                continue

            # if we see root, prefer it immediately
            if entry.role == Roles.ROOT:
                return addr, entry.rx_cost

            # only consider cluster heads if specified
            if require_cluster_head:
                role = entry.role
                if role is None or role != Roles.CLUSTER_HEAD:
                    continue

            # avoid routers unless explicitly allowed
            if not allow_router:
                role = entry.role
                if role is not None and role == Roles.ROUTER:
                    continue

            # TODO this should not matter, since that node should become unregistered first annyways
            # do not join a node that doesn't know how to reach the root
            if entry.path_cost is None:
                self.log(f'skipping join candidate {addr} with unknown path cost to root')
                continue

            # prefer nearest candidate
            if entry.rx_cost < best_rx_strength_local:
                best_rx_strength_local = entry.rx_cost
                best_addr_local = addr

            # prefer the best cost to root candidate
            # if entry.path_cost < best_rx_strength_local:
            #     best_rx_strength_local = entry.path_cost
            #     best_addr_local = addr

        return best_addr_local, best_rx_strength_local

    # mark neighbor rejected our join request
    def mark_join_rejected(self, neighbor_addr=None):
        if neighbor_addr is None:
            return

        if self.role != Roles.UNREGISTERED:
            self.log("mark_join_rejected called when not UNREGISTERED")
            return

        # find neighbor entry and set backoff time
        if neighbor_addr is not None:
            entry = self.neighbors_table.get(neighbor_addr, None)
            if entry is not None:
                entry.join_rejected_until = self.now + config.JOIN_REJECT_BACKOFF
                return

        # do not backoff by uid, address should be sufficient
        # if neighbor_uid is not None:
        #     # optional: backoff by uid when address unknown
        #     for addr, ent in self.neighbors_table.items():
        #         if getattr(ent, "uid", None) == neighbor_uid:
        #             ent.join_rejected_until = self.now + config.JOIN_REJECT_BACKOFF
        #             break

    # Runs on TIMER_JOIN_REQ fired, selects one of candidate parents and sends join request
    def select_and_join(self):
        if self.role != Roles.UNREGISTERED:
            self.log("select_and_join called when not UNREGISTERED")
            return

        self.maintain_tables()

        # prefer cluster heads first
        best_addr, best_rx_strength = self.choose_join_candidate(require_cluster_head=True)

        # if none, try any registered node
        if best_addr is None:
            best_addr, best_rx_strength = self.choose_join_candidate(require_cluster_head=False, allow_router=False)

        # if still none, try routers
        if best_addr is None:
            best_addr, best_rx_strength = self.choose_join_candidate(require_cluster_head=False, allow_router=True)

        # if we found a candidate, send join request
        if best_addr is not None:
            self.log(f'best join candidate at uid {self.id}: {best_addr} with rx_strength={best_rx_strength},'
                     f'best candidate is a {self.get_neighbor_role(best_addr)}')
            self.send_join_req(best_addr)
        else:
            # otherwise send another probe
            self.send_probe()

        self.set_timer('TIMER_JOIN_REQ', config.TIMER_JOIN_REQ_INTERVAL)

    # runs after become_unregistered broadcast probe message
    def send_probe(self):
        if self.role not in (Roles.UNDISCOVERED, Roles.UNREGISTERED):
            self.log("send_probe called when not UNDISCOVERED/UNREGISTERED")
            return

        pck = self.build_common_packet(p_type='NULL', ack=False, dst_addr=wsn.BROADCAST_ADDR)

        if (self.probes_sent % 6) < 2:
            # first 2 probes look for cluster heads
            pck.update({'type': 'PROBE_CH'})
        elif (self.probes_sent % 6) < 4:
            # next 2 probes look for cluster members
            pck.update({'type': 'PROBE_CM'})
        else:
            # final 2 probes look for routers
            pck.update({'type': 'PROBE_ROUTER'})

        self.send(pck, tx_level=(len(config.NODE_TX_RANGES) - 1)) # send at max power
        self.probes_sent += 1

    # broadcast HEART_BEAT packet
    def send_heart_beat(self):
        # ensure path cost is fresh before advertising
        self.compute_path_cost()
        pck = self.build_common_packet(p_type='HEART_BEAT', ack=False, dst_addr=wsn.BROADCAST_ADDR,
                                       add_roles=True, add_capabilities=True)

        # include our child address if we have one
        if self.addr is not None:
            pck['child_addr'] = self.addr

        # include our path cost to root
        pck['path_cost'] = self.path_cost
        pck.update({'uid': self.id}) # do we need uid??
        self.send(pck)

    # send JOIN_REQ packet to given dst
    def send_join_req(self, dest):
        if self.role != Roles.UNREGISTERED:
            self.log("send_join_req called when not UNREGISTERED")
            return

        # send a join request to given dst_addr
        pck = self.build_common_packet(p_type='JOIN_REQ', ack=False, dst_addr=dest,
                                       add_roles=True, add_capabilities=True)
        pck.update({'uid': self.id}) # add our uid so CH can identify us
        self.log(f'tx JOIN_REQ to {dest} from uid={self.id}')
        self.last_join_target = dest
        self.last_join_time = self.now
        self.send(pck)

    # maintain neighbor/member/child network tables
    def maintain_tables(self):
        # neighbor table cleanup
        for n_addr, n_entry in list(self.neighbors_table.items()):
            if n_entry is None:
                self.neighbors_table.pop(n_addr, None)
                continue
            age = self.now - n_entry.lastHeard if n_entry.lastHeard is not None else None
            if age is not None and age > config.MEMBER_STALE_INTERVAL:
                self.neighbors_table.pop(n_addr, None)

        # if not root or unregistered, check the neighbor table for our parent and become unregistered if missing
        if self.role is not Roles.ROOT and self.role is not Roles.UNREGISTERED and \
                self.parent_address is not None and self.parent_gui is not None:
            parent_entry: NeighborTableEntry | None = self.neighbors_table.get(self.parent_address, None)
            # if parent was pruned, become unregistered
            if parent_entry is None:
                self.log(f'parent {self.parent_address} missing, becoming UNREGISTERED')
                self.become_unregistered()
                return
            # if parent uid is known, verify it matches
            if self.parent_gui is not None and parent_entry.uid is not None:
                # if parent uid changed, become unregistered
                if parent_entry.uid != self.parent_gui:
                    self.log(f'parent uid changed from {self.parent_gui} to {parent_entry.uid}, becoming UNREGISTERED')
                    self.become_unregistered()
                    return

        # if there is a better neighbor than our parent, become unregistered
        if self.role == Roles.REGISTERED:
            if self.parent_address is not None:
                parent_entry: NeighborTableEntry | None = self.neighbors_table.get(self.parent_address, None)
                if parent_entry is not None and parent_entry.path_cost is not None:
                    best_addr = self.choose_join_candidate(require_cluster_head=False, allow_router=False)
                    if best_addr is not None:
                        if best_addr != self.parent_address:
                            best_entry: NeighborTableEntry | None = self.neighbors_table.get(best_addr, None)
                            if best_entry is not None:
                                self.log(f'found better parent candidate {best_addr}')
                                self.become_unregistered()
                                return


        # if we are router and our downstream neighbor is missing, become unregistered
        if self.role is Roles.ROUTER:
            if self.downstream_ch_addr is not None and self.downstream_ch_gui is not None:
                downstream_entry: NeighborTableEntry | None = self.neighbors_table.get(self.downstream_ch_addr, None)
                if downstream_entry is None:
                    self.log(f'downstream cluster head {self.downstream_ch_addr} missing, becoming UNREGISTERED')
                    self.become_unregistered()
                    return
                # if downstream uid is known, verify it matches
                if self.downstream_ch_gui is not None and downstream_entry.uid is not None:
                    # if downstream uid changed, become unregistered
                    if downstream_entry.uid != self.downstream_ch_gui:
                        self.log(f'downstream cluster head uid changed from {self.downstream_ch_gui} to {downstream_entry.uid}, becoming UNREGISTERED')
                        self.become_unregistered()
                        return
            else:
                self.log(f'ROUTER has no downstream cluster head address set, becoming UNREGISTERED')
                self.become_unregistered()
                return

        # member/child network cleanup for CH/root
        if self.role is Roles.CLUSTER_HEAD or self.role is Roles.ROOT:
            # cleanup members table
            for member_addr, member_entry in list(self.members_table.items()):
                if member_entry is None:
                    self.members_table.pop(member_addr, None)
                    continue
                # remove expired members
                if member_entry is not None and self.now >= member_entry.expiry_time:
                    self.members_table.pop(member_addr, None)
                    continue
                # remove members with different net_addr than our ch_addr (ie. if our ch_addr changed)
                if self.ch_addr is not None and member_addr.net_addr != self.ch_addr.net_addr:
                    self.members_table.pop(member_addr, None)
                    continue
                # same for root
                if self.root_addr is not None and member_addr.net_addr != self.root_addr.net_addr:
                    self.members_table.pop(member_addr, None)
                    continue

            # TODO this may be too much, we need to inspect every packet to keep last_heard fresh
            # cleanup child networks table
            for net_id, entry in list(self.child_networks_table.items()):
                if entry is None:
                    self.child_networks_table.pop(net_id, None)
                    continue

                # remove child networks if expired and still pending
                age = self.now - entry.last_heard if entry.last_heard is not None else None
                if age is not None and age > config.PARENT_STALE_INTERVAL and entry.net_state != "VALID":
                    self.child_networks_table.pop(net_id, None)

    # get next free node address
    def get_next_free_node_addr(self, candidate_uid=None):
        # only cluster heads can assign node addresses
        if self.role not in (Roles.CLUSTER_HEAD, Roles.ROOT) or self.ch_addr is None:
            self.log("get_next_free_node_addr called when not CLUSTER_HEAD or ROOT")
            return None

        # first check if candidate uid already has an address, return it if so
        if candidate_uid is not None:
            for member_addr, member_entry in self.members_table.items():
                if member_entry is not None and member_entry.uid == candidate_uid:
                    self.log(f'found existing address {member_addr} for uid={candidate_uid}')
                    return member_addr.node_addr

        # collect used node addresses
        used_node_addrs = set()
        for member_addr in self.members_table.keys():
            if member_addr is not None:
                used_node_addrs.add(member_addr.node_addr)

        # find next free node address:
        for node_addr in range(1, config.SIM_MAX_CHILDREN): # 1..config.SIM_MAX_CHILDREN-1
            if node_addr not in used_node_addrs:
                return node_addr

        self.log(f'no free node addresses available in cluster head network {self.ch_addr}')
        return None

    # get next free network address
    def get_next_free_network_addr(self):
        # only root can assign network addresses
        if self.role != Roles.ROOT:
            self.log("get_next_free_network_addr called when not ROOT")
            return None

        # collect used network addresses
        used_net_addrs = set()
        for used_net_addr in self.child_networks_table.keys():
            used_net_addrs.add(used_net_addr)

        # find next free network address (1 is reserved for root):
        for net_addr in range(2, config.SIM_MAX_NETWORKS + 2):
            if net_addr not in used_net_addrs:
                return net_addr

        return None

    # tell a node to leave by sending JOIN_NACK
    def send_join_nack(self, candidate_uid):
        pck = self.build_common_packet(p_type='JOIN_ACK', ack=False, dst_addr=wsn.BROADCAST_ADDR)
        pck.update({
            'uid': self.id,
            'target_uid': candidate_uid,
            'promoted_reg': False,
            'cm_addr': None,
            'time_addr_valid': 0
        })
        self.send(pck)


    # send JOIN_ACK packet to requesting node, rcv_pck is the received JOIN_REQ packet
    def send_join_ack(self, rcv_pck):
        candidate_uid = rcv_pck.get('uid', None) # uid of requesting node
        candidate_dist = rcv_pck.get('distance', 99999999) # distance to requesting node

        if candidate_uid is None:
            self.log('join request denied (missing candidate uid)')
            return

        # only cluster heads and root can grant joins
        if self.role not in (Roles.CLUSTER_HEAD, Roles.ROOT) or self.ch_addr is None:
            pck = self.build_common_packet(p_type='JOIN_ACK', ack=False, dst_addr=wsn.BROADCAST_ADDR)
            pck.update({
                'uid': self.id,
                'target_uid': candidate_uid,
                'promoted_reg': False,
                'cm_addr': None,
                'time_addr_valid': 0
            })
            self.log(f'JOIN_ACK denied uid={candidate_uid} (not a cluster head)')
            self.send(pck)
            return

        pck = self.build_common_packet(p_type='JOIN_ACK', ack=True, dst_addr=wsn.BROADCAST_ADDR)
        pck.update({'target_uid': candidate_uid}) # target the requesting uid
        pck.update({'uid': self.id}) # add our uid

        # get next free node address
        next_free_node_addr = self.get_next_free_node_addr(candidate_uid)

        # if no free slots, deny join
        if next_free_node_addr is None:
            pck.update({'promoted_reg': False})
            pck.update({'cm_addr': None})
            pck.update({'time_addr_valid': 0})
            self.log(f'JOIN_ACK denied uid={candidate_uid} (no free slots)')
            self.send(pck)
            return

        # assign new address
        new_addr = wsn.Addr(self.ch_addr.net_addr, next_free_node_addr)
        pck.update({'promoted_reg': True}) # indicate the node will be promoted to registered
        pck.update({'cm_addr': new_addr}) # newly assigned cluster member address
        pck.update({'time_addr_valid': self.now + config.MEMBER_STALE_INTERVAL}) # addr valid till when?

        # check if we already have this member
        for member_addr, member_entry in self.members_table.items():
            if member_entry is not None and member_entry.uid == candidate_uid:
                self.log(f'JOIN_ACK granted existing uid={candidate_uid}, addr={member_addr}')
                seq_no = self.send(pck, tx_level=self.get_tx_power_level_for_dist(candidate_dist))

                # update existing member entry
                member_entry.expiry_time = self.now + config.MEMBER_STALE_INTERVAL
                member_entry.tx_power_level = self.get_tx_power_level_for_dist(candidate_dist)
                member_entry.renewal_valid = False
                if seq_no is not None:
                    member_entry.ack_seq_no = seq_no
                else:
                    member_entry.ack_seq_no = -1
                return

        # otherwise, add new member entry
        member_entry = MemberTableEntry(
            uid=candidate_uid, renewal_valid=False, ack_seq_no=-1,
            expiry_time=self.now + config.MEMBER_STALE_INTERVAL,
            tx_power_level=self.get_tx_power_level_for_dist(candidate_dist)
        )
        self.members_table[new_addr] = member_entry

        # send and save seq_no for ack
        seq_no = self.send(pck, tx_level=self.get_tx_power_level_for_dist(candidate_dist))
        if seq_no is not None:
            member_entry.ack_seq_no = seq_no
        else:
            member_entry.ack_seq_no = -1

        self.log(f'JOIN_ACK granted uid={candidate_uid}, addr={new_addr}, seq={seq_no}')
        return

    # send ACK packet to dest for given sequence number
    def send_ack(self, dest, seq_no, ack_type="NULL"):
        pck = self.build_common_packet(p_type='ACK', ack=False, dst_addr=dest)
        pck.update({'ack_seq_no': seq_no})
        pck.update({'ack_type': ack_type})
        self.route_and_forward_package(pck)

    # N-HOP routing
    def send_route_request(self, target_addr):
        self.broadcast_id += 1
        pck = self.build_common_packet(p_type='ROUTE_REQ', ack=False, dst_addr=wsn.BROADCAST_ADDR)

        pck.update({
            'rreq_id': self.broadcast_id, # broadcast id
            'target_addr': target_addr,  # target
        })

        # we have seen our own rreq
        self.rreq_seen.add((self.addr, self.broadcast_id))

        self.log(f'broadcasting ROUTE_REQ for {target_addr}')
        self.send(pck)

    # start route discovery process for target address
    def start_route_discovery(self, target_addr):
        # ensure we have a target and it's not broadcast
        if target_addr is None or target_addr == wsn.BROADCAST_ADDR:
            return
        # ensure we are registered and have an address
        if self.role is Roles.UNREGISTERED or self.role is Roles.UNDISCOVERED:
            return
        if self.addr is None or self.ch_addr is None:
            return

        # check if we already have a pending discovery for this target
        key = (target_addr.net_addr, target_addr.node_addr)
        if key in self.pending_route_discovery:
            return
        self.pending_route_discovery.add(key)
        self.send_route_request(target_addr)

    # send route reply from target to requester
    def send_route_reply(self, requester_addr):
        pck = self.build_common_packet(p_type='ROUTE_RESP', ack=False, dst_addr=requester_addr,
                                       add_capabilities=True, add_roles=True)

        pck.update({
            'target_addr': self.addr, # send our address as target
            'target_uid': self.id, # our uid
        })

        self.log(f'send ROUTE_RESP to {requester_addr} from target {self.addr}')
        self.route_and_forward_package(pck)

    # route and forward given packet
    def route_and_forward_package(self, pck, use_mesh=True, use_tree=True):
        dst: wsn.Addr = pck.get('dst_addr')
        dst_parent_addr: wsn.Addr = None
        prev_hop = pck.get('last_router')
        self_parent_entry = self.neighbors_table.get(self.parent_address) if self.parent_address is not None else None

        # if broadcast, send directly
        if dst == wsn.BROADCAST_ADDR:
            return self.send(pck)

        # if the packet has an explicit next hop, use it and bypass routing
        explicit_next_hop = pck.get('next_hop_addr')
        if explicit_next_hop is not None:
            if explicit_next_hop in (self.addr, self.ch_addr, self.root_addr):
                pck['next_hop_addr'] = None
            else:
                # explicit next hop provided, use it
                self.log(f'using explicit next hop {explicit_next_hop} for dst={dst}')
                self.send(pck)

        # calculate dst parent address
        if dst.node_addr != 254:
            dst_parent_addr = wsn.Addr(dst.net_addr, 254)

        #
        # Mesh Rules:
        #
        if use_mesh and pck['type'] not in ('NETID_REQ', 'NETID_RESP', 'JOIN_REQ', 'JOIN_ACK', 'CH_PROMOTE'):
            entry: NeighborTableEntry = self.neighbors_table.get(dst)
            parent_entry: NeighborTableEntry = self.neighbors_table.get(dst_parent_addr)

            # if destination is in our neighbor table, send to destination
            if entry is not None:
                nh = entry.nextHopAddr
                if nh is not None:
                    pck['next_hop_addr'] = nh
                    return self.send(pck)

            # if destination<-parent is in our neighbor table, send to parent
            if parent_entry is not None:
                nh = parent_entry.nextHopAddr
                if nh is not None:
                    pck['next_hop_addr'] = nh
                    return self.send(pck)

        # no mesh route known so start discovery (but not for route discovery packets themselves)
        # if pck.get('type') not in ('ROUTE_REQ', 'ROUTE_RESP'):
        #     self.start_route_discovery(dst)

        #
        # Tree Rules
        #
        if use_tree:
            if self.role == Roles.ROUTER:
                upstream = self.parent_address
                downstream = self.downstream_ch_addr

                # if no link, send to upstream if we have it
                if downstream is None:
                    self.log(f'error ROUTER no downstream, sending to upstream {upstream} for dst={dst}')
                    if upstream is not None and prev_hop != upstream:
                        pck['next_hop_addr'] = upstream
                        return self.send(pck)
                    return -1

                # if from parent, send to downstream
                if prev_hop == upstream:
                    # self.log(f'ROUTER sending to downstream {downstream} for dst={dst}')
                    pck['next_hop_addr'] = downstream
                    return self.send(pck)

                # otherwise send to upstream
                else:
                    # self.log(f'ROUTER sending to upstream {upstream} for dst={dst}')
                    pck['next_hop_addr'] = upstream
                    return self.send(pck)

            # if we are a cluster head/root:
            if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT):
                # if destination is part of our network, send to child
                if self.ch_addr is not None and dst.net_addr == self.ch_addr.net_addr:
                    pck['next_hop_addr'] = dst
                    return self.send(pck)
                # if the destination network id is in one of our child networks, send to that next hop
                elif self.child_networks_table:
                    child_net_entry: ChildNetworkEntry = self.child_networks_table.get(dst.net_addr)
                    if child_net_entry is not None:
                        pck['next_hop_addr'] = child_net_entry.next_hop_addr
                        return self.send(pck)

            # otherwise if we are not root, send up the tree to our parent
            if self.role != Roles.ROOT and self.parent_address is not None:
                nh = self.parent_address
                if self_parent_entry is not None and self_parent_entry.nextHopAddr is not None:
                    nh = self_parent_entry.nextHopAddr
                if nh == prev_hop:
                    self.log(f'[LOOP] tree parent nh={nh} equals prev_hop for dst={dst} at node {self.id}')
                    return -1
                pck['next_hop_addr'] = nh
                return self.send(pck)

        # if we are root and we reach here, theoretically should not happen
        parent_entry = self.neighbors_table.get(self.parent_address)
        self.log(
            f'no route to destination {dst} from node {self.id} '
            f'role={self.role.name} parent={self.parent_address} prev_hop={prev_hop} '
            f'neighbors={list(self.neighbors_table.keys())}'
        )
        if parent_entry is not None:
            self.log(
                f'parent_entry: nextHop={parent_entry.nextHopAddr} hops={parent_entry.hops} '
                f'lastHeard={parent_entry.lastHeard} rx_cost={parent_entry.rx_cost}'
            )
        if self.child_networks_table:
            self.log(f'child_networks={ {k: v.next_hop_addr for k, v in self.child_networks_table.items()} }')
        if self.members_table:
            self.log(f'members={list(self.members_table.keys())}')
        return -1

    # send NETID_REQ packet to root
    def send_network_req(self):
        if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT):
            self.log("send_network_req called when CLUSTER_HEAD or ROOT")
            return

        pck = self.build_common_packet(p_type='NETID_REQ', ack=False, dst_addr=wsn.Addr(1, 254))
        pck.update({'target_uid': self.id})
        self.log(f'NETID_REQ tx uid={self.id} src_addr={self.addr} dst={pck["dst_addr"]}')
        self.route_and_forward_package(pck)

    # send NETID_RESP packet to requesting node from root
    def send_network_resp(self, req_pck):
        cm_dest = req_pck['src_addr']  # cluster member dst
        cm_uid = req_pck['target_uid']  # cluster member uid
        last_router = req_pck.get('last_router')
        req_hops = req_pck.get('hop_count', None)

        # only root can respond to network id requests
        if self.role is not Roles.ROOT:
            self.log("send_network_resp called when not ROOT")
            return

        pck = self.build_common_packet(
            p_type='NETID_RESP',
            ack=True,
            dst_addr=cm_dest
        )
        pck.update({'target_uid': cm_uid})  # target node uid

        # check for duplicate request from same uid
        existing_net_id = None
        existing_entry = None
        for net_id, entry in self.child_networks_table.items():
            if entry is None:
                continue
            if entry.requester_uid == cm_uid:  # duplicate request
                existing_net_id = net_id
                existing_entry = entry
                self.log(f'found existing network id {existing_net_id} for uid={cm_uid}, reusing it')
                break

        # get next free / existing network address
        if existing_net_id is not None:
            next_free_net_addr = existing_net_id

            # update existing entry instead of overwriting it later
            if existing_entry:
                # if last router changed, update it
                if last_router is not None and existing_entry.next_hop_addr != last_router:
                    existing_entry.next_hop_addr = last_router

                # update hop count and last heard
                if req_hops is not None:
                    existing_entry.hops = req_hops
                existing_entry.last_heard = self.now
        else:
            next_free_net_addr = self.get_next_free_network_addr()

        # if no free networks, deny request
        if next_free_net_addr is None:
            self.log('no free networks')
            pck.update({'promoted_ch': False})
            pck.update({'ch_addr': None})
        else:
            # network exists or new one was just allocated
            ch_addr = wsn.Addr(next_free_net_addr, 254)
            pck.update({'promoted_ch': True})
            pck.update({'ch_addr': ch_addr})

            # only create a new entry if this is a brand-new network id
            if existing_net_id is None:
                new_entry = ChildNetworkEntry(
                    next_hop_addr=last_router,  # route downstream via last router
                    hops=req_hops if req_hops is not None else 0,
                    net_state="PENDING",
                    last_heard=self.now,
                    ack_seq_no=-1,  # will be filled after send
                    requester_uid=cm_uid,
                )
                self.child_networks_table[next_free_net_addr] = new_entry

        # use last router as explicit next hop:
        if last_router is not None:
            pck['next_hop_addr'] = last_router
        else:
            # if we don't know, try routing via table
            pck['next_hop_addr'] = None

        # include reverse hop count:
        if req_hops is not None:
            pck.update({'reverse_hop_count': req_hops})
        else:
            self.log('NETID_REQ missing hop_count')

        pck.update({'use_mesh': False})
        pck.update({'use_tree': True})

        seq_no = self.route_and_forward_package(pck, use_mesh=False, use_tree=True)

        # if success, record the seq_no for ACK to table
        if next_free_net_addr is not None and next_free_net_addr in self.child_networks_table and seq_no is not None:
            self.child_networks_table[next_free_net_addr].ack_seq_no = seq_no

        self.log(
            f'NETID_RESP {"granted" if next_free_net_addr else "denied"} uid={cm_uid},'
            f' net={next_free_net_addr}, ch_addr={pck.get("ch_addr")}, seq={seq_no},'
            f' dst={cm_dest}, last_router={req_pck.get("last_router")}'
        )
        return

    # handle CH_PROMOTE packet received
    def handle_ch_promote_request(self, pck):
        # must have a member address to be promoted
        target_addr = pck.get('dst_addr', None)
        ch_addr = pck.get('ch_addr', None)
        new_parent_addr = pck.get('new_parent', None)
        parent_uid = pck.get('uid', None)  # promoter uid
        req_seq_no = pck.get('seq_no', None)

        # we cannot be promoted unless we are a cluster member
        if self.role != Roles.REGISTERED or self.addr is None:
            self.log('CH_PROMOTE request ignored (not cluster member)')
            return

        # check if we are the target
        if self.addr is None or target_addr is None or self.addr != target_addr:
            self.log('CH_PROMOTE request ignored (not target member)')
            return

        # verify parent uid matches
        if self.parent_gui is not None and self.parent_gui != parent_uid:
            self.log('CH_PROMOTE request ignored (parent uid mismatch)?????')
            return

        if new_parent_addr is None:
            self.log('CH_PROMOTE request denied (missing new parent)')
            return

        # if any of our members are routers, we cannot be promoted
        for member_addr in self.members_table.keys():
            role = self.get_neighbor_role(member_addr)
            if role == Roles.ROUTER:
                self.log('CH_PROMOTE request denied (child is router)')
                return

        # clear address, take new cluster head address, become cluster head
        # parent address becomes new_parent_addr
        old_addr = self.addr
        self.addr = None
        self.ch_addr = ch_addr
        self.parent_address = new_parent_addr
        self.parent_gui = parent_uid

        # transfer old parent entry to new parent address and delete old entry
        old_parent_entry = self.neighbors_table.get(ch_addr, None)
        if old_parent_entry is not None:
            self.neighbors_table[self.parent_address] = old_parent_entry
            self.neighbors_table.pop(ch_addr, None)

        self.draw_parent()
        self.set_role(Roles.CLUSTER_HEAD)
        self.send_heart_beat()
        self.kill_timer('TIMER_HEART_BEAT')
        self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)

        # send back direct ACK to promoter
        ack = self.build_common_packet(p_type='ACK', ack=False, dst_addr=self.parent_address)
        ack.update({'src_addr': old_addr})
        ack.update({'uid': self.id})
        ack.update({'next_hop_addr': self.parent_address})
        ack.update({'ack_seq_no': req_seq_no, 'ack_type': 'CH_PROMOTE'})
        self.log(f"CH_PROMOTE ACK tx to {self.parent_address} for seq={req_seq_no}")
        self.send(ack, tx_level=self.get_tx_power_level_for_dist(ack.get('distance', None)))

    # handle CH_PROMOTE ACK packet received
    def handle_ch_promote_ack(self, pck):
        if self.role != Roles.CLUSTER_HEAD:
            self.log('CH_PROMOTE ACK ignored (not cluster head)')
            return

        if self.pending_ch_promotion is None:
            self.log('CH_PROMOTE ACK ignored (no pending promotion)')
            return

        # TODO verify ack_seq_no matches pending promotion
        rcv_seq_no = pck.get('ack_seq_no', None)
        target_addr = self.pending_ch_promotion.get('target_addr', None)
        post_role = self.pending_ch_promotion.get('post_role', 'router')

        if post_role == 'router':
            self.pending_ch_promotion = None
            self.set_role(Roles.ROUTER)
            self.downstream_ch_addr = self.ch_addr # save downstream cluster head address
            self.downstream_ch_gui = pck.get('uid', None)
            self.ch_addr = None
            self.members_table = {}
            self.child_networks_table = {}
            self.send_heart_beat()
        else:
            self.log(f'CH_PROMOTE complete {target_addr} to CH, demoting to rejoin network')
            # clear cluster-head specific state and rejoin as a member
            self.members_table = {}
            self.child_networks_table = {}
            self.ch_addr = None
            self.addr = None
            self.become_unregistered(preserve_neighbors=True)

    # find suitable candidate for cluster head promotion and run it
    def attempt_member_promotion(self, post_role='router'):
        # only cluster heads can promote members
        if self.role != Roles.CLUSTER_HEAD or self.ch_addr is None:
            self.log('not a CH cannot promote member')
            return
        # make sure no promotion is in progress
        if self.pending_ch_promotion:
            # check if it has timed out
            time_elapsed = self.now - self.pending_ch_promotion.get('time_started', 0 )
            if time_elapsed > config.CH_PROMOTE_TIMEOUT:
                self.log('ch promotion timed out, clearing pending state')
                self.pending_ch_promotion = None
            else:
                self.log('ch promotion already pending')
            return
        # cannot promote if parent is a router
        if self.get_neighbor_role(self.parent_address) == Roles.ROUTER:
            # self.log('parent is router, we cannot promote to ROUTER')
            return

        # cannot promote if any of our members are routers
        for member_addr in self.members_table.keys():
            role = self.get_neighbor_role(member_addr)
            if role == Roles.ROUTER:
                self.log('child is router, cannot promote member')
                return

        # find suitable candidate
        candidate_addr = self._find_ch_promotion_candidate()
        if candidate_addr is None:
            self.log('no suitable candidate found for CH promotion')
            return
        self.log(f'promoting member at address {candidate_addr} to cluster head')

        # send CH_PROMOTE packet
        pck = self.build_common_packet(p_type='CH_PROMOTE', ack=True, dst_addr=candidate_addr)
        pck.update({'uid': self.id})
        pck.update({'new_parent': self.addr}) # give our child address as new parent for promoted node
        pck.update({'ch_addr': self.ch_addr}) # the new cluster head address
        self.log(f'CH_PROMOTE tx uid={self.id} src_addr={self.addr} dst={pck["dst_addr"]}')
        seq_no = self.send(pck)

        # record pending promotion
        if seq_no is not None:
            self.pending_ch_promotion = {
                'seq_no': seq_no,
                'target_addr': candidate_addr,
                'post_role': post_role,
                'time_started': self.now
            }
            self.log(f'started CH_PROMOTE to {candidate_addr} seq={seq_no} post={post_role}')

    # rx handler
    def on_receive(self, pck):
        # don't process if dead
        if not self.is_alive:
            return

        # update battery on rx
        self.battery_mj -= (_estimate_packet_size_bytes(pck) * config.RX_ENERGY_PER_BYTE_UJ) / 1000.0
        if self.battery_mj <= config.MIN_BATTERY_MJ:
            self.is_alive = False
            return

        pck = pck.copy()  # shallow copy
        pck['arrival_time'] = self.now  # add arrival time to the received packet

        # compute Euclidean distance between self and neighbor, used as rx_cost
        sender_uid = pck.get('last_tx_uid', pck.get('uid'))
        if sender_uid in NODE_POS and self.id in NODE_POS:
            x1, y1 = NODE_POS[self.id]
            x2, y2 = NODE_POS[sender_uid]
            pck['distance'] = math.hypot(x1 - x2, y1 - y2)

        # check if we even need to process this packet
        if self._should_drop_packet(pck):
            self.log(f'dropping packet {pck}')
            return

        # trace path if we didn't drop it
        if config.TRACE_PATHS:
            pck.get('path', []).append(self.id)

        # snoop for NETID_REQ/RESP to update routing info
        if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT, Roles.ROUTER) and pck.get('type') in ('NETID_REQ', 'NETID_RESP', 'ROUTE_REQ', 'ROUTE_RESP'):
            self.update_routing_info(pck)

        # if packet is not for us, route and forward
        if not self._is_packet_at_destination(pck):
            if pck['type'] != 'DATA' and pck['type'] != 'SENSOR':
                # self.log(f"forwarding network packet {pck}")
                None
            self.route_and_forward_package(pck)
            return

        logged_delivery = False

        # helper to log delivery if at final dest
        def log_delivery():
            nonlocal logged_delivery
            if self._is_packet_at_destination(pck) and not logged_delivery and pck['type'] != 'HEART_BEAT' \
                    and pck['type'] != 'PROBE_CH' and pck['type'] != 'PROBE_CM' and pck['type'] != 'PROBE_ROUTER':
                self.record_packet_delivery(pck, trace_decision=True)
                logged_delivery = True


        # aodv type flood request handler
        # if pck['type'] == 'ROUTE_REQ':
        #     rreq_id = pck['rreq_id'] # unique id for this rreq
        #
        #     # drop duplicates
        #     if (pck['src_addr'], rreq_id) in self.rreq_seen:
        #         return
        #
        #     self.rreq_seen.add((pck['src_addr'], rreq_id)) # (src_addr, rreq_id) seen
        #     # learn route back to requester (src_addr), not target
        #     learn_pck = pck.copy()
        #     learn_pck['target_addr'] = pck['src_addr']
        #     self.update_routing_info(learn_pck)
        #
        #     # if we are the target, send reply
        #     if self.addr is not None and pck.get('target_addr') is not None and pck.get('target_addr') == self.addr:
        #         self.send_route_reply(requester_addr=pck['src_addr'], target_addr=self.addr, hops_from_us=0)
        #     else:
        #         # otherwise, if hop count exceeded, or we have no address, drop request
        #         if pck['hop_count'] >= 2 or self.addr is None:
        #             return
        #
        #         # TODO here we should check if we have a route to target and reply if so
        #         # else, broadcast request with incremented hop count
        #         forward_pck = pck.copy()
        #         forward_pck['hop_count'] += 1
        #         forward_pck['last_router'] = self.addr
        #         # do NOT change src_addr
        #         self.send(forward_pck)
        #     return
        #
        # if pck['type'] == 'ROUTE_RESP':
        #     # learn route to target
        #     self.update_routing_info(pck.copy())
        #
        #     # if we are the destination, route complete
        #     if self.addr is not None and pck.get('dst_addr') == self.addr:
        #         self.log(f"Route found to {pck['src_addr']}.")
        #     else:
        #         self.route_and_forward_package(pck)
        #     return


        # Root or cluster head cases
        if self.role in (Roles.ROOT, Roles.CLUSTER_HEAD):
            if pck['type'] == 'HEART_BEAT':
                self.update_routing_info(pck) # updates neighbor table with received heart beat message
                log_delivery()
                return
            elif pck['type'] == 'PROBE_CH':
                self.send_heart_beat() # if we get a probe as root or cluster head, respond with heart beat
                log_delivery()
                return
            elif pck['type'] == 'JOIN_REQ':
                self.log(f'JOIN_REQ rx at {self.role.name} uid={pck.get("uid")}, src_addr={pck.get("src_addr")}')
                self.send_join_ack(pck) # send join response to the candidate
                log_delivery()
                return
            elif pck['type'] == 'ACK':
                # handle ACK packets
                if pck.get('ack_type') == 'CH_PROMOTE':
                    self.handle_ch_promote_ack(pck)
                    log_delivery()
                    return

                # validate member table entry when we receive ACK for JOIN_ACK
                member = self.members_table.get(pck['src_addr'])
                if member is not None and member.ack_seq_no == pck['ack_seq_no']:
                    self.log(f'JOIN_ACK ACK received for uid={member.uid}, addr={pck["src_addr"]}, seq={pck["ack_seq_no"]}')
                    member.renewal_valid = True
                    member.expiry_time = self.now + config.MEMBER_STALE_INTERVAL

                    # make routers as we go
                    if self.role == Roles.CLUSTER_HEAD:
                        self.attempt_member_promotion(post_role='router')

                    log_delivery()
                    return

                # validate child network entry when we receive ACK for NETID_RESP
                for net_id, entry in self.child_networks_table.items():
                    if entry.ack_seq_no == pck['ack_seq_no']:
                        self.log(f'NETID_RESP ACK received for net={net_id}, seq={pck["ack_seq_no"]}')
                        entry.net_state = "VALID" # net valid
                        entry.last_heard = self.now
                        log_delivery()
                        return
                log_delivery()
                return

            elif pck['type'] == 'NETID_REQ':  # it sends a network reply to requested node
                if self.role == Roles.ROOT:
                    self.log(f'NETID_REQ rx at root uid={pck.get("target_uid")}, src_addr={pck.get("src_addr")},'
                             f' last_router={pck.get("last_router")}, hop_count={pck.get("hop_count")}')
                    self.send_network_resp(pck)
                log_delivery()
                return

            elif pck['type'] in ('SENSOR', 'DATA'):
                if self.role == Roles.ROOT:
                    # self.log(f'DATA rx from uid={pck.get("uid")}, src_addr={pck.get("src_addr")}, sensor_value={pck.get("sensor_value")}')
                    None
                log_delivery()
                return

        # router cases
        elif self.role == Roles.ROUTER:
            if pck['type'] == 'HEART_BEAT':
                self.update_routing_info(pck) # updates neighbor table with received heart beat message
                log_delivery()
                return
            elif pck['type'] == 'PROBE_ROUTER':
                self.send_heart_beat()  # advertise router presence for bridging
                log_delivery()
                return
            elif pck['type'] == 'JOIN_REQ':
                if pck.get('uid') is not None and pck['uid'] not in self.received_JR_guis:
                    self.received_JR_guis.append(pck['uid'])
                self.send_network_req() # if we get a join request as a CM, send network request to root
                log_delivery()
                return
            elif pck['type'] == 'NETID_RESP':
                # handle router to CH
                # learn_pck = pck.copy()
                # if learn_pck.get('dst_addr') is not None:
                #     learn_pck['src_addr'] = learn_pck['dst_addr']
                #     self.update_routing_info(learn_pck)
                if pck['target_uid'] == self.id:
                    # check if we were actually promoted
                    if not pck['promoted_ch'] or pck['ch_addr'] is None:
                        self.log('NETID_RESP received but not promoted (no network)')
                        # still ack back to clear pending entry at root
                        if pck.get('ack', False):
                            self.send_ack(pck['src_addr'], pck['seq_no'])
                        log_delivery()
                        return

                    # promote
                    self.log(f'NETID_RESP reached target; promoting ROUTER to CH {pck["ch_addr"]}')
                    self.ch_addr = pck['ch_addr'] # new cluster head address
                    self.set_role(Roles.CLUSTER_HEAD) # become cluster head
                    self.send_heart_beat() # send heart beat as new cluster head

                    # send join acks to the pending join requests
                    for gui in self.received_JR_guis:
                        self.send_join_ack({'uid': gui})
                    self.received_JR_guis = []

                    # if ack back requested, send it
                    if pck.get('ack', False):
                        self.send_ack(pck['src_addr'], pck['seq_no'])
                    log_delivery()
                    return


        # node cases (non-root, non-cluster head)
        elif self.role == Roles.REGISTERED:
            if pck['type'] == 'HEART_BEAT':
                self.update_routing_info(pck) # if received heart beat, update neighbor table
                log_delivery()
                return
            elif pck['type'] == 'PROBE_CM':
                self.send_heart_beat() # if we get a cluster member probe, respond with heart beat
                log_delivery()
                return
            elif pck['type'] == 'JOIN_REQ':
                if pck.get('uid') is not None and pck['uid'] not in self.received_JR_guis:
                    self.received_JR_guis.append(pck['uid'])
                self.send_network_req() # if we get a join request as a CM, send network request to root
                log_delivery()
                return
            elif pck['type'] == 'NETID_RESP':
                # handle response and promotion
                if pck['target_uid'] == self.id:
                    # check if we were actually promoted
                    if not pck['promoted_ch'] or pck['ch_addr'] is None:
                        self.log('NETID_RESP received but not promoted (no network)')
                        # still ack back to clear pending entry at root
                        if pck.get('ack', False):
                            self.send_ack(pck['src_addr'], pck['seq_no'])
                        log_delivery()
                        return

                    # promote
                    self.log(f'NETID_RESP reached target; promoting to CH {pck["ch_addr"]}')
                    self.ch_addr = pck['ch_addr'] # new cluster head address
                    self.set_role(Roles.CLUSTER_HEAD) # become cluster head
                    self.send_heart_beat() # send heart beat as new cluster head

                    # send join acks to the pending join requests
                    for gui in self.received_JR_guis:
                        self.send_join_ack({'uid': gui})
                    self.received_JR_guis = []

                    # if ack back requested, send it
                    if pck.get('ack', False):
                        self.send_ack(pck['src_addr'], pck['seq_no'])
                    log_delivery()
                    return

            # if we are a regular cluster member, we might get promoted to cluster head without needing to request a network
            elif pck['type'] == 'CH_PROMOTE':
                self.handle_ch_promote_request(pck)
                log_delivery()
                return

            elif pck['type'] == 'JOIN_ACK':
                # if we get a join ack as a regular member, and it is for us, check if it wants to become unregistered
                if pck['target_uid'] == self.id and not pck.get('promoted_reg', True):
                    self.log('RN becoming unregistered due to demoted JOIN_ACK')
                    self.become_unregistered(preserve_neighbors=False)
                    log_delivery()
                    return


        # undiscovered node case
        elif self.role == Roles.UNDISCOVERED:
            if pck['type'] == 'HEART_BEAT':  # it kills probe timer, becomes unregistered and sets join request timer once received heart beat
                self.update_routing_info(pck)
                self.kill_timer('TIMER_PROBE')
                self.become_unregistered(preserve_neighbors=True)
                log_delivery()
                return

        # Unregistered node case
        elif self.role == Roles.UNREGISTERED:
            if pck['type'] == 'HEART_BEAT':
                self.update_routing_info(pck) # if received heart beat, update neighbor table
                log_delivery()
                return

            if pck['type'] == 'JOIN_ACK':
                if pck['target_uid'] == self.id:
                    # did we get accepted?
                    if not pck['promoted_reg'] or pck['cm_addr'] is None:
                        self.log(f'JOIN_ACK received but not accepted (promoted_reg={pck.get("promoted_reg")}, cm_addr={pck.get("cm_addr")})')
                        self.mark_join_rejected(pck.get('src_addr'))
                        self.last_join_target = None
                        self.last_join_time = 0
                        log_delivery()
                        return

                    # accepted, update our addresses
                    self.addr = pck['cm_addr']
                    self.parent_address = pck['src_addr']
                    self.parent_gui = pck['uid']
                    self.parent_set_time = self.now
                    self.draw_parent()

                    # stop join request timer
                    self.kill_timer('TIMER_JOIN_REQ')
                    self.send_heart_beat() # advertise as CM
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)

                    # send ACK back to cluster head that we received the join ack
                    self.send_ack(pck['src_addr'], pck['seq_no'])

                    self.log(f'JOIN_ACK accepted: uid={self.id} parent={self.parent_address} addr={self.addr}')
                    self.last_join_target = None
                    self.last_join_time = 0

                    # update role
                    if self.ch_addr is not None:
                        self.set_role(Roles.CLUSTER_HEAD)
                    else:
                        self.set_role(Roles.REGISTERED)

                    log_delivery()
                    return

        # record delivery if we reach here
        log_delivery()

    # timer handler
    def on_timer_fired(self, name, *args, **kwargs):
        if name == 'TIMER_ARRIVAL':  # it wakes up and set timer probe once time arrival timer fired
            self.scene.nodecolor(self.id, 1, 0, 0)  # sets self color to red
            if self.id not in JOIN_START_TIMES:
                JOIN_START_TIMES[self.id] = self.now
            self.wake_up()
            self.set_timer('TIMER_PROBE', 1)

        elif name == 'TIMER_PROBE':  # it sends probe if counter didn't reach the threshold once timer probe fired.
            if self.c_probe < self.th_probe:
                self.send_probe()
                self.c_probe += 1
                self.set_timer('TIMER_PROBE', 1)
            else:  # if the counter reached the threshold
                if self.is_root_eligible:  # if the node is root eligible, it becomes root
                    self.set_role(Roles.ROOT)
                    self.scene.nodecolor(self.id, 0, 0, 0)
                    self.addr = wsn.Addr(1, 254)  # root is always network 1
                    self.ch_addr = wsn.Addr(1, 254)
                    self.root_addr = self.addr
                    self.hop_count = 0
                    self.log(f'ROOT online id={self.id}, addr={self.addr}, tx_range={self.tx_range}, max_children={config.SIM_MAX_CHILDREN}, max_networks={config.SIM_MAX_NETWORKS}')
                    self.send_heart_beat()  # advertise immediately
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                else:  # otherwise it keeps trying to sending probe after a long time
                    self.c_probe = 0
                    self.set_timer('TIMER_PROBE', 30)

        elif name == 'TIMER_HEART_BEAT':  # sends heart beat and performs periodic maintenance
            self.send_heart_beat()
            self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)

            # Increment counter and perform table maintenance every 5 heartbeats
            self.heartbeat_counter += 1
            if self.heartbeat_counter >= 5:  # 5 seconds = 5 × 1 second intervals
                self.maintain_tables()
                self.heartbeat_counter = 0  # reset counter

        elif name == 'TIMER_ROUTERABLE_CHECK':  # check if can become router and attempt
            if self.role == Roles.CLUSTER_HEAD:
                self.attempt_member_promotion(post_role='router')
            self.set_timer('TIMER_ROUTERABLE_CHECK', config.ROUTERABLE_CHECK_INTERVAL)

        elif name == 'TIMER_JOIN_REQ':  # if it has not received heart beat messages before, it sets timer again and wait heart beat messages once join request timer fired
            if len(self.neighbors_table) == 0 and self.role != Roles.UNREGISTERED:
                self.become_unregistered()
            else:  # otherwise it chose one of them and sends join request
                # self.log(f'TIMER_JOIN_REQ neighbor_count={len(self.neighbors_table)}')
                self.select_and_join()

        elif name == 'TIMER_SENSOR':
            # data timer
            if self.addr is not None or self.ch_addr is not None:
                pck = self.build_common_packet('DATA', ack=False, dst_addr=wsn.Addr(1, 254))
                pck.update({'payload': random.uniform(10, 50)})
                self.route_and_forward_package(pck)

            timer_duration = self.id % config.SENSOR_BASE_INTERVAL
            if timer_duration == 0:
                timer_duration = 1
            timer_duration += random.uniform(0, 1)
            self.set_timer('TIMER_SENSOR', timer_duration)
        elif name == 'TIMER_EXPORT_CH_CSV':
            # root exports clusterhead distances csv
            if self.role == Roles.ROOT:
                write_clusterhead_distances_csv()
                # reschedule
                self.set_timer('TIMER_EXPORT_CH_CSV', config.EXPORT_CH_CSV_INTERVAL)
        elif name == 'TIMER_EXPORT_NEIGHBOR_CSV':
            if self.role == Roles.ROOT:
                # write_neighbor_distances_csv("neighbor_distances.csv")
                self.set_timer('TIMER_EXPORT_NEIGHBOR_CSV', config.EXPORT_NEIGHBOR_CSV_INTERVAL)
