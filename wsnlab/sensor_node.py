import sys

sys.path.insert(1, '.')
from source import wsnlab_vis as wsn
import math
import copy
import random
from source import config
from collections import Counter
import csv

from roles import Roles
from tracking_containers import *
from csv_utils import write_clusterhead_distances_csv

from table_entries import *

BATTERY_CAPACITY_MJ = config.BATTERY_CAPACITY_MAH * 3.0 * 3600

# for energy calc
def _estimate_packet_size_bytes(pck: dict) -> int:
    base = 64
    per_field = 4  # bytes per field
    field_count = sum(1 for key in pck.keys() if pck[key] is not None)
    mac_bytes = base + per_field * max(field_count, 0)
    return mac_bytes + 6  # N + 6 phy

class SensorNode(wsn.Node):
    # init of SensorNode
    def init(self):
        super().init()
        self.scene.nodecolor(self.id, 1, 1, 1)  # sets self color to white
        self.sleep()

        # ROOT
        self.root_addr: wsn.Addr = None  # root address (if we are not root this is None)
        self.is_root_eligible = True if self.id == ROOT_ID else False  # only one node is root eligible

        # CLUSTER HEAD
        self.ch_addr: wsn.Addr = None  # our cluster head address (our (x.254) address)
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
        self.hops_to_root = 99999  # hops to root, initialized to large number
        self.probes_sent = 0  # number of probes sent

        self.tx_power_level = 0  # transmission power level
        self.tx_range = config.NODE_TX_RANGES[self.tx_power_level] # set initial tx range

        self.seq_no = 0  # monotonic packet sequence number (wraps at 2^16)
        self.path_cost = None  # cumulative cost to root (rx_cost sum)

        # energy stuff
        self.battery_mj = BATTERY_CAPACITY_MJ
        self.is_alive = True

        # promotion tracking
        self.promotion_completed_at = None  # ts when promotion to CH completed
        self.last_registered_at = None  # ts when joined/rejoined (cooldown)

        # ad hoc routing / promotion
        self.pending_ch_promotion = None  # track in-flight CH promotion (seq, target)
        self.last_parent_check = 0
        self.parent_set_time = 0
        self.router_links = set()  # uids of CHs we draw bridge lines to

        # metadata
        self.last_join_target: wsn.Addr | None = None  # last join attempt destination
        self.last_join_target_uid: int | None = None  # uid of last join target
        self.last_join_time: float = 0 # ts of last join attempt
        self.heartbeat_counter = 0  # tracks heartbeats
        self.forwarded_packets = set()  # (src_addr, seq_no) 

    # easy way to get all addresses for this node
    @property
    def my_addresses(self):
        addrs = {self.addr}
    
        if (self.role in [Roles.CLUSTER_HEAD, Roles.ROOT] and self.ch_addr is not None):
            addrs.add(self.ch_addr)
        
        return addrs

    # build a common packet
    def build_common_packet(self, p_type="NULL", ack=False, dst_addr=wsn.BROADCAST_ADDR,
                            add_roles=False, add_capabilities=False):
        src_addr = self.addr
        if self.role in [Roles.CLUSTER_HEAD, Roles.ROOT]:
            # if the dst is a child of this node, use the CH address
            if self.members_table.get(dst_addr) is not None:
                src_addr = self.ch_addr
            # or if we are broadcasting as a CH, use the CH address
            elif dst_addr == wsn.BROADCAST_ADDR:
                src_addr = self.ch_addr

        # assign packet seqno, build packet fields for this node
        packet_seq_no = self.seq_no
        self.seq_no = (self.seq_no + 1) % (2**16)
        packet = {
            'type': p_type,
            'addr_type': 0, # 0/1 for standard/extended addressing (0 for now)
            'ack': ack, # ack back flag
            'hop_count': 0, # hop count of packet
            'use_mesh': not config.TREE_ONLY, # allow mesh routing?

            'seq_no': packet_seq_no, # packet sequence number

            'dst_addr': dst_addr, # destination address
            'next_hop_addr': None, # next hop address
            'src_addr': src_addr, # source address

            # DEBUG TRACKING FIELDS
            'origin_uid': self.id, # id of the node that originated the packet
            'created_time': self.now,
            'path': [],
            'path_dynamic': [],
        }


        # add role attributes if requested
        if add_roles:
            packet.update({'role': self.role})
        if add_capabilities:
            packet.update({
                'capabilities': NodeCapabilities(
                    CAPABLE_CLUSTER_HEAD=True, # all nodes can be cluster heads
                    CAPABLE_ROUTER=True, # all nodes can be routers
                    CAPABLE_ROOT_NODE=(self.role == Roles.ROOT), # only root node can be root or gateway
                    CAPABLE_GATEWAY=(self.role == Roles.ROOT),
                    joinable=self.is_joinable(), # advertised joinable?
                )
            })

        return packet, packet_seq_no

    # check if packet should be dropped on rx
    def _should_drop_packet(self, pck):
        p_type = pck.get('type')
        dst_addr = pck.get('dst_addr')
        next_hop = pck.get('next_hop_addr')

        # bad packet, drop
        if p_type is None or dst_addr is None:
            self.log(f"DROP: malformed packet. type={p_type}")
            return True

        # ttl exceeded, drop
        if pck.get('hop_count', 0) >= config.ROUTING_MAX_HOPS:
            self.log(f"DROP: ttl exceeded, hops={pck.get('hop_count')}")
            return True

        # if next hop is set and it's not us, drop
        if next_hop is not None:
            if next_hop != wsn.BROADCAST_ADDR and next_hop not in self.my_addresses:
                return True

        return False

    # check if packet is for us or if we should forward it
    def _is_packet_at_destination(self, pck, *, log: bool = False):
        dest = pck.get('dst_addr')

        # broadcast is for us
        if dest == wsn.BROADCAST_ADDR:
            return True

        # destination is us, then it's for us
        if dest in self.my_addresses:
            if log:
                self.log(f"Packet for us: {pck}")
            return True

        # network broadcast to our network
        if self.addr is not None and dest.net_addr == self.addr.net_addr:
            if dest.node_addr == config.BROADCAST_NODE_ADDR:
                return True
        
        # network broadcast to our child network
        if self.ch_addr is not None and dest.net_addr == self.ch_addr.net_addr:
            if dest.node_addr == config.BROADCAST_NODE_ADDR:
                return True

        # not for us, forward
        return False

    # record a packet delivery to the log
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

        path_dynamic_list = pck.get('path_dynamic', [])
        if isinstance(path_dynamic_list, list):
            stored_path_dynamic = path_dynamic_list.copy()
        else:
            stored_path_dynamic = [path_dynamic_list]

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
            "path_dynamic": stored_path_dynamic,
        })

    # get the tx power level for a distance
    def get_tx_power_level_for_dist(self, distance):
        if distance is None:
            return len(config.NODE_TX_RANGES) - 1

        target = distance  # find best tx power to match distance
        for idx, rng in enumerate(config.NODE_TX_RANGES):
            if rng >= target:
                return idx

        # fallback to max
        return len(config.NODE_TX_RANGES) - 1

    # set the tx power level for a distance
    def set_tx_power_for_distance(self, distance):
        level = self.get_tx_power_level_for_dist(distance)
        self.tx_power_level = level
        self.tx_range = config.NODE_TX_RANGES[level]
        return level

    # compute our cumulative path cost to root
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

    # determine if we can accept a new member
    def is_joinable(self) -> bool:
        # only cluster heads or root nodes with a CH address can accept members
        if self.role not in (Roles.CLUSTER_HEAD, Roles.ROOT):
            return False
        if self.ch_addr is None:
            return False

        # check if we can issue a new address
        return self.get_next_free_node_addr(candidate_uid=None) is not None

    # get a neighbors role
    def get_neighbor_role(self, addr: wsn.Addr):
        entry: NeighborTableEntry = self.neighbors_table.get(addr)
        if entry is None:
            return None
        return entry.role

    # if if the packet has been seen before, its a duplicate
    def _is_duplicate_packet(self, pck) -> bool:
        src_addr = pck.get('src_addr')
        seq_no = pck.get('seq_no')
        if src_addr is None or seq_no is None:
            return False
        return (src_addr, seq_no) in self.forwarded_packets

    # mark a forwarded packet and remove old packets
    def _mark_packet_forwarded(self, pck):
        src_addr = pck.get('src_addr')
        seq_no = pck.get('seq_no')
        if src_addr is None or seq_no is None:
            return
        self.forwarded_packets.add((src_addr, seq_no))
        # half the set if it grows too large
        if len(self.forwarded_packets) > 1000:
            to_remove = list(self.forwarded_packets)[:500]
            for item in to_remove:
                self.forwarded_packets.discard(item)

    # handle battery depletion, exempt root
    def _handle_battery_death(self, *, reason: str = ""):
        if self.role == Roles.ROOT:
            return
        if not self.is_alive:
            return
        self.is_alive = False
        self.log(f"battery depleted{f" ({reason})" if reason else ""}")
        self.kill_all_timers()
        self.clear_tx_range()
        self.erase_parent()
        self.scene.nodecolor(self.id, 0.2, 0.2, 0.2)

    # send a packet, specify tx power level if desired
    def send(self, pck, tx_level=None):
        # don't send if dead
        if not self.is_alive:
            return -1

        # if our next hope or dst is one of our addresses, overrite to parent
        existing_next_hop = pck.get('next_hop_addr', None)
        dst_addr = pck.get('dst_addr')
        if existing_next_hop is not None and existing_next_hop in self.my_addresses and dst_addr not in self.my_addresses:
            new_next_hop = self.parent_address if self.parent_address not in self.my_addresses else None
            if new_next_hop is not None:
                pck['next_hop_addr'] = new_next_hop
            else:
                pck['next_hop_addr'] = None

        # fallback to dst
        if pck.get('next_hop_addr', None) is None:
            if pck.get('dst_addr') != wsn.BROADCAST_ADDR:
                self.log("WARN: packet next_hop_addr not set, defaulting to dst_addr")
            pck['next_hop_addr'] = pck.get('dst_addr')

        # pick tx power to next hop for this packet from
        if tx_level is None:
            # broadcast goes out at max power
            if pck.get('dst_addr') == wsn.BROADCAST_ADDR:
                tx_level = len(config.NODE_TX_RANGES) - 1
            else:
                # try to size power for the selected neighbor
                next_hop_addr = pck.get('next_hop_addr', None)
                if next_hop_addr is not None:
                    entry = self.neighbors_table.get(next_hop_addr, None)
                    if entry is not None:
                        tx_level = self.get_tx_power_level_for_dist(entry.rx_cost)

        try:
            tx_level = int(tx_level)
        except (TypeError, ValueError):
            tx_level = len(config.NODE_TX_RANGES) - 1

        # compute energy cost and deduct from battery
        if self.role != Roles.ROOT:
            self.battery_mj -= ((_estimate_packet_size_bytes(pck) * config.TX_ENERGY_PER_BYTE_UJ[tx_level]) + config.TX_OVERHEAD_UJ) / 1000.0

            # did we die in middle of send?
            if self.battery_mj <= 0.0:
                self._handle_battery_death(reason=f"while sending {pck.get('type')}")
                return -1 # died, packet not sent

        # increase hop count before send
        pck.update({'hop_count': pck.get('hop_count', 0) + 1})

        link_src_addr = self.addr
        if self.role in [Roles.CLUSTER_HEAD, Roles.ROOT] and self.ch_addr is not None:
            link_src_addr = self.ch_addr

        pck.update({'last_router': link_src_addr})

        # grab the list and append info
        pck['path'].append(self.id)
        pck['path_dynamic'].append(link_src_addr)

        # apply tx range for this packet
        self.tx_power_level = tx_level
        self.tx_range = config.NODE_TX_RANGES[tx_level]

        super().send(pck)
        return pck.get('seq_no')

    # arrival event handler
    def run(self):
        self.set_timer('TIMER_ARRIVAL', self.arrival)

    # runs to set the node role
    def set_role(self, new_role, *, recolor=True):
        # track role history for energy analysis
        old_role = getattr(self, "role", None)
        if old_role is not None and hasattr(self, 'battery_mj'):
            # record time and energy
            if self.id not in ROLE_HISTORY:
                ROLE_HISTORY[self.id] = []
            time_in_role = self.now - getattr(self, 'role_start_time', self.now)
            energy_consumed = getattr(self, 'role_start_battery', self.battery_mj) - self.battery_mj
            ROLE_HISTORY[self.id].append((old_role, time_in_role, energy_consumed))

        # start tracking new role
        if hasattr(self, 'battery_mj'):
            self.role_start_time = self.now
            self.role_start_battery = self.battery_mj

        # update global role counts
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
            elif new_role == Roles.CLUSTER_HEAD:
                self.scene.nodecolor(self.id, 0, 0, 1)
                self.tx_power_level = len(config.NODE_TX_RANGES) - 1
                self.tx_range = config.NODE_TX_RANGES[self.tx_power_level]
                self.draw_tx_range()
            elif new_role == Roles.ROUTER:
                self.scene.nodecolor(self.id, 1, 0, 0)
                self.tx_power_level = len(config.NODE_TX_RANGES) - 1
                self.tx_range = config.NODE_TX_RANGES[self.tx_power_level]
                self.clear_tx_range()
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

        # cluster heads send keepalives
        self.kill_timer('TIMER_CH_KEEPALIVE')
        if new_role == Roles.CLUSTER_HEAD:
            self.set_timer('TIMER_CH_KEEPALIVE', config.CH_KEEPALIVE_INTERVAL)

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

    # runs to become unregistered
    def become_unregistered(self, *, preserve_neighbors=False):
        self.kill_timer('TIMER_PROBE')
        if self.role != Roles.UNDISCOVERED:
            self.kill_all_timers()
            if self.role != Roles.UNREGISTERED:
                self.log(f'{self.id} became UNREGISTERED')

        self.scene.nodecolor(self.id, 1, 1, 0)
        self.erase_parent()

        self.addr = None
        self.ch_addr = None

        self.parent_address = None
        self.parent_gui = None
        self.root_addr = None
        self.parent_set_time = self.now
        self.downstream_ch_addr = None
        self.downstream_ch_gui = None

        self.set_role(Roles.UNREGISTERED)
        self.c_probe = 0
        self.th_probe = len(config.NODE_TX_RANGES) * 6
        self.hops_to_root = 99999
        self.probes_sent = 0
        self.tx_power_level = 0
        self.tx_range = config.NODE_TX_RANGES[self.tx_power_level]
        self.pending_ch_promotion = None
        self.last_parent_check = 0
        self.last_join_target = None
        self.last_join_target_uid = None
        self.last_join_time = 0

        if not preserve_neighbors:
            self.neighbors_table = {}
            self.child_networks_table = {}
            self.members_table = {}

        self.received_JR_guis = []

        # start probe and join timers
        self.send_probe()

        self.set_timer('TIMER_JOIN_REQ', random.uniform(0, config.TIMER_JOIN_REQ_INTERVAL))
        self.set_timer('TIMER_PROBE', random.uniform(0, 1))

    # runs to update tables based on packet type
    def update_routing_info(self, pck):
        neighbor_addr = pck.get('last_router')
        if neighbor_addr is None: 
            return

        # get stats
        arrival_time = pck.get('arrival_time', self.now)
        dist = pck.get('distance', 0)


        # update neighbor table
        entry = self.neighbors_table.get(neighbor_addr)

        if entry is None:
            # create new entry
            self.neighbors_table[neighbor_addr] = NeighborTableEntry(
                uid=pck.get('uid'),
                nextHopAddr=neighbor_addr,
                hops=1,
                capabilities=pck.get('capabilities'),
                role=pck.get('role'),
                lastHeard=arrival_time,
                rx_cost=dist,
                path_cost=pck.get('path_cost'),
                join_rejected_until=0
            )
        else:
            # update existing entry
            entry.lastHeard = arrival_time
            entry.rx_cost = dist
            if pck.get('uid'): entry.uid = pck.get('uid')
            if pck.get('role'): entry.role = pck.get('role')
            if pck.get('path_cost'): entry.path_cost = pck.get('path_cost')
        entry = self.neighbors_table.get(neighbor_addr)

        # on heartbeat, update table
        ptype = pck.get('type', None)
        if ptype == 'HEART_BEAT':
            src_addr = pck.get('src_addr')
            uid = pck.get('uid')
            member_addr = pck.get('child_addr', src_addr)

            if entry is not None:
                entry.hops = 1
                entry.nextHopAddr = neighbor_addr
            
            # ensure we have a src 
            if src_addr:
                pass 

            # member renewal
            if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT) and self.ch_addr:
                # check if the sender is a member of the subnet and update if so
                if member_addr is not None and member_addr.net_addr == self.ch_addr.net_addr:
                    member_entry = self.members_table.get(member_addr)
                    if member_entry:
                        if member_entry.uid == uid:
                            member_entry.expiry_time = self.now + config.MEMBER_STALE_INTERVAL
                        else:
                            self.log(f"uid conflict: {member_addr} owned by {member_entry.uid}, claimed by {uid}, sending NACK")
                            self.send_join_nack(uid)
                    
                    # unknown member
                    else:
                        is_known_uid = any(m.uid == uid for m in self.members_table.values() if m)
                        
                        if is_known_uid:
                            self.log(f"uid {uid} moved to {member_addr} without re-join, ignoring")
                        else:
                            self.log(f"unknown member {uid} at {member_addr}, sending NACK")
                            self.send_join_nack(uid)

            # read advertised neighbors to build neighbor table
            neighbor_list = pck.get('neighbors', [])
            if neighbor_list:
                adv_limit = max(1, config.NEIGHBOR_HOP_LIMIT)
                for advert in neighbor_list:
                    advert_addr = advert.get('addr')
                    advert_hops = advert.get('hops')
                    # skip invalid
                    if advert_addr is None or advert_hops is None:
                        continue

                    # avoid adding ourselves
                    if advert_addr in self.my_addresses:
                        continue
                    
                    # only add within limit
                    new_hops = advert_hops + 1
                    if new_hops > adv_limit:
                        continue
                    
                    # update or add entry if better
                    existing_adv = self.neighbors_table.get(advert_addr)
                    if existing_adv is None or new_hops < existing_adv.hops:
                        self.neighbors_table[advert_addr] = NeighborTableEntry(
                            uid=existing_adv.uid if existing_adv else None,
                            nextHopAddr=neighbor_addr,
                            hops=new_hops,
                            capabilities=existing_adv.capabilities if existing_adv else None,
                            role=existing_adv.role if existing_adv else None,
                            lastHeard=arrival_time,
                            rx_cost=existing_adv.rx_cost if existing_adv else dist,
                            path_cost=existing_adv.path_cost if existing_adv else None,
                            join_rejected_until=existing_adv.join_rejected_until if existing_adv else 0
                        )
                    # update entry if same hop count
                    elif new_hops == existing_adv.hops:
                        existing_adv.lastHeard = arrival_time
                        if existing_adv.nextHopAddr != neighbor_addr:
                            existing_adv.nextHopAddr = neighbor_addr

            # update hops_to_root if heartbeat is from our parent
            if neighbor_addr == self.parent_address:
                parent_hops = pck.get('hops_to_root', 99999)
                if parent_hops < 99999:
                    self.hops_to_root = parent_hops + 1

        # cluster heads store pending netid requests
        elif ptype == 'NETID_REQ':
            if self.role != Roles.CLUSTER_HEAD:
                return
            target_uid = pck.get('target_uid')
            last_hop = pck.get('last_router')
            
            if target_uid is not None and last_hop is not None:
                # store last hop for target uid
                self.pending_netid_last_hops[target_uid] = last_hop

        # cluster heads write new child networks on netid response
        elif ptype == 'NETID_RESP':
            if self.role != Roles.CLUSTER_HEAD:
                return

            # grab the previously saved next hop
            promoted = pck.get('promoted_ch', False)
            target_uid = pck.get('target_uid')
            next_hop_to_child = self.pending_netid_last_hops.pop(target_uid, None)
            
            if promoted and target_uid and next_hop_to_child:
                new_net_addr = pck.get('ch_addr').net_addr
                hops_to_child = pck.get('reverse_hop_count', 0)
                
                # create/update child network entry
                self.child_networks_table[new_net_addr] = ChildNetworkEntry(
                    next_hop_addr=next_hop_to_child,
                    hops=hops_to_child,
                    net_state="VALID",
                    last_heard=self.now,
                    ack_seq_no=-1,
                    requester_uid=target_uid
                )
                self.log(f"learned child network {new_net_addr} via {next_hop_to_child}")

        # cluster heads and root update child networks on keepalive
        elif ptype == 'NETID_KEEPALIVE':
            if self.role not in (Roles.CLUSTER_HEAD, Roles.ROOT):
                return
            
            net_id = pck.get('net_id') or (pck.get('src_addr').net_addr if pck.get('src_addr') else None)
            if net_id is None:
                return
            
            # update child network entry fields
            entry = self.child_networks_table.get(net_id)
            if entry:
                entry.last_heard = self.now
                entry.net_state = "VALID"
                last_hop = pck.get('last_router')
                if last_hop and last_hop != entry.next_hop_addr:
                    entry.next_hop_addr = last_hop
                if pck.get('hop_count'):
                    entry.hops = pck.get('hop_count')


    # find best member to promote to cluster head
    def _find_ch_promotion_candidate(self):
        # if we are not a cluster head, we cannot promote anyone
        if self.role != Roles.CLUSTER_HEAD:
            # self.log('not a cluster head, cannot promote anyone')
            return None

        best_addr = None
        best_score = -1

        # score every member by their rx_cost
        self.maintain_tables()
        for member_addr, member_entry in self.members_table.items():
            # find its neighbor entry
            n_entry = self.neighbors_table.get(member_addr, None)
            if n_entry is None:
                # self.log(f'no neighbor entry for member: {member_addr}')
                continue
                
            # only consider members
            if n_entry.role != Roles.REGISTERED:
                # self.log(f'not a registered member: {member_addr}, role: {n_entry.role}')
                continue

            # push score higher
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
            # pass over missing entries or non 1-hop
            if entry is None:
                continue

            hops = entry.hops if entry.hops is not None else 1
            if hops != 1:
                continue
            role = entry.role
            caps = entry.capabilities

            # skip the ones that rejected us recently
            if entry.join_rejected_until and (self.now < entry.join_rejected_until):
                continue

            # skip cluster heads/root that cannot accept members
            if role in (Roles.CLUSTER_HEAD, Roles.ROOT):
                if caps is not None and getattr(caps, 'joinable', True) is False:
                    continue

            # if we see root, prefer it immediately
            if role == Roles.ROOT and hops == 1:
                return addr, entry.rx_cost

            # only consider cluster heads if specified
            if require_cluster_head:
                if role is None or role != Roles.CLUSTER_HEAD:
                    continue

            # avoid routers unless explicitly allowed
            if not allow_router:
                if role is not None and role == Roles.ROUTER:
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

        # find/create neighbor entry and set backoff time
        if neighbor_addr is not None:
            entry = self.neighbors_table.get(neighbor_addr, None)
            if entry is not None:
                entry.join_rejected_until = self.now + config.JOIN_REJECT_BACKOFF
                return
            else:
                self.neighbors_table[neighbor_addr] = NeighborTableEntry(
                    uid=None,
                    nextHopAddr=neighbor_addr,
                    hops=1,
                    capabilities=None,
                    role=None,
                    lastHeard=self.now,
                    rx_cost=0,
                    path_cost=None,
                    join_rejected_until=self.now + config.JOIN_REJECT_BACKOFF
                )

    # run on TIMER_JOIN_REQ fired selects one of candidate parents and sends join request
    def select_and_join(self):
        if self.role != Roles.UNREGISTERED:
            return

        # make sure tables are up to date
        self.maintain_tables()

        # prefer cluster heads first
        best_addr, best_rx_strength = self.choose_join_candidate(require_cluster_head=True)

        # if none, try any node except routers
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
            return

        pck, _ = self.build_common_packet(p_type='PROBE', ack=False, dst_addr=wsn.BROADCAST_ADDR)

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
        # ensure path cost is right
        self.compute_path_cost()
        pck, _ = self.build_common_packet(p_type='HEART_BEAT', ack=False, dst_addr=wsn.BROADCAST_ADDR,
                                       add_roles=True, add_capabilities=True)

        # include our child address if we have one
        if self.addr is not None:
            pck['child_addr'] = self.addr

        # include our path cost and hops to root
        pck['path_cost'] = self.path_cost
        pck['hops_to_root'] = self.hops_to_root
        pck.update({'uid': self.id})

        # advertise neighbors up to N-1 hops
        adv_limit = max(1, config.NEIGHBOR_HOP_LIMIT)
        max_adv_hops = adv_limit - 1
        if max_adv_hops > 0:
            neighbor_adverts = []
            for n_addr, n_entry in self.neighbors_table.items():
                # skip invalid entries, invalid hop count, or too many hops
                if n_addr is None or n_entry is None:
                    continue
                if n_entry.hops is None or n_entry.hops <= 0:
                    continue
                if n_entry.hops <= max_adv_hops:
                    neighbor_adverts.append({
                        'addr': n_addr,
                        'hops': n_entry.hops
                    })
            if neighbor_adverts:
                pck['neighbors'] = neighbor_adverts
        self.send(pck)

    # CH keepalive to root so child network table entries are correct
    def send_child_network_keepalive(self):
        if self.role != Roles.CLUSTER_HEAD or self.ch_addr is None:
            return

        dst_addr = self.root_addr if self.root_addr is not None else wsn.Addr(1, 254)
        pck, _ = self.build_common_packet(p_type='NETID_KEEPALIVE', ack=False, dst_addr=dst_addr)
        pck.update({
            'net_id': self.ch_addr.net_addr,
            'requester_uid': self.id,
        })

        if self.addr is not None:
            pck['child_addr'] = self.addr

        self.route_and_forward_package(pck, use_mesh=False)

    # send JOIN_REQ packet to given dst
    def send_join_req(self, dest):
        if self.role != Roles.UNREGISTERED:
            self.log("send_join_req called when not UNREGISTERED")
            return

        # send a join request to given dst_addr
        pck, _ = self.build_common_packet(p_type='JOIN_REQ', ack=False, dst_addr=dest,
                                       add_roles=True, add_capabilities=True)
        pck.update({'uid': self.id}) # add our uid so CH can identify us
        pck.update({'next_hop_addr': dest})
        self.log(f'tx JOIN_REQ to {dest} from uid={self.id}')
        self.last_join_target = dest

        # store uid to validate later
        target_entry = self.neighbors_table.get(dest)
        self.last_join_target_uid = target_entry.uid if target_entry else None
        self.last_join_time = self.now
        self.send(pck)

    # maintain neighbor/member/child network tables
    def maintain_tables(self):
        # neighbor table cleanup
        for n_addr, n_entry in list(self.neighbors_table.items()):
            if n_entry is None:
                self.neighbors_table.pop(n_addr, None)
                continue
            if n_entry.hops is not None and n_entry.hops > max(1, config.NEIGHBOR_HOP_LIMIT):
                self.neighbors_table.pop(n_addr, None)
                continue
            age = self.now - n_entry.lastHeard if n_entry.lastHeard is not None else None
            if age is not None and age > config.MEMBER_STALE_INTERVAL:
                self.neighbors_table.pop(n_addr, None)

        # if not root or unregistered, check the neighbor table for our parent and become unregistered if missing
        if self.role is not Roles.ROOT and self.role is not Roles.UNREGISTERED and \
                self.parent_address is not None and self.parent_gui is not None:
            parent_entry: NeighborTableEntry | None = self.neighbors_table.get(self.parent_address, None)
            # if parent was lost, become unregistered
            if parent_entry is None:
                self.log(f'parent {self.parent_address} missing, becoming UNREGISTERED')
                self.become_unregistered()
                return
            
            # skip parent role checks during promotion period
            in_grace_period = False
            if self.promotion_completed_at is not None:
                if self.now - self.promotion_completed_at < 1.0:
                    in_grace_period = True
                else:
                    self.promotion_completed_at = None  # grace period expired

            # if parent role changed to something incompatible, detach to avoid stale links
            if parent_entry.role is not None and not in_grace_period:
                if self.role == Roles.REGISTERED and parent_entry.role not in (Roles.CLUSTER_HEAD, Roles.ROOT):
                    self.log(f'parent role changed to {parent_entry.role}, becoming UNREGISTERED')
                    self.become_unregistered()
                    return
                if self.role == Roles.CLUSTER_HEAD and parent_entry.role not in (Roles.ROUTER, Roles.ROOT, Roles.CLUSTER_HEAD):
                    self.log(f'parent role changed to {parent_entry.role}, becoming UNREGISTERED')
                    self.become_unregistered()
                    return
                if self.role == Roles.ROUTER and parent_entry.role not in (Roles.ROUTER, Roles.ROOT, Roles.CLUSTER_HEAD):
                    self.log(f'parent role changed to {parent_entry.role}, becoming UNREGISTERED')
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
            # skip update during rejoin
            if self.last_registered_at is not None and (self.now - self.last_registered_at) < config.REJOIN_COOLDOWN:
                pass
            elif self.parent_address is not None:
                parent_entry: NeighborTableEntry | None = self.neighbors_table.get(self.parent_address, None)
                if parent_entry is not None and parent_entry.path_cost is not None:
                    best_addr, best_rx_cost = self.choose_join_candidate(require_cluster_head=True, allow_router=False)
                    if best_addr is not None:
                        if best_addr != self.parent_address:
                            best_entry: NeighborTableEntry | None = self.neighbors_table.get(best_addr, None)
                            if best_entry is not None:
                                # only switch if improvement exceeds threshold
                                current_rx_cost = parent_entry.rx_cost
                                improvement = (current_rx_cost - best_rx_cost) / current_rx_cost
                                if improvement > config.PARENT_SWITCH_HYSTERESIS:
                                    self.log(f'better parent found {best_addr} '
                                           f'(improvement: {improvement*100:.1f}%)')
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
                # remove members with different net_addr than our ch_addr
                if self.ch_addr is not None and member_addr.net_addr != self.ch_addr.net_addr:
                    self.members_table.pop(member_addr, None)
                    continue
                # same for root
                if self.root_addr is not None and member_addr.net_addr != self.root_addr.net_addr:
                    self.members_table.pop(member_addr, None)
                    continue

            # cleanup child networks table
            for net_id, entry in list(self.child_networks_table.items()):
                if entry is None:
                    self.child_networks_table.pop(net_id, None)
                    continue

                # remove child networks if expired and still pending
                age = self.now - entry.last_heard if entry.last_heard is not None else None
                if age is not None and age > config.PARENT_STALE_INTERVAL and entry.net_state != "VALID":
                    self.child_networks_table.pop(net_id, None)
                    continue

                # remove old child networks so addresses can be reused
                if age is not None and age > config.NETID_STALE_INTERVAL:
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

        # also exclude our own addr if it's a member address (not 254) in the same network
        # this prevents conflict when CH was promoted from a member role within the same network
        if self.addr is not None and self.addr.node_addr != 254 and self.addr.net_addr == self.ch_addr.net_addr:
            used_node_addrs.add(self.addr.node_addr)

        # if we've already allocated all slots, no new address is available
        if len(used_node_addrs) >= config.SIM_MAX_CHILDREN:
            return None

        # find next free node address:
        for node_addr in range(1, config.SIM_MAX_CHILDREN + 1):  # 1..config.SIM_MAX_CHILDREN
            if node_addr not in used_node_addrs:
                return node_addr

        # self.log(f'no free node addresses available in cluster head network {self.ch_addr}')
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
        pck, _ = self.build_common_packet(p_type='JOIN_ACK', ack=False, dst_addr=wsn.BROADCAST_ADDR)
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

        # only cluster heads and root can grant joins, otherwise deny
        if self.role not in (Roles.CLUSTER_HEAD, Roles.ROOT) or self.ch_addr is None:
            pck, _ = self.build_common_packet(p_type='JOIN_ACK', ack=False, dst_addr=wsn.BROADCAST_ADDR)
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

        pck, _ = self.build_common_packet(p_type='JOIN_ACK', ack=True, dst_addr=wsn.BROADCAST_ADDR)
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
                self.log(f'JOIN_ACK tx (existing) to uid={candidate_uid}, addr={member_addr}')
                seq_no = self.send(pck, tx_level=self.get_tx_power_level_for_dist(candidate_dist))

                # update existing member entry
                member_entry.expiry_time = self.now + config.MEMBER_STALE_INTERVAL
                member_entry.renewal_valid = False
                if seq_no is not None:
                    member_entry.ack_seq_no = seq_no
                else:
                    member_entry.ack_seq_no = -1
                return

        # otherwise, add new member entry
        member_entry = MemberTableEntry(
            uid=candidate_uid, renewal_valid=False, ack_seq_no=-1,
            expiry_time=self.now + config.MEMBER_STALE_INTERVAL
        )
        self.members_table[new_addr] = member_entry

        # send and save seq_no for ack
        seq_no = self.send(pck, tx_level=self.get_tx_power_level_for_dist(candidate_dist))
        if seq_no is not None:
            member_entry.ack_seq_no = seq_no
        else:
            member_entry.ack_seq_no = -1

        self.log(f'JOIN_ACK tx to uid={candidate_uid}, addr={new_addr}, seq={seq_no}')
        return

    # send ACK packet to dest for given sequence number
    def send_ack(self, dest, seq_no, ack_type="NULL"):
        pck, _ = self.build_common_packet(p_type='ACK', ack=False, dst_addr=dest)
        pck.update({'ack_seq_no': seq_no})
        pck.update({'ack_type': ack_type})
        self.route_and_forward_package(pck)

    # route and forward given packet
    def route_and_forward_package(self, pck, use_mesh=True):
        dst = pck.get('dst_addr')
        prev_hop = pck.get('last_router')

        # if broadcast send directly
        if dst == wsn.BROADCAST_ADDR:
            pck['next_hop_addr'] = wsn.BROADCAST_ADDR
            return self.send(pck)

        # if explicit next hop is given use that
        explicit_next = pck.get('next_hop_addr')
        if explicit_next is not None and explicit_next not in self.my_addresses:
            self.log(f"forwarding via next hop: {explicit_next}")
            return self.send(pck)
    
        pck['next_hop_addr'] = None

        # drop if no dst
        if dst is None:
            self.log("no destination in packet, dropping")
            return -1

        if dst in self.my_addresses:
            self.log("route_and_forward called for self-dst packet")
            return 0

        target_net = getattr(dst, 'net_addr', None)

        # block certain packets for the mesh (mostly control stuff)
        mesh_type = pck.get('type')
        mesh_blocked_types = {
            'NETID_REQ', 'NETID_RESP', 'NETID_KEEPALIVE',
            'ACK', 'CH_PROMOTE', 'JOIN_ACK',
        }
        mesh_blocked = mesh_type in mesh_blocked_types
        allow_mesh = use_mesh and (not config.TREE_ONLY) and pck.get('use_mesh', True) and not mesh_blocked

        # mesh: use neighbor table
        if allow_mesh:
            route = self.neighbors_table.get(dst)
            # if we know the dst, send to next hop
            if route and route.nextHopAddr:
                pck['next_hop_addr'] = route.nextHopAddr
                return self.send(pck)

            # if we know the dst CH, send to next hop
            if target_net is not None:
                dst_ch_addr = wsn.Addr(target_net, 254)
                ch_route = self.neighbors_table.get(dst_ch_addr)
                if ch_route and ch_route.nextHopAddr:
                    pck['next_hop_addr'] = ch_route.nextHopAddr
                    return self.send(pck)

        # router logic
        if self.role == Roles.ROUTER:
            if self.downstream_ch_addr is None:
                self.log(f"router {self.addr} has no downstream_ch_addr for dst={dst}")
            else:
                downstream_net = self.downstream_ch_addr.net_addr

                # packets for the downstream network go to the downstream CH
                if target_net == downstream_net:
                    pck['next_hop_addr'] = self.downstream_ch_addr
                    return self.send(pck)

                # packets from parent go to downstream CH
                if prev_hop == self.parent_address:
                    pck['next_hop_addr'] = self.downstream_ch_addr
                    return self.send(pck)

        # cluster head logic
        if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT):
            my_net_id = None
            if self.ch_addr is not None:
                my_net_id = self.ch_addr.net_addr
            elif self.addr is not None:
                my_net_id = self.addr.net_addr
            
            # if in my network, send directly
            if target_net is not None and my_net_id is not None and target_net == my_net_id:
                pck['next_hop_addr'] = dst
                return self.send(pck)

            # if in a child network, send to next hop to child network 
            if target_net is not None and self.child_networks_table:
                child_net_entry = self.child_networks_table.get(target_net)
                if child_net_entry is not None and child_net_entry.next_hop_addr is not None:
                    pck['next_hop_addr'] = child_net_entry.next_hop_addr
                    return self.send(pck)

        # otherwise, up the tree!!!
        if self.role != Roles.ROOT and self.parent_address is not None:
            if self.parent_address == prev_hop:
                self.log(f"loop detected, parent {self.parent_address} sent non-routable {pck}")
                return -1

            pck['next_hop_addr'] = self.parent_address
            return self.send(pck)

        self.log(f"no route to address {dst}, i am {self.role.name}")
        return -1

    # send NETID_REQ packet to root
    def send_network_req(self):
        if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT):
            self.log("send_network_req called when CLUSTER_HEAD or ROOT")
            return

        pck, _ = self.build_common_packet(p_type='NETID_REQ', ack=False, dst_addr=wsn.Addr(1, 254))
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

        pck, _ = self.build_common_packet(
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
                self.log(f'found existing network id {existing_net_id} for uid={cm_uid}, reusing existing entry')
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
                    next_hop_addr=last_router,  # the next hop is the last router
                    hops=req_hops if req_hops is not None else 0,
                    net_state="VALID",
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
        seq_no = self.route_and_forward_package(pck, use_mesh=False)

        # if success, record the seq_no for ACK to table
        if pck.get('promoted_ch') and next_free_net_addr is not None and next_free_net_addr in self.child_networks_table and seq_no is not None:
            self.child_networks_table[next_free_net_addr].ack_seq_no = seq_no

        granted = bool(pck.get('promoted_ch'))
        self.log(
            f'NETID_RESP {"granted" if granted else "denied"} uid={cm_uid},'
            f' net={next_free_net_addr}, ch_addr={pck.get("ch_addr")}, seq={seq_no},'
            f' dst={cm_dest}, last_router={req_pck.get("last_router")}'
        )
        return

    # handle CH_PROMOTE packet received (transfer role from registered to src's cluster head)
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

        # write new CH address
        old_addr = self.addr
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
        self.promotion_completed_at = self.now  # track promotion time

        self.send_heart_beat()
        self.kill_timer('TIMER_HEART_BEAT')
        self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)

        # send back ACK to parent
        ack, _ = self.build_common_packet(p_type='ACK', ack=False, dst_addr=self.parent_address)
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

    # find suitable candidate for cluster head promotion and try it
    def attempt_member_promotion(self, post_role='router'):
        # only cluster heads can promote members
        if self.role != Roles.CLUSTER_HEAD or self.ch_addr is None:
            # self.log('attempt_member_promotion ignored (not cluster head)')
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
            # self.log('attempt_member_promotion ignored (parent is router)')
            return

        # only promote when exactly one active member exists
        active_members = [
            addr for addr, entry in self.members_table.items()
            if entry is not None and entry.expiry_time >= self.now
        ]
        if len(active_members) != 1:
            # self.log(f'attempt_member_promotion ignored (active members: {active_members})')
            return

        # find suitable candidate
        candidate_addr = self._find_ch_promotion_candidate()
        if candidate_addr is None:
            # self.log('no suitable candidate found for CH promotion')
            return

        self.log(f'promoting member at address {candidate_addr} to cluster head')

        # send CH_PROMOTE packet
        pck, _ = self.build_common_packet(p_type='CH_PROMOTE', ack=True, dst_addr=candidate_addr)
        pck.update({'uid': self.id})
        pck.update({'next_hop_addr': candidate_addr})
        pck.update({'new_parent': self.addr}) # give our child address as new parent for promoted node
        pck.update({'ch_addr': self.ch_addr}) # the new cluster head address
        pck.update({'members_table': dict(self.members_table)}) # transfer members to new CH (copy)
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
        if self.role is not Roles.ROOT:
            self.battery_mj -= (_estimate_packet_size_bytes(pck) * config.RX_ENERGY_PER_BYTE_UJ) / 1000.0
        if self.battery_mj <= 0.0:
            self._handle_battery_death(reason=f"while receiving {pck.get('type')}")
            return

        pck = copy.deepcopy(pck)  # deep copy to avoid shared path lists across receivers
        pck['arrival_time'] = self.now  # add arrival time to the received packet

        # compute distance between self and neighbor, used as rx_cost
        sender_uid = pck.get('last_tx_uid', pck.get('uid'))
        if sender_uid in NODE_POS and self.id in NODE_POS:
            x1, y1 = NODE_POS[self.id]
            x2, y2 = NODE_POS[sender_uid]
            pck['distance'] = math.hypot(x1 - x2, y1 - y2)

        # check if we should drop the packet
        if self._should_drop_packet(pck):
            self.log(f'dropping packet {pck}')
            return

        # check duplicate
        if self._is_duplicate_packet(pck):
            return
        self._mark_packet_forwarded(pck)

        # snoop for NETID_REQ/RESP to update routing info
        if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT, Roles.ROUTER) and pck.get('type') in ('NETID_REQ', 'NETID_RESP', 'NETID_KEEPALIVE'):
            self.update_routing_info(pck)

        # if packet is not for us, route and forward
        if not self._is_packet_at_destination(pck, log=False):
            if pck['type'] != 'DATA' and pck['type'] != 'SENSOR':
                # self.log(f"forwarding network packet {pck}")
                None
            self.route_and_forward_package(pck)
            return

        # add path if we didn't drop or forward
        pck.get('path', []).append(self.id)
        if self.role in (Roles.CLUSTER_HEAD, Roles.ROOT):
            pck.get('path_dynamic', []).append(self.ch_addr)
        else:
            pck.get('path_dynamic', []).append(self.addr)

        logged_delivery = False

        # log delivery func (ignore some packets)
        def log_delivery():
            nonlocal logged_delivery
            if self._is_packet_at_destination(pck) and not logged_delivery and pck['type'] != 'HEART_BEAT' \
                    and pck['type'] != 'PROBE_CH' and pck['type'] != 'PROBE_CM' and pck['type'] != 'PROBE_ROUTER':
                self.record_packet_delivery(pck, trace_decision=True)
                logged_delivery = True

        # root or cluster head cases
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
                    # mark neighbor as registered once join completes so promotion can see it
                    n_entry = self.neighbors_table.get(pck['src_addr'])
                    if n_entry is None:
                        self.neighbors_table[pck['src_addr']] = NeighborTableEntry(
                            uid=member.uid,
                            nextHopAddr=pck['src_addr'],
                            hops=1,
                            capabilities=None,
                            role=Roles.REGISTERED,
                            lastHeard=self.now,
                            rx_cost=pck.get('distance', 0),
                            path_cost=None,
                            join_rejected_until=0
                        )
                    else:
                        n_entry.role = Roles.REGISTERED
                        n_entry.uid = member.uid
                        n_entry.hops = 1
                        n_entry.lastHeard = self.now
                        if pck.get('distance') is not None:
                            n_entry.rx_cost = pck['distance']

                    # try to make routers as we go
                    if self.role == Roles.CLUSTER_HEAD and config.ENABLE_ROUTERS:
                        self.log(f'attempting router promotion from JOIN_ACK ACK for uid={member.uid}, addr={pck["src_addr"]}')
                        self.attempt_member_promotion(post_role='router')

                    log_delivery()
                    return

                # validate child network entry when we receive ACK for NETID_RESP
                for net_id, entry in self.child_networks_table.items():
                    if entry.ack_seq_no == pck['ack_seq_no']:
                        self.log(f'NETID_RESP ACK received for net={net_id}, seq={pck["ack_seq_no"]}')
                        entry.net_state = "VALID" # net valid
                        entry.last_heard = self.now
                        # update next_hop_addr from the last router in the ACK
                        ack_last_router = pck.get('last_router')
                        if ack_last_router is not None and ack_last_router != entry.next_hop_addr:
                            entry.next_hop_addr = ack_last_router
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
                DATA_PACKETS_DELIVERED[0] += 1
                log_delivery()
                return

            elif pck['type'] == 'JOIN_ACK':
                # handle JOIN_ACK for CH new parent
                if pck['target_uid'] == self.id:
                    if pck.get('promoted_reg', False) and pck.get('cm_addr') is not None:
                        self.addr = pck['cm_addr']
                        self.parent_address = pck['src_addr']
                        self.parent_gui = pck.get('uid')
                        self.parent_set_time = self.now
                        self.draw_parent()
                        self.send_ack(pck['src_addr'], pck['seq_no'])
                        self.log(f'JOIN_ACK accepted (CH re-parent): addr={self.addr} parent={self.parent_address}')
                log_delivery()
                return

        # router cases
        elif self.role == Roles.ROUTER:
            if pck['type'] == 'HEART_BEAT':
                self.update_routing_info(pck) # update neighbor table on received HB
                log_delivery()
                return
            elif pck['type'] == 'PROBE_ROUTER':
                self.send_heart_beat()  # advertise router on probe
                log_delivery()
                return
            elif pck['type'] == 'JOIN_REQ':
                # only accept JOIN_REQ if we appear to be the only option (no other CH/ROOT neighbors)
                other_heads = [
                    addr for addr, entry in self.neighbors_table.items()
                    if entry is not None
                    and addr != self.parent_address
                    and entry.hops == 1
                    and entry.role in (Roles.CLUSTER_HEAD, Roles.ROOT)
                ]
                # if other_heads:
                #     self.log(f'JOIN_REQ ignored at router; nearby CH/ROOT neighbors present: {other_heads}')
                #     log_delivery()
                #     return

                if pck.get('uid') is not None and pck['uid'] not in self.received_JR_guis:
                    self.received_JR_guis.append(pck['uid'])
                self.send_network_req() # if we get a join request as a CM, send network request to root
                log_delivery()
                return
            elif pck['type'] == 'NETID_RESP':
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
                    self.promotion_completed_at = self.now  # track promotion time
                    self.send_heart_beat() # send hb as new CH

                    # register downstream CH as a member and send JOIN_ACK
                    if self.downstream_ch_addr is not None and self.downstream_ch_gui is not None:
                        downstream_addr = wsn.Addr(self.ch_addr.net_addr, 254)
                        member_entry = MemberTableEntry(
                            uid=self.downstream_ch_gui,
                            renewal_valid=True,
                            ack_seq_no=-1,
                            expiry_time=self.now + config.MEMBER_STALE_INTERVAL
                        )
                        self.members_table[downstream_addr] = member_entry
                        self.send_join_ack({'uid': self.downstream_ch_gui, 'distance': 0})

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
                    self.promotion_completed_at = self.now  # track promotion time (prevents cascading failures)
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
                # if we get a join ack as a regular member and it is for us become become unregistered
                if pck['target_uid'] == self.id and not pck.get('promoted_reg', True):
                    # only honor demotion from our current parent
                    if self.parent_address is not None and pck.get('src_addr') != self.parent_address:
                        self.log(f'JOIN_ACK demotion ignored from non-parent {pck.get("src_addr")} (parent {self.parent_address})')
                        log_delivery()
                        return
                    self.log('RN becoming unregistered due to demoted JOIN_ACK')
                    self.become_unregistered(preserve_neighbors=False)
                    log_delivery()
                    return


        # undiscovered node case
        elif self.role == Roles.UNDISCOVERED:
            if pck['type'] == 'HEART_BEAT':  # kills probe timer, becomes unregistered and sets join request timer on received heart beat
                self.update_routing_info(pck)
                self.kill_timer('TIMER_PROBE')
                self.become_unregistered(preserve_neighbors=True)
                log_delivery()
                return

        # Unregistered node case
        elif self.role == Roles.UNREGISTERED:
            if pck['type'] == 'HEART_BEAT':
                self.update_routing_info(pck) # update neighbor table on received heart beat
                log_delivery()
                return

            if pck['type'] == 'JOIN_ACK':
                self.log(f'JOIN_ACK rx from {pck.get("src_addr")}, target_uid={pck.get("target_uid")}, assigned addr={pck.get("cm_addr")}')
                if pck['target_uid'] == self.id:
                    # validate address and uid matches what we expect
                    src_addr = pck.get('src_addr')
                    src_uid = pck.get('uid')
                    valid_by_addr = src_addr in (self.last_join_target, self.parent_address)
                    valid_by_uid = self.last_join_target_uid is not None and src_uid == self.last_join_target_uid

                    if self.last_join_target is not None and not valid_by_addr and not valid_by_uid:
                        self.log(f'JOIN_ACK ignored from non-target parent {src_addr} uid={src_uid} (expected addr={self.last_join_target}, uid={self.last_join_target_uid})')
                        log_delivery()
                        return

                    # did we get accepted?
                    if not pck['promoted_reg'] or pck['cm_addr'] is None:
                        if self.last_join_target is None or pck.get('src_addr') == self.last_join_target:
                            self.log(f'JOIN_ACK received but not accepted (promoted_reg={pck.get("promoted_reg")}, cm_addr={pck.get("cm_addr")})')
                            self.mark_join_rejected(pck.get('src_addr'))
                            self.last_join_target = None
                            self.last_join_target_uid = None
                            self.last_join_time = 0
                        else:
                            self.log(f'JOIN_ACK rejection ignored from non-target {pck.get("src_addr")} (expected {self.last_join_target})')
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
                    self.last_join_target_uid = None
                    self.last_join_time = 0

                    # update role
                    if self.ch_addr is not None:
                        self.set_role(Roles.CLUSTER_HEAD)
                    else:
                        self.set_role(Roles.REGISTERED)
                        self.last_registered_at = self.now  # track rejoin time for cooldown

                    log_delivery()
                    return

        # record delivery if we reach here
        log_delivery()

    # timer handlers
    def on_timer_fired(self, name, *args, **kwargs):
        if name == 'TIMER_ARRIVAL':  # wakes up and set timer probe once time arrival timer fired
            self.scene.nodecolor(self.id, 1, 0, 0)  # sets self color to red
            if self.id not in JOIN_START_TIMES:
                JOIN_START_TIMES[self.id] = self.now
            self.wake_up()
            self.set_timer('TIMER_PROBE', 1)

        elif name == 'TIMER_PROBE':  # sends probe if counter didn't reach the threshold on timer probe
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
                    self.hops_to_root = 0
                    self.log(f'ROOT online id={self.id}, addr={self.addr}, tx_range={self.tx_range}, max_children={config.SIM_MAX_CHILDREN}, max_networks={config.SIM_MAX_NETWORKS}')
                    self.send_heart_beat()  # advertise immediately
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                else:  # otherwise it keeps trying to sending probe after a long time
                    self.c_probe = 0
                    self.set_timer('TIMER_PROBE', 30)

        elif name == 'TIMER_HEART_BEAT':  # sends heart beat and performs periodic maintenance
            self.send_heart_beat()
            self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)

            # perform table maintenance every 5 heartbeats
            self.heartbeat_counter += 1
            if self.heartbeat_counter >= 5:
                self.maintain_tables()
                self.heartbeat_counter = 0

        # CH send keepalive timer
        elif name == 'TIMER_CH_KEEPALIVE':
            if self.role == Roles.CLUSTER_HEAD:
                if self.ch_addr is not None:
                    self.send_child_network_keepalive()
                self.set_timer('TIMER_CH_KEEPALIVE', config.CH_KEEPALIVE_INTERVAL)

        # check if we can make ourselves a router periodically
        elif name == 'TIMER_ROUTERABLE_CHECK':
            if self.role == Roles.CLUSTER_HEAD and config.ENABLE_ROUTERS:
                self.attempt_member_promotion(post_role='router')
            self.set_timer('TIMER_ROUTERABLE_CHECK', config.ROUTERABLE_CHECK_INTERVAL)

        # join request timer, resend join request every now and thenm
        elif name == 'TIMER_JOIN_REQ':
            # if we don't have any neighbors and not unregistered become unregistered
            if len(self.neighbors_table) == 0 and self.role != Roles.UNREGISTERED:
                self.become_unregistered()
            # otherwise select and join
            else:
                self.select_and_join()

        # send sensor data packet
        elif name == 'TIMER_SENSOR':
            if self.addr is not None or self.ch_addr is not None:
                if config.SENSOR_DATA_TO_ROOT:
                    # send to root
                    dst_addr = wsn.Addr(1, 254)
                else:
                    # find random valid destination
                    valid_destinations = [
                        n for n in ALL_NODES
                        if n.id != self.id
                        and getattr(n, 'is_alive', True)
                        and n.addr is not None
                        and n.role in (Roles.ROOT, Roles.CLUSTER_HEAD, Roles.REGISTERED, Roles.ROUTER)
                    ]
                    if valid_destinations:
                        target_node = random.choice(valid_destinations)
                        dst_addr = target_node.ch_addr if target_node.ch_addr else target_node.addr
                    else:
                        dst_addr = None

                if dst_addr:
                    pck, _ = self.build_common_packet('DATA', ack=False, dst_addr=dst_addr)
                    pck.update({'payload': random.uniform(10, 50)})
                    DATA_PACKETS_SENT[0] += 1
                    self.route_and_forward_package(pck)

            # schedule next timer
            timer_duration = self.id % config.SENSOR_BASE_INTERVAL
            if timer_duration == 0:
                timer_duration = 1
            timer_duration += random.uniform(0, 1)
            self.set_timer('TIMER_SENSOR', timer_duration)

        # export clusterhead distances csv
        elif name == 'TIMER_EXPORT_CH_CSV':
            if self.role == Roles.ROOT:
                write_clusterhead_distances_csv()
                # reschedule
                self.set_timer('TIMER_EXPORT_CH_CSV', config.EXPORT_CH_CSV_INTERVAL)

        # export neighbor distances csv
        elif name == 'TIMER_EXPORT_NEIGHBOR_CSV':
            if self.role == Roles.ROOT:
                # write_neighbor_distances_csv("neighbor_distances.csv")
                self.set_timer('TIMER_EXPORT_NEIGHBOR_CSV', config.EXPORT_NEIGHBOR_CSV_INTERVAL)
