import sys

sys.path.insert(1, '.')
from source import wsnlab_vis as wsn
from dataclasses import dataclass
from roles import Roles

# Node Capabilities data class
@dataclass(frozen=True, slots=True)
class NodeCapabilities:
    CAPABLE_CLUSTER_HEAD: bool = True
    CAPABLE_ROUTER: bool = True
    CAPABLE_ROOT_NODE: bool = False
    CAPABLE_GATEWAY: bool = False
    joinable: bool = True

# Neighbor Table entry data class
@dataclass(slots=True)
class NeighborTableEntry: # indexed by dynamic address
    uid: int | None # uid of the neighbor node
    nextHopAddr: wsn.Addr # address of next hop to this entry (NET.NODE)
    hops: int  # hop count to reach this neighbor
    capabilities: NodeCapabilities | None  # capabilities of the neighbor
    role: Roles | None # role of the neighbor 
    lastHeard: float  # time of last heard from this neighbor
    rx_cost: float  # distance to next hop node
    path_cost: float | None = None  # cost to root advertised by this neighbor
    join_rejected_until: int = 0  # reject rejoin attempts until this time

# Member Table entry data class
@dataclass(slots=True)
class MemberTableEntry: # indexed by dynamic address
    uid: int  # uid of the member node
    renewal_valid: bool  # HIGH=Address renewal valid, LOW=Address renewal not valid (in progress)
    ack_seq_no: int  # last acknowledged sequence number for renewal
    expiry_time: float  # time until which the membership is valid

# Child Network Table entry data class
@dataclass(slots=True)
class ChildNetworkEntry: # indexed by network id
    next_hop_addr: wsn.Addr # address of next hop to child network
    hops: int # hop count to reach this child network
    net_state: str # state "VALID", "PENDING", "STALE"
    last_heard: float  # time of last heard from child network
    ack_seq_no: int  # seq number of NETID_RESP pending validation
    requester_uid: int  # uid of node requester/owner of child network
