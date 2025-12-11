## simulation properties
ENABLE_ROUTERS = True # enable routers
TREE_ONLY = False # use tree routing only
SIM_NODE_COUNT = 50 # node count in simulation
NEIGHBOR_HOP_LIMIT = 2 # max hops to keep in neighbor table
PACKET_LOSS_PROB = 0.01 # probability to drop a packet
SIM_MAX_CHILDREN = 253 # max children per cluster head [3, 253]
SIM_MAX_NETWORKS = 253 # max child networks [2, 253]
SENSOR_DATA_TO_ROOT = False # True=send to root, False=random node


# events
NODES_TO_KILL = 0 # number of nodes to kill during the kill event
KILL_DELAY = 50 # delay after NODE_ARRIVAL_MAX to kill nodes
NODES_REVIVE = False # bring killed nodes back?
REVIVE_DELAY = 100 # delay after kill before reviving nodes


# simulation misc
NODE_ARRIVAL_MAX = 50 # max time for nodes to wake at
SIM_NODE_PLACING_CELL_SIZE = 75 # cell size to place one node
SIM_DURATION = 1000 # simulation duration in seconds
SIM_TIME_SCALE = 0.01 # real time duration of 1 second simulation time
SIM_TERRAIN_SIZE = (650, 650) # terrain size
SIM_TITLE = 'ForestNet' # title of visualization window
SIM_VISUALIZATION = True # visualization active
SCALE = 1 # scale factor for visualization
VISUAL_DRAW_LINKS = True # toggle drawing of parent/router links
VISUAL_TIME_UPDATE_INTERVAL = 0.5
TRACE_PATHS = True
LOG_PDR_OVER_TIME = True # record PDR over time
PDR_LOG_INTERVAL = 5 # seconds between PDR samples


# energy tracking
BATTERY_CAPACITY_MAH = 1
# tx power mapped to ranges: {0: 8.5 mA, 1: 9.9 mA, 2: 14.0 mA, 3: 17.4 mA}
# energy per byte = (V * I * 8) / 250000
TX_ENERGY_PER_BYTE_UJ = [0.82, 0.95, 1.34, 1.67]
TX_OVERHEAD_UJ = 10.0
# rx at 18.8 mA (energy per byte = (3.0 * 18.8 * 8) / 250000 = 1.8 uJ/byte)
RX_ENERGY_PER_BYTE_UJ = 1.8


## network misc
CH_PROMOTE_TIMEOUT = 10 # how long we wait for a promotion response before retrying
HEARTH_BEAT_TIME_INTERVAL = 1 # heartbeat/parent check interval
MEMBER_STALE_INTERVAL = HEARTH_BEAT_TIME_INTERVAL * 3 # how long before a member is considered stale
PARENT_CHECK_INTERVAL = HEARTH_BEAT_TIME_INTERVAL * 3 # how often children check on parent
PARENT_STALE_INTERVAL = PARENT_CHECK_INTERVAL * 5 # parent considered dead after this
NETID_STALE_INTERVAL = PARENT_STALE_INTERVAL * 10 # how long before a child network id can be recycled
CH_KEEPALIVE_INTERVAL = HEARTH_BEAT_TIME_INTERVAL * 5 # CH sends keepalive to root for child network table refresh
EXPORT_CH_CSV_INTERVAL = 10 # simulation time units
EXPORT_NEIGHBOR_CSV_INTERVAL = 10 # simulation time units
JOIN_REJECT_BACKOFF = 5 # how long to wait before retrying a parent that denied join
TIMER_JOIN_REQ_INTERVAL = 1 # how often to resend join requests
SENSOR_BASE_INTERVAL = 0.1 # interval for sensor packets
ROUTERABLE_CHECK_INTERVAL = 10 # how often to check if node can become a router
TABLE_MAINT_INTERVAL = 2 # how often to check and maintain routing table
PARENT_SWITCH_HYSTERESIS = 0.01 # require % improvement in rx_cost to switch parents
REJOIN_COOLDOWN = 1 # seconds after rejoining before checking for better parents
BROADCAST_NET_ADDR = 255 # broadcast network address
BROADCAST_NODE_ADDR = 255 # broadcast node address
ROUTING_MAX_HOPS = 100 # hop limit to avoid routing loops
NODE_TX_RANGES = [25, 50, 75, 120]  # discrete tx ranges of nodes


def print_key_settings():
    print("simulation:")
    print(f"ENABLE_ROUTERS={ENABLE_ROUTERS}, TREE_ONLY={TREE_ONLY}, SENSOR_DATA_TO_ROOT={SENSOR_DATA_TO_ROOT}")
    print(f"NEIGHBOR_HOP_LIMIT={NEIGHBOR_HOP_LIMIT}, PACKET_LOSS_PROB={PACKET_LOSS_PROB}")
    print(f"SIM_MAX_CHILDREN={SIM_MAX_CHILDREN}, SIM_MAX_NETWORKS={SIM_MAX_NETWORKS}")
    print("events:")
    print(f"NODES_TO_KILL={NODES_TO_KILL}, KILL_DELAY={KILL_DELAY}, NODES_REVIVE={NODES_REVIVE}, REVIVE_DELAY={REVIVE_DELAY}")
    print("simulation scale:")
    print(f"SIM_NODE_COUNT={SIM_NODE_COUNT}, BATTERY_CAPACITY_MAH={BATTERY_CAPACITY_MAH}, CH_PROMOTE_TIMEOUT={CH_PROMOTE_TIMEOUT}")
