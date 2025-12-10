## network properties (broadcast addresses)
BROADCAST_NET_ADDR = 255
BROADCAST_NODE_ADDR = 255

## node properties
NODE_TX_RANGES = [25, 50, 75, 120]  # discrete tx ranges of nodes
NODE_ARRIVAL_MAX = 50  # max time to wake up (root will wake at 25)

## simulation properties
PACKET_LOSS_PROB = 0.00 # probability to drop a packet
SIM_MAX_CHILDREN = 253  # max children per cluster head [3, 253]
SIM_MAX_NETWORKS = 253  # max child networks [2, 253]
KILL_TIME = NODE_ARRIVAL_MAX + 50  # time to trigger forced node kill event
NODES_TO_KILL = 20  # number of nodes to kill during the kill event
SIM_NODE_COUNT = 50  # node count in simulation
SIM_NODE_PLACING_CELL_SIZE = 75  # cell size to place one node
SIM_DURATION = 1000  # simulation duration in seconds
SIM_TIME_SCALE = 0.2  # real time duration of 1 second simulation time
SIM_TERRAIN_SIZE = (650, 650)  # terrain size
SIM_TITLE = 'ForestNet'  # title of visualization window
SIM_VISUALIZATION = True  # visualization active
SCALE = 1  # scale factor for visualization
VISUAL_DRAW_LINKS = True  # toggle drawing of parent/router links
VISUAL_TIME_UPDATE_INTERVAL = 0.5
TRACE_PATHS = True

# battery tracking
BATTERY_CAPACITY_MAH = 5
BATTERY_VOLTAGE = 3.0
BATTERY_CAPACITY_MJ = BATTERY_CAPACITY_MAH * BATTERY_VOLTAGE * 3600
TX_ENERGY_PER_BYTE_UJ = [5.0, 7.25, 10.5, 15.67]  # epb for each tx range
TX_OVERHEAD_UJ = 100.0 # tx overhead
RX_ENERGY_PER_BYTE_UJ = 18.8 # rx epb
MIN_BATTERY_MJ = 0

## network params
ENABLE_ROUTERS = True  # enable routers
TREE_ONLY = True  # use tree routing only
CH_PROMOTE_TIMEOUT = 10 # how long we wait for a promotion response before retrying
HEARTH_BEAT_TIME_INTERVAL = 1 # heartbeat/parent check interval
MEMBER_STALE_INTERVAL = HEARTH_BEAT_TIME_INTERVAL * 3 # how long before a member is considered stale
PARENT_CHECK_INTERVAL = HEARTH_BEAT_TIME_INTERVAL * 3 # how often children check on parent
PARENT_STALE_INTERVAL = MEMBER_STALE_INTERVAL * 2  # parent considered dead after this
NETID_STALE_INTERVAL = PARENT_STALE_INTERVAL * 10  # how long before a child network id can be recycled
CH_KEEPALIVE_INTERVAL = HEARTH_BEAT_TIME_INTERVAL * 5  # CH sends keepalive to root for child network table refresh
EXPORT_CH_CSV_INTERVAL = 10  # simulation time units
EXPORT_NEIGHBOR_CSV_INTERVAL = 10  # simulation time units
ROUTING_MAX_HOPS = 100  # hop limit to avoid routing loops
JOIN_REJECT_BACKOFF = 5 # how long to wait before retrying a parent that denied join
TIMER_JOIN_REQ_INTERVAL = 1 # how often to resend join requests 
SENSOR_BASE_INTERVAL = 1  # interval for sensor packets
ROUTERABLE_CHECK_INTERVAL = 30  # how often to check if node can become a router
TABLE_MAINT_INTERVAL = 2  # how often to check and maintain routing table
PARENT_SWITCH_HYSTERESIS = 0.05  # require % improvement in rx_cost to switch parents
PROMOTION_GRACE_PERIOD = 30  # seconds to skip parent role checks after promotion
REJOIN_COOLDOWN = 1  # seconds after rejoining before checking for better parents
LINK_ACK_RETRY_INTERVAL = 0.2  # delay between retransmissions when waiting for a link ack
LINK_ACK_MAX_RETRIES = 3  # number of times to resend a packet if the link ack is not received