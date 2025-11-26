## network properties
BROADCAST_NET_ADDR = 255
BROADCAST_NODE_ADDR = 255

## node properties
NODE_TX_RANGES = [25, 50, 75, 120]  # discrete tx ranges of nodes
NODE_ARRIVAL_MAX = 50  # max time to wake up

## simulation properties
PACKET_LOSS_PROB = 0.0001 # probability to drop a packet
SIM_MAX_CHILDREN = 254  # max children per cluster head
SIM_MAX_NETWORKS = 253  # max child networks (2 through 254, root is 1)
SIM_NODE_COUNT = 50  # noce count in simulation
SIM_NODE_PLACING_CELL_SIZE = 75  # cell size to place one node
SIM_DURATION = 5000  # simulation Duration in seconds
SIM_TIME_SCALE = 0.1  #  The real time dureation of 1 second simualtion time
SIM_TERRAIN_SIZE = (1000, 1000)  #terrain size
SIM_TITLE = 'ForestNet'  # title of visualization window
SIM_VISUALIZATION = True  # visualization active
SCALE = 1  # scale factor for visualization
VISUAL_DRAW_LINKS = True  # toggle drawing of parent/router links
VISUAL_TIME_UPDATE_INTERVAL = 0.5
TRACE_PATHS = True

## params
CH_PROMOTE_TIMEOUT = 10
HEARTH_BEAT_TIME_INTERVAL = 1 # heartbeat/parent check interval
MEMBER_STALE_INTERVAL = HEARTH_BEAT_TIME_INTERVAL * 3 # how long before a member is considered stale
PARENT_CHECK_INTERVAL = HEARTH_BEAT_TIME_INTERVAL * 3 # how often children check on parent
PARENT_STALE_INTERVAL = MEMBER_STALE_INTERVAL * 10  # parent considered dead after this
EXPORT_CH_CSV_INTERVAL = 10  # simulation time units
EXPORT_NEIGHBOR_CSV_INTERVAL = 10  # simulation time units
ROUTING_MAX_HOPS = 20  # hop limit to avoid routing loops
JOIN_REJECT_BACKOFF = 10 # how long to wait before retrying a parent that denied join
TIMER_JOIN_REQ_INTERVAL = 1 # how often to resend join requests
SENSOR_BASE_INTERVAL = 10  # baseline interval for sensor reports
ROUTERABLE_CHECK_INTERVAL = 20  # how often to check if node can become a router
TABLE_MAINT_INTERVAL = 5  # how often to check and maintain routing table

# battery tracking
BATTERY_CAPACITY_MAH = 1000
BATTERY_VOLTAGE = 3.0
BATTERY_CAPACITY_MJ = BATTERY_CAPACITY_MAH * BATTERY_VOLTAGE * 3600
TX_ENERGY_PER_BYTE_UJ = [5.0, 7.25, 10.5, 15.67]  # epb for each tx range
TX_OVERHEAD_UJ = 100.0 # tx overhead
RX_ENERGY_PER_BYTE_UJ = 18.8 # rx epb
MIN_BATTERY_MJ = 0
