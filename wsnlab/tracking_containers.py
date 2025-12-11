import sys
sys.path.insert(1, '.')

import random
from source import config
from collections import Counter, deque

NODE_POS = {} # {node_id: (x, y)}
ALL_NODES = [] # node objects
CLUSTER_HEADS = []
ROLE_COUNTS = Counter() # role counts
ROOT_ID = random.randrange(config.SIM_NODE_COUNT) # random root node id

# logs
JOIN_START_TIMES = {} # node_id -> time when it started join process
JOIN_COMPLETE_TIMES = {} # node_id -> time when it completed join process
PACKET_DELIVERY_LOGS = deque()
DATA_PACKETS_SENT = [0] # data packets generated
DATA_PACKETS_DELIVERED = [0] # data packets received at dst
ROLE_HISTORY = {} # node_id -> [(role, time_in_role, energy_consumed)]
PDR_SAMPLES = []  # (time, sent, delivered, pdr_pct)
