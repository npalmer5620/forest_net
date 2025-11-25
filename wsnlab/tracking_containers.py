import sys
sys.path.insert(1, '.')

import random
from source import config
from collections import Counter, deque

NODE_POS = {}  # {node_id: (x, y)}
ALL_NODES = []  # node objects
CLUSTER_HEADS = []
ROLE_COUNTS = Counter()  # role counts
ROOT_ID = random.randrange(config.SIM_NODE_COUNT)  # random root node id

# logs
JOIN_START_TIMES = {}  # node_id -> time when it started join process
JOIN_COMPLETE_TIMES = {} # node_id -> time when it completed join process
PACKET_DELIVERY_LOGS = deque()
