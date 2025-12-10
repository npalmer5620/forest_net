import sys
sys.path.insert(1, '.')
from source import config

import math
import random

from roles import Roles
from tracking_containers import NODE_POS, ALL_NODES, CLUSTER_HEADS, ROLE_COUNTS, ROOT_ID, PACKET_DELIVERY_LOGS
from sensor_node import SensorNode
from csv_utils import (
    write_node_distances_csv,
    write_node_distance_matrix_csv,
    write_join_times_csv,
    write_packet_deliveries_csv,
    write_node_tables_csv,
    get_average_join_time,
    get_join_time_stats,
)
from sim_main import sim
from time import perf_counter

FAILURE_DELAY = getattr(config, "KILL_TIME", config.NODE_ARRIVAL_MAX + 100)
NUM_FAILURES = max(int(getattr(config, "NODES_TO_KILL", 5)), 0)

def print_battery_report():
    if not ALL_NODES:
        return

    def to_mAh(n): return n.battery_mj / (config.BATTERY_VOLTAGE * 3600)

    levels = [(n, to_mAh(n)) for n in ALL_NODES
              if n.id != ROOT_ID and to_mAh(n) / config.BATTERY_CAPACITY_MAH > 0.01]
    total = sum(v for _, v in levels)
    avg = total / len(levels)

    min_node, min_mah = min(levels, key=lambda t: t[1])
    max_node, max_mah = max(levels, key=lambda t: t[1])

    to_pct = lambda mAh: (mAh / max(config.BATTERY_CAPACITY_MAH, 1e-9)) * 100

    print(f"Min bat: {min_mah:.2f} mAh ({to_pct(min_mah):.2f}%) - uid={min_node.id}, addr={getattr(min_node, 'addr', None)}")
    print(f"Max bat: {max_mah:.2f} mAh ({to_pct(max_mah):.2f}%) - uid={max_node.id}, addr={getattr(max_node, 'addr', None)}")
    print(f"Avg bat: {avg:.2f} mAh ({to_pct(avg):.2f}%)")


def create_network(node_class, number_of_nodes=100):
    edge = math.ceil(math.sqrt(number_of_nodes))
    for i in range(number_of_nodes):
        x = i / edge
        y = i % edge
        px = 50 + config.SCALE * x * config.SIM_NODE_PLACING_CELL_SIZE + random.uniform(
            -1 * config.SIM_NODE_PLACING_CELL_SIZE / 3, config.SIM_NODE_PLACING_CELL_SIZE / 3)
        py = 50 + config.SCALE * y * config.SIM_NODE_PLACING_CELL_SIZE + random.uniform(
            -1 * config.SIM_NODE_PLACING_CELL_SIZE / 3, config.SIM_NODE_PLACING_CELL_SIZE / 3)
        node = sim.add_node(node_class, (px, py))
        NODE_POS[node.id] = (px, py)
        ALL_NODES.append(node)
        node.tx_range = config.NODE_TX_RANGES[0] * config.SCALE
        node.logging = True
        node.arrival = random.uniform(0, config.NODE_ARRIVAL_MAX)
        if node.id == ROOT_ID:
            node.arrival = 0.1


def schedule_random_failure(delay=FAILURE_DELAY, num_failures=1):
    if num_failures <= 0:
        return

    def kill_multiple():
        candidates = [
            n for n in ALL_NODES
            if getattr(n, "role", None) in (Roles.CLUSTER_HEAD, Roles.ROUTER) and getattr(n, "is_alive", True)
        ]
        victims = random.sample(candidates, min(num_failures, len(candidates)))
        for victim in victims:
            victim.kill_all_timers()
            victim.is_alive = False
            victim.battery_mj = 0
            victim.sleep()
            try:
                victim.clear_tx_range()
            except Exception:
                pass
            try:
                victim.erase_parent()
            except Exception:
                pass
            victim.scene.nodecolor(victim.id, 0.5, 0.5, 0.5)
            role_name = getattr(victim, "role", Roles.UNDISCOVERED).name
            victim.log(f"removing {role_name} uid={victim.id} at t={sim.env.now:.2f}")

    sim.delayed_exec(delay, kill_multiple)


# creating random network
create_network(SensorNode, config.SIM_NODE_COUNT)
root_pos = NODE_POS.get(ROOT_ID)
print(f"root id={ROOT_ID}, pos={root_pos}, nodes={config.SIM_NODE_COUNT}, tx_ranges={config.NODE_TX_RANGES}")

# write initial node distances
write_node_distances_csv()
write_node_distance_matrix_csv()

# schedule removal of nodes after time to form
if NUM_FAILURES > 0:
    print(f"{NUM_FAILURES} node failure(s) at t={FAILURE_DELAY}")
    schedule_random_failure(num_failures=NUM_FAILURES)
else:
    print("node failures disabled (NODES_TO_KILL=0)")

if __name__ == "__main__":
    # start the simulation
    wall_start = perf_counter()
    sim.run()
    wall_elapsed = perf_counter() - wall_start
    print("done")
    expected_wall = config.SIM_DURATION * config.SIM_TIME_SCALE
    print(f"wall time: {wall_elapsed:.2f}s for sim duration={config.SIM_DURATION}s (timescale={config.SIM_TIME_SCALE},"
          f"expected ~{expected_wall:.2f}s)")

    # role counts
    summary = {r.name: ROLE_COUNTS.get(r, 0) for r in Roles}
    print(f"Final role counts: {summary}")

    # write join times and packet deliveries
    write_join_times_csv()
    write_packet_deliveries_csv()

    min_join, avg_join, max_join, joined_count = get_join_time_stats()
    if avg_join is None:
        print("no join times")
    else:
        print(
            f"join time stats ({joined_count} nodes): min={min_join:.4f}, "
            f"avg={avg_join:.4f}, max={max_join:.4f}"
        )
    print(f"packet deliveries logged: {len(PACKET_DELIVERY_LOGS)}")

    # battery life
    print_battery_report()

    # write node tables summary
    write_node_tables_csv()

    # Created 100 nodes at random locations with random arrival times.
    # When nodes are created they appear in white
    # Activated nodes becomes red
    # Discovered nodes will be yellow
    # Registered nodes will be green.
    # Root node will be black.
    # Routers/Cluster Heads should be blue
