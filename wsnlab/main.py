import sys
sys.path.insert(1, '.')
from source import config

import math
import random
import statistics
from collections import defaultdict

from roles import Roles
from tracking_containers import NODE_POS, ALL_NODES, CLUSTER_HEADS, ROLE_COUNTS, ROOT_ID, PACKET_DELIVERY_LOGS, DATA_PACKETS_SENT, DATA_PACKETS_DELIVERED, ROLE_HISTORY
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

KILL_DELAY = getattr(config, "KILL_DELAY", 50)
KILL_TIME = config.NODE_ARRIVAL_MAX + KILL_DELAY
NUM_FAILURES = max(int(getattr(config, "NODES_TO_KILL", 5)), 0)

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


def schedule_random_failure(delay=KILL_TIME, num_failures=1):
    if num_failures <= 0:
        return

    killed_nodes = [] # store (node, battery_before)

    def kill_multiple():
        candidates = [
            n for n in ALL_NODES
            if getattr(n, "role", None) in (Roles.REGISTERED, Roles.CLUSTER_HEAD, Roles.ROUTER) and getattr(n, "is_alive", True)
        ]
        victims = random.sample(candidates, min(num_failures, len(candidates)))
        for victim in victims:
            # store battery level before kill
            killed_nodes.append((victim, victim.battery_mj))
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

        # schedule revival if enabled
        if getattr(config, "NODES_REVIVE", False) and killed_nodes:
            revive_delay = getattr(config, "REVIVE_DELAY", 50)
            sim.delayed_exec(revive_delay, revive_nodes)

    def revive_nodes():
        for node, battery_before in killed_nodes:
            node.is_alive = True
            node.battery_mj = battery_before
            node.wake_up() # wake up node
            node.become_unregistered()
            node.log(f"revived uid={node.id} at t={sim.env.now:.2f}")

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
    revive_info = ""
    if getattr(config, "NODES_REVIVE", False):
        revive_delay = getattr(config, "REVIVE_DELAY", 50)
        revive_info = f", revive at t={KILL_TIME + revive_delay}"
    print(f"{NUM_FAILURES} node failure(s) at t={KILL_TIME}{revive_info}")
    schedule_random_failure(num_failures=NUM_FAILURES)
else:
    print("node failures disabled (NODES_TO_KILL=0)")

if __name__ == "__main__":
    # start the simulation
    wall_start = perf_counter()
    sim.run()
    wall_elapsed = perf_counter() - wall_start
    print(f"done at sim_time={sim.env.now:.2f}s")
    expected_wall = config.SIM_DURATION * config.SIM_TIME_SCALE
    print(f"wall time: {wall_elapsed:.2f}s for sim duration={config.SIM_DURATION}s (timescale={config.SIM_TIME_SCALE},"
          f"expected ~{expected_wall:.2f}s)")

    # role counts
    summary = {r.name: ROLE_COUNTS.get(r, 0) for r in Roles}
    print(f"final role counts: {summary}")

    # write join times and packet deliveries
    write_join_times_csv()
    write_packet_deliveries_csv()

    min_join, avg_join, max_join, joined_count = get_join_time_stats()
    if avg_join is None:
        print("no join times")
    else:
        print(f"join time ({joined_count} nodes): min={min_join:.4f}, avg={avg_join:.4f}, max={max_join:.4f}")
    
    # pdr calculation
    delivered = DATA_PACKETS_DELIVERED[0]
    sent = DATA_PACKETS_SENT[0]
    if sent > 0:
        pdr = (delivered / sent) * 100
        print(f"pdr: {pdr:.2f}% ({delivered} delivered/{sent} sent)")

    # end to end delay
    delays = [e['delay'] for e in PACKET_DELIVERY_LOGS if e.get('type') == 'DATA' and e.get('delay') is not None]
    if len(delays) >= 2:
        mean_delay = statistics.mean(delays)
        std_delay = statistics.stdev(delays)
        print(f"e2e delay: mean={mean_delay:.4f}s, std={std_delay:.4f}s (n={len(delays)})")

    # connectivity
    connected_roles = (Roles.ROOT, Roles.REGISTERED, Roles.CLUSTER_HEAD, Roles.ROUTER)
    connected = [n for n in ALL_NODES if getattr(n, 'is_alive', True) and getattr(n, 'role', None) in connected_roles]
    alive = sum(1 for n in ALL_NODES if getattr(n, 'is_alive', True))
    if alive > 0:
        print(f"connectivity: {len(connected)/alive*100:.2f}% ({len(connected)}/{alive} nodes)")

    # average hops to root
    hops = [getattr(n, 'hops_to_root', 99999) for n in connected if getattr(n, 'role', None) != Roles.ROOT and getattr(n, 'hops_to_root', 99999) < 99999]
    if hops:
        print(f"avg hops to root: {sum(hops)/len(hops):.2f} (n={len(hops)})")

    # finalize roles
    for node in ALL_NODES:
        role = getattr(node, 'role', None)
        if role is not None and hasattr(node, 'battery_mj'):
            time_in_role = sim.env.now - getattr(node, 'role_start_time', sim.env.now)
            battery_mj = getattr(node, 'battery_mj', 0)
            energy_consumed = getattr(node, 'role_start_battery', battery_mj) - battery_mj
            if node.id not in ROLE_HISTORY:
                ROLE_HISTORY[node.id] = []
            # append role history since sim is over
            ROLE_HISTORY[node.id].append((role, time_in_role, energy_consumed))

    # energy by role
    role_stats = defaultdict(lambda: {'time': 0, 'energy': 0, 'count': 0})
    for node_id, history in ROLE_HISTORY.items():
        for role, time_in_role, energy_consumed in history:
            role_stats[role]['time'] += time_in_role
            role_stats[role]['energy'] += energy_consumed
            role_stats[role]['count'] += 1

    print("\nenergy used by role:")
    for role in Roles:
        if role not in role_stats:
            continue
        stats = role_stats[role]
        if stats['time'] > 0:
            total_energy_mj = stats['energy']
            total_energy_j = total_energy_mj / 1000

            # avg power consumption in mW
            avg_power_mw = stats['energy'] / stats['time'] * 1000
            battery_capacity_mj = config.BATTERY_CAPACITY_MAH * 3.0 * 3600

            # estimate lifetime based on avg power consumption
            est_lifetime = battery_capacity_mj / (avg_power_mw / 1000) if avg_power_mw > 0 else float('inf')
            print(f"{role.name}: {total_energy_j:.3f}J, est_lifetime={str(est_lifetime)}")

    # compute average battery remaining by role
    role_batteries = defaultdict(list)
    for node in ALL_NODES:
        if getattr(node, 'is_alive', True) and node.id != ROOT_ID and hasattr(node, 'battery_mj'):
            role = getattr(node, 'role', None)
            if role is not None:
                battery_mah = node.battery_mj / (3.0 * 3600)
                role_batteries[role].append(battery_mah)

    print("\navg battery remaining by role:")
    for role in Roles:
        if role not in role_batteries:
            continue
        batteries = role_batteries[role]
        if batteries:
            avg_bat = sum(batteries) / len(batteries)
            pct = (avg_bat / config.BATTERY_CAPACITY_MAH) * 100
            print(f"{role.name}: {avg_bat:.2f} mAh ({pct:.2f}%)")

    # write node tables summary
    write_node_tables_csv()

