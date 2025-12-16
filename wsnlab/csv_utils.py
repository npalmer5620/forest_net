import sys
sys.path.insert(1, '.')

import math
import csv
from pathlib import Path

from roles import Roles
from tracking_containers import *
from sim_main import sim
from source import config

# write node distances to csv
def write_node_distances_csv(path="logs/node_distances.csv"):
    # write distances between nodes in NODE_POS
    ids = sorted(NODE_POS.keys())
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source_id", "target_id", "distance"])
        for i, sid in enumerate(ids):
            x1, y1 = NODE_POS[sid]
            for tid in ids[i + 1:]:  # i+1 to avoid duplicates and self-pairs
                x2, y2 = NODE_POS[tid]
                dist = math.hypot(x1 - x2, y1 - y2)
                w.writerow([sid, tid, f"{dist:.6f}"])

# write node distance matrix to csv
def write_node_distance_matrix_csv(path="logs/node_distance_matrix.csv"):
    ids = sorted(NODE_POS.keys())
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id"] + ids)
        for sid in ids:
            x1, y1 = NODE_POS[sid]
            row = [sid]
            for tid in ids:
                x2, y2 = NODE_POS[tid]
                dist = math.hypot(x1 - x2, y1 - y2)
                row.append(f"{dist:.6f}")
            w.writerow(row)

# write clusterhead distances to csv
def write_clusterhead_distances_csv(path="logs/clusterhead_distances.csv"):
    clusterheads = []
    for node in sim.nodes:
        # only nodes that are cluster heads and have positions
        if hasattr(node, "role") and node.role == Roles.CLUSTER_HEAD and node.id in NODE_POS:
            x, y = NODE_POS[node.id]
            clusterheads.append((node.id, x, y))

    if len(clusterheads) < 2:
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(["clusterhead_1", "clusterhead_2", "distance"])
        return

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["clusterhead_1", "clusterhead_2", "distance"])
        for i, (id1, x1, y1) in enumerate(clusterheads):
            for id2, x2, y2 in clusterheads[i + 1:]:
                dist = math.hypot(x1 - x2, y1 - y2)
                w.writerow([id1, id2, f"{dist:.6f}"])

# write join times to csv
def write_join_times_csv(path="logs/join_times.csv"):
    node_ids = sorted(set(JOIN_START_TIMES.keys()) | set(JOIN_COMPLETE_TIMES.keys()))
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id", "join_start_time", "join_complete_time", "join_latency"])
        for nid in node_ids:
            start = JOIN_START_TIMES.get(nid)
            end = JOIN_COMPLETE_TIMES.get(nid)
            latency = end - start if start is not None and end is not None else None
            w.writerow([
                nid,
                f"{start:.6f}" if start is not None else "",
                f"{end:.6f}" if end is not None else "",
                f"{latency:.6f}" if latency is not None else "",
            ])

# get average join time for all non-root nodes that completed join
def get_average_join_time():
    durations = []
    for nid, end_time in JOIN_COMPLETE_TIMES.items():
        if nid == ROOT_ID:  # skip root
            continue
        start_time = JOIN_START_TIMES.get(nid)
        if start_time is None:
            continue
        durations.append(end_time - start_time)

    if not durations:
        return None, 0

    return sum(durations) / len(durations), len(durations)

# get min, avg, max, count of join times (skip root)
def get_join_time_stats():
    durations = []
    for nid, end_time in JOIN_COMPLETE_TIMES.items():
        if nid == ROOT_ID:
            continue
        start_time = JOIN_START_TIMES.get(nid)
        if start_time is None:
            continue
        durations.append(end_time - start_time)

    if not durations:
        return None, None, None, 0

    return min(durations), sum(durations) / len(durations), max(durations), len(durations)

# write packet delivery logs
def write_packet_deliveries_csv(path="logs/packet_deliveries.csv"):
    entries = list(PACKET_DELIVERY_LOGS)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "seq_no",
            "packet_type",
            "origin_uid",
            "dst_addr",
            "final_uid",
            "created_time",
            "delivered_time",
            "delay",
            "hop_count",
            "path",
            "path_dynamic",
        ])

        # write entries for packet delivery logs
        for entry in entries:
            path_list = entry.get("path", [])
            path_str = "->".join(str(x) for x in path_list) if path_list else ""
            path_dynamic_list = entry.get("path_dynamic", [])
            path_dynamic_str = "->".join(str(x) for x in path_dynamic_list) if path_dynamic_list else ""
            w.writerow([
                entry.get("seq_no"),
                entry.get("type"),
                entry.get("src_uid"),
                entry.get("dst"),
                entry.get("final_uid"),
                f"{entry.get('created', 0):.6f}" if entry.get("created") is not None else "",
                f"{entry.get('delivered', 0):.6f}" if entry.get("delivered") is not None else "",
                f"{entry.get('delay', 0):.6f}" if entry.get("delay") is not None else "",
                entry.get("hop_count"),
                path_str,
                path_dynamic_str,
            ])

# cumulative PDR over time
def write_pdr_over_time_csv(path="logs/pdr_over_time.csv"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "sent", "delivered", "pdr_pct", "packet_loss_prob", "tree_only"])
        for sample_time, sent, delivered, pdr in PDR_SAMPLES:
            w.writerow([f"{sample_time:.6f}", sent, delivered, f"{pdr:.4f}", f"{config.PACKET_LOSS_PROB}", config.TREE_ONLY])

def write_connectivity_over_time_csv(path="logs/connectivity_over_time.csv"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "connected", "alive", "connectivity_pct", "e0_mah", "traffic_interval", "tree_only"])
        for sample_time, connected, alive, conn_pct, e0, traffic in CONNECTIVITY_SAMPLES:
            w.writerow([f"{sample_time:.6f}", connected, alive, f"{conn_pct:.4f}", f"{e0:.4f}", f"{traffic:.4f}", config.TREE_ONLY])

def write_node_deaths_csv(path="logs/node_deaths.csv"):
    from tracking_containers import NODE_DEATHS
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id", "death_time", "primary_role", "e0_mah"])
        for node_id, death_time, primary_role in NODE_DEATHS:
            role_name = primary_role.name if hasattr(primary_role, 'name') else str(primary_role)
            w.writerow([node_id, f"{death_time:.6f}", role_name, f"{config.BATTERY_CAPACITY_MAH:.4f}"])

# format address for output
def format_addr(addr):
    if addr is None:
        return ""
    if hasattr(addr, 'net_addr') and hasattr(addr, 'node_addr'):
        return f"{addr.net_addr}.{addr.node_addr}"
    return str(addr)

# write node tables summary to csv
def write_node_tables_csv(path="logs/node_tables.csv"):
    nodes = sorted(ALL_NODES, key=lambda n: n.id)

    def get_battery_pct(node):
        battery_mj = getattr(node, "battery_mj", 0)
        mah = battery_mj / (3.0 * 3600)
        return (mah / max(config.BATTERY_CAPACITY_MAH, 1e-9)) * 100

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id", "role", "addr", "ch_addr", "battery_pct", "downstream_ch_addr", "neighbors", "members", "child_networks"])

        for node in nodes:
            node_id = node.id
            is_alive = getattr(node, "is_alive", True)
            role = getattr(node, "role", None)

            # if dead mark killed
            if not is_alive:
                role_name = "KILLED"
                addr = ""
                ch_addr = ""
                battery_pct = ""
                downstream_ch_addr = ""
                neighbors_str = ""
                members_str = ""
                child_nets_str = ""
            else:
                role_name = role.name if role else "UNKNOWN"
                addr = format_addr(getattr(node, "addr", None))
                ch_addr = format_addr(getattr(node, "ch_addr", None))
                battery_pct = f"{get_battery_pct(node):.2f}"

                # downstream CH addr for routers
                if role == Roles.ROUTER:
                    downstream_ch_addr = format_addr(getattr(node, "downstream_ch_addr", None))
                else:
                    downstream_ch_addr = ""

                neighbors_table = getattr(node, "neighbors_table", {})
                neighbors_str = str([
                    (format_addr(addr_key), entry.role.name if entry.role else "?", entry.hops)
                    for addr_key, entry in neighbors_table.items()
                ])

                # members
                if role in (Roles.CLUSTER_HEAD, Roles.ROOT):
                    members_table = getattr(node, "members_table", {})
                    members_str = str([
                        (format_addr(addr_key), entry.uid)
                        for addr_key, entry in members_table.items()
                    ])
                else:
                    members_str = "[]"

                # child networks
                if role in (Roles.CLUSTER_HEAD, Roles.ROOT):
                    child_networks_table = getattr(node, "child_networks_table", {})
                    child_nets_str = str([
                        (net_id, format_addr(entry.next_hop_addr), entry.net_state)
                        for net_id, entry in child_networks_table.items()
                    ])
                else:
                    child_nets_str = "[]"

            w.writerow([node_id, role_name, addr, ch_addr, battery_pct, downstream_ch_addr, neighbors_str, members_str, child_nets_str])
