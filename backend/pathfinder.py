from collections import deque

def find_attack_path(graph_data: dict) -> list:
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]

    if not nodes:
        return []

    adjacency = {n["id"]: [] for n in nodes}
    for edge in edges:
        src = edge["source"]
        tgt = edge["target"]
        if src in adjacency:
            adjacency[src].append(tgt)
        if tgt in adjacency:
            adjacency[tgt].append(src)

    node_map = {n["id"]: n for n in nodes}

    entry_candidates = [
        n for n in nodes
        if n["type"] in ["service", "pod"] and n["risk"] > 0
    ]
    if not entry_candidates:
        entry_candidates = nodes

    entry = max(entry_candidates, key=lambda n: n["risk"])

    target_candidates = [
        n for n in nodes
        if n["type"] in ["secret", "rbac"] and n["id"] != entry["id"]
    ]
    if not target_candidates:
        target_candidates = [n for n in nodes if n["id"] != entry["id"]]

    if not target_candidates:
        return [entry["id"]]

    target = max(target_candidates, key=lambda n: n["risk"])

    queue = deque([[entry["id"]]])
    visited = {entry["id"]}

    while queue:
        path = queue.popleft()
        current = path[-1]
        if current == target["id"]:
            return path
        for neighbor in adjacency.get(current, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])

    return [entry["id"], target["id"]]


def calculate_blast_radius(graph_data: dict, node_id: str, hops: int = 2) -> dict:
    """
    From a given node, find all reachable nodes within N hops.
    Returns reachable node ids + per-node hop distance + total risk exposure.
    """
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]

    adjacency = {n["id"]: [] for n in nodes}
    for edge in edges:
        src = edge["source"]
        tgt = edge["target"]
        if src in adjacency:
            adjacency[src].append(tgt)
        if tgt in adjacency:
            adjacency[tgt].append(src)

    node_map = {n["id"]: n for n in nodes}

    # BFS up to N hops
    visited   = {node_id: 0}
    queue     = deque([(node_id, 0)])
    reachable = {}

    while queue:
        current, depth = queue.popleft()
        if depth >= hops:
            continue
        for neighbor in adjacency.get(current, []):
            if neighbor not in visited:
                visited[neighbor] = depth + 1
                queue.append((neighbor, depth + 1))
                n = node_map.get(neighbor)
                if n:
                    reachable[neighbor] = {
                        "id":       neighbor,
                        "name":     n["name"],
                        "type":     n["type"],
                        "risk":     n["risk"],
                        "hop":      depth + 1,
                        "severity": n.get("severity", "LOW"),
                    }

    total_exposure = sum(r["risk"] for r in reachable.values())

    return {
        "origin":         node_id,
        "hops":           hops,
        "reachable":      list(reachable.values()),
        "total_exposure": min(total_exposure, 100),
        "count":          len(reachable),
    }


def trace_rbac_chains(graph_data: dict) -> list:
    """
    Find all ServiceAccount → RoleBinding → ClusterRole chains.
    Returns list of chains with cumulative risk.
    """
    nodes    = graph_data["nodes"]
    edges    = graph_data["edges"]
    node_map = {n["id"]: n for n in nodes}

    service_accounts = [n for n in nodes if n["type"] == "serviceaccount"]
    rbac_nodes       = [n for n in nodes if n["type"] == "rbac"]

    chains = []

    for sa in service_accounts:
        for rb in rbac_nodes:
            # Check if there's a path between them via edges
            chain_risk = sa["risk"] + rb["risk"]
            chains.append({
                "serviceaccount": sa["name"],
                "serviceaccount_id": sa["id"],
                "rbac":          rb["name"],
                "rbac_id":       rb["id"],
                "chain_risk":    min(chain_risk, 100),
                "severity":      "CRITICAL" if chain_risk >= 70
                                 else "HIGH" if chain_risk >= 40
                                 else "MEDIUM",
                "description":   f"{sa['name']} is bound to {rb['name']} — "
                                 f"grants elevated cluster permissions",
            })

    # Sort by chain risk descending
    chains.sort(key=lambda c: c["chain_risk"], reverse=True)
    return chains