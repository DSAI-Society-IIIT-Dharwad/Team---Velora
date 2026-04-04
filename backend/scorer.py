def score_graph(graph_data: dict) -> dict:
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]

    if not nodes:
        return {**graph_data, "cluster_risk": 0}

    # Boost risk for nodes connected to high-risk nodes
    node_map = {n["id"]: n for n in nodes}

    for edge in edges:
        source = node_map.get(edge["source"])
        target = node_map.get(edge["target"])

        if source and target:
            # If source is high risk, target gets a spillover boost
            if source["risk"] >= 40:
                target["risk"] = min(target["risk"] + 10, 100)
            if target["risk"] >= 40:
                source["risk"] = min(source["risk"] + 10, 100)

    # Assign severity label
    for node in nodes:
        r = node["risk"]
        if r >= 70:
            node["severity"] = "CRITICAL"
        elif r >= 40:
            node["severity"] = "HIGH"
        elif r >= 20:
            node["severity"] = "MEDIUM"
        elif r > 0:
            node["severity"] = "LOW"
        else:
            node["severity"] = "SAFE"

    # Cluster-wide risk = weighted average leaning toward top risks
    risks = sorted([n["risk"] for n in nodes], reverse=True)
    if len(risks) >= 3:
        cluster_risk = int((risks[0] * 0.5 + risks[1] * 0.3 + risks[2] * 0.2))
    elif len(risks) == 2:
        cluster_risk = int((risks[0] * 0.6 + risks[1] * 0.4))
    else:
        cluster_risk = risks[0] if risks else 0

    return {
        "nodes": nodes,
        "edges": edges,
        "cluster_risk": min(cluster_risk, 100)
    }