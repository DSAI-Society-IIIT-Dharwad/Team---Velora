"""
dijkstra.py
-----------
Finds shortest weighted attack paths in the cluster graph.

Uses Dijkstra's algorithm (via NetworkX) to find the minimum-cost
path from a source node to a target node, where cost = sum of edge
weights along the path.

Key functions:
  find_shortest_path(G, source, target)  -> single path result
  find_all_attack_paths(G)               -> all source-to-sink paths
"""

import heapq
import networkx as nx
from graphparser import get_sources, get_sinks, get_node_name


# Risk score thresholds for severity labels
SEVERITY_THRESHOLDS = {
    "CRITICAL": 20.0,
    "HIGH":     10.0,
    "MEDIUM":   5.0,
    "LOW":      0.0,
}


def find_shortest_path(G: nx.DiGraph, source: str, target: str) -> dict:
    """
    Find the shortest weighted path from source to target using Dijkstra.

    Edge weights represent traversal cost (higher = riskier / harder path).
    The risk score is the cumulative sum of edge weights along the path.

    Args:
        G:      Directed graph from graphparser.load_graph()
        source: Source node ID
        target: Target node ID

    Returns:
        dict with keys:
          found       (bool)   - whether a path exists
          path        (list)   - ordered list of node IDs
          path_names  (list)   - ordered list of human-readable node names
          hops        (int)    - number of edges traversed
          risk_score  (float)  - cumulative edge weight
          severity    (str)    - CRITICAL / HIGH / MEDIUM / LOW
          edges       (list)   - edge detail dicts with relationship/cve/cvss
          error       (str)    - set if found=False
    """
    if source not in G:
        return _no_path(f"Source node '{source}' not found in graph.")
    if target not in G:
        return _no_path(f"Target node '{target}' not found in graph.")

    try:
        path = nx.dijkstra_path(G, source, target, weight="weight")
        cost = nx.dijkstra_path_length(G, source, target, weight="weight")
    except nx.NetworkXNoPath:
        return _no_path(f"No path found from '{source}' to '{target}'.")
    except nx.NodeNotFound as e:
        return _no_path(str(e))

    edges = _extract_edge_details(G, path)
    risk  = round(cost, 1)

    return {
        "found":      True,
        "path":       path,
        "path_names": [get_node_name(G, n) for n in path],
        "hops":       len(path) - 1,
        "risk_score": risk,
        "severity":   _severity(risk),
        "edges":      edges,
        "error":      None,
    }


def find_all_attack_paths(G: nx.DiGraph) -> list:
    """
    Find shortest weighted paths from every source to every sink.

    Only paths that actually exist are included. Results are sorted
    by risk_score ascending (lowest cost first, matching rubric format).

    Args:
        G: Directed graph from graphparser.load_graph()

    Returns:
        List of path result dicts (same structure as find_shortest_path),
        sorted by risk_score ascending.
    """
    sources = get_sources(G)
    sinks   = get_sinks(G)
    results = []

    for src in sources:
        for sink in sinks:
            if src == sink:
                continue
            result = find_shortest_path(G, src, sink)
            if result["found"]:
                results.append(result)

    # Sort by risk score ascending (cheapest/shortest path first)
    results.sort(key=lambda r: r["risk_score"])

    # Add path numbers
    for i, r in enumerate(results, 1):
        r["path_number"] = i

    return results


def format_path_report(results: list) -> str:
    """
    Format a list of attack path results into the kill chain report style.

    Matches the exact format shown in the sample-output.txt:
      Path #N | M hops | Risk Score: X.X [SEVERITY]
      node-name (Type) --[relationship]--> next-node (Type) [CVE, CVSS X.X]
      ...

    Args:
        results: List of dicts from find_all_attack_paths()

    Returns:
        Formatted multi-line string
    """
    if not results:
        return "  No attack paths detected.\n"

    lines = []
    for r in results:
        lines.append(
            f"  Path #{r['path_number']}  |  {r['hops']} hops  "
            f"|  Risk Score: {r['risk_score']}  [{r['severity']}]"
        )
        lines.append("  " + "─" * 60)

        path  = r["path"]
        edges = r["edges"]

        for i, edge in enumerate(edges):
            src_name  = edge["src_name"]
            src_type  = edge["src_type"]
            tgt_name  = edge["tgt_name"]
            tgt_type  = edge["tgt_type"]
            rel       = edge["relationship"]
            cve_tag   = ""
            if edge["cve"]:
                cve_tag = f"  [{edge['cve']}, CVSS {edge['cvss']}]"

            lines.append(
                f"  {src_name} ({src_type})  "
                f"--[{rel}]-->  "
                f"{tgt_name} ({tgt_type}){cve_tag}"
            )

        lines.append("")

    return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_edge_details(G: nx.DiGraph, path: list) -> list:
    """
    Build a list of edge detail dicts for each hop in a path.
    Each dict contains source/target names, types, relationship, cve, cvss.
    """
    details = []
    for i in range(len(path) - 1):
        src, tgt  = path[i], path[i + 1]
        edge_data = G.edges[src, tgt]
        details.append({
            "src":          src,
            "src_name":     get_node_name(G, src),
            "src_type":     G.nodes[src].get("type", "Unknown"),
            "tgt":          tgt,
            "tgt_name":     get_node_name(G, tgt),
            "tgt_type":     G.nodes[tgt].get("type", "Unknown"),
            "relationship": edge_data.get("relationship", "unknown"),
            "weight":       edge_data.get("weight", 1.0),
            "cve":          edge_data.get("cve"),
            "cvss":         edge_data.get("cvss"),
        })
    return details


def _severity(risk_score: float) -> str:
    """Map a cumulative risk score to a severity label."""
    if risk_score >= SEVERITY_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if risk_score >= SEVERITY_THRESHOLDS["HIGH"]:
        return "HIGH"
    if risk_score >= SEVERITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def _no_path(reason: str) -> dict:
    """Return a standard 'not found' result dict."""
    return {
        "found":      False,
        "path":       [],
        "path_names": [],
        "hops":       0,
        "risk_score": 0.0,
        "severity":   "NONE",
        "edges":      [],
        "error":      reason,
    }