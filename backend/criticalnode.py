"""
criticalnode.py
---------------
Identifies the single node whose removal eliminates the greatest
number of source-to-sink attack paths in the cluster graph.

Algorithm:
  1. Count baseline: all simple paths from every source to every sink
  2. For each candidate node (non-source, non-sink):
       - Copy the graph (never mutate the original)
       - Remove the candidate node
       - Recount all simple paths
       - Record how many paths were eliminated
  3. Rank candidates by paths eliminated, descending
  4. Return the top node + full ranking

Key functions:
  analyse(G)                  -> full critical node result dict
  format_critical_node_report -> human-readable report string
"""

import copy
import networkx as nx
from graphparser import get_sources, get_sinks, get_node_name

# Max path depth to avoid combinatorial explosion on large graphs
PATH_CUTOFF = 15


def analyse(G: nx.DiGraph) -> dict:
    """
    Find the node whose removal eliminates the most attack paths.

    Source nodes and sink nodes are excluded from candidates —
    removing them would be trivial and is not actionable.

    Args:
        G: Directed graph from graphparser.load_graph()

    Returns:
        dict with keys:
          baseline_paths  (int)  - total paths before any removal
          critical_node   (str)  - node ID of the best candidate
          critical_name   (str)  - human-readable name
          critical_type   (str)  - node type
          paths_eliminated (int) - paths eliminated by removing critical node
          ranking         (list) - top-5 candidates, sorted by impact
    """
    sources = set(get_sources(G))
    sinks   = set(get_sinks(G))

    # Baseline: count all simple paths from every source to every sink
    baseline = _count_all_paths(G, sources, sinks)

    # Candidates: every node that is neither a source nor a sink
    candidates = [
        n for n in G.nodes()
        if n not in sources and n not in sinks
    ]

    scores = []
    for node in candidates:
        # Copy the graph — never mutate the original
        G_copy = G.copy()
        G_copy.remove_node(node)

        remaining = _count_all_paths(G_copy, sources, sinks)
        eliminated = baseline - remaining

        scores.append({
            "node":       node,
            "name":       get_node_name(G, node),
            "type":       G.nodes[node].get("type", "Unknown"),
            "eliminated": eliminated,
            "remaining":  remaining,
        })

    # Sort by paths eliminated descending
    scores.sort(key=lambda s: s["eliminated"], reverse=True)

    top5    = scores[:5]
    best    = scores[0] if scores else None

    return {
        "baseline_paths":   baseline,
        "critical_node":    best["node"]      if best else None,
        "critical_name":    best["name"]      if best else None,
        "critical_type":    best["type"]      if best else None,
        "paths_eliminated": best["eliminated"] if best else 0,
        "ranking":          top5,
    }


def format_critical_node_report(result: dict) -> str:
    """
    Format the critical node analysis into a readable report section.

    Matches the style shown in sample-output.txt.

    Args:
        result: Dict from analyse()

    Returns:
        Formatted multi-line string
    """
    if not result["critical_node"]:
        return "  No candidates found for critical node analysis.\n"

    lines = []
    baseline = result["baseline_paths"]
    lines.append(f"  Baseline attack paths : {baseline}")
    lines.append("")
    lines.append(
        f"  \u2605  RECOMMENDATION:\n"
        f"     Remove permission binding '{result['critical_name']}' "
        f"({result['critical_type']}) to eliminate "
        f"{result['paths_eliminated']} of {baseline} attack paths."
    )
    lines.append("")
    lines.append("  Top 5 highest-impact nodes to remove:")

    for entry in result["ranking"]:
        bar_len  = int((entry["eliminated"] / max(baseline, 1)) * 20)
        bar      = "\u2588" * bar_len
        lines.append(
            f"    {entry['name']:<30} "
            f"({entry['type']:<15})  "
            f"-{entry['eliminated']} paths  {bar}"
        )

    lines.append("")
    return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _count_all_paths(G: nx.DiGraph, sources: set, sinks: set) -> int:
    """
    Count all simple paths from every source to every sink.

    Uses nx.all_simple_paths with a cutoff depth to keep runtime
    bounded on large graphs. The same cutoff is applied consistently
    for baseline and all candidate removals.
    """
    total = 0
    for src in sources:
        if src not in G:
            continue
        for sink in sinks:
            if sink not in G or sink == src:
                continue
            paths = nx.all_simple_paths(G, src, sink, cutoff=PATH_CUTOFF)
            total += sum(1 for _ in paths)
    return total