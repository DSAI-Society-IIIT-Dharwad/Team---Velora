"""
cycledetector.py
----------------
Detects circular permission chains in the cluster graph using DFS.

A cycle in the graph means two or more resources mutually grant each
other permissions — e.g. service-a grants admin to service-b, which
grants admin back to service-a. This is a critical misconfiguration.

Key functions:
  find_cycles(G)           -> list of all unique cycles
  format_cycle_report(...)  -> human-readable report string
"""

import networkx as nx
from graphparser import get_node_name


def find_cycles(G: nx.DiGraph) -> list:
    """
    Find all unique cycles in the directed graph using DFS.

    Uses Johnson's algorithm (via NetworkX) which finds all simple
    cycles without duplicates. A simple cycle visits each node at
    most once. Cycles are normalised so A->B->A and B->A->B are
    not reported twice.

    Args:
        G: Directed graph from graphparser.load_graph()

    Returns:
        List of cycle dicts, each containing:
          nodes       (list) - ordered node IDs in the cycle
          node_names  (list) - ordered human-readable names
          length      (int)  - number of nodes in the cycle
          edges       (list) - edge detail dicts (relationship, cve, cvss)
          relationships (list) - relationship labels around the cycle
    """
    raw_cycles = list(nx.simple_cycles(G))

    if not raw_cycles:
        return []

    # Normalise each cycle so we don't report duplicates.
    # Rotate each cycle to start from its lexicographically smallest node,
    # then deduplicate.
    seen    = set()
    results = []

    for cycle in raw_cycles:
        if len(cycle) < 2:
            continue  # self-loops are not meaningful here

        normalised = _normalise_cycle(cycle)
        key        = tuple(normalised)

        if key in seen:
            continue
        seen.add(key)

        edges = _extract_cycle_edges(G, normalised)

        results.append({
            "nodes":         normalised,
            "node_names":    [get_node_name(G, n) for n in normalised],
            "length":        len(normalised),
            "edges":         edges,
            "relationships": [e["relationship"] for e in edges],
        })

    # Sort by cycle length ascending (shorter cycles first)
    results.sort(key=lambda c: c["length"])
    return results


def format_cycle_report(cycles: list) -> str:
    """
    Format cycle detection results into a readable report section.

    Matches the style used in sample-output.txt:
      Cycle #1: node-a <-> node-b <-> node-a
      Relationship: admin-grant -> admin-grant

    Args:
        cycles: List of cycle dicts from find_cycles()

    Returns:
        Formatted multi-line string
    """
    if not cycles:
        return "  No circular permissions detected.\n"

    lines = []
    for i, cycle in enumerate(cycles, 1):
        names    = cycle["node_names"]
        rels     = cycle["relationships"]

        # Build the  A <-> B <-> A  display string
        cycle_display = " \u21a4 ".join(names) + f" \u21a4 {names[0]}"

        lines.append(f"  Cycle #{i}: {cycle_display}")
        lines.append(f"  Relationships: {' -> '.join(rels)}")

        # Remediation advice
        if cycle["edges"]:
            first_edge = cycle["edges"][0]
            lines.append(
                f"  \u26a0  Fix: revoke '{first_edge['relationship']}' "
                f"from {first_edge['src_name']} to {first_edge['tgt_name']} "
                f"to break this cycle."
            )
        lines.append("")

    return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _normalise_cycle(cycle: list) -> list:
    """
    Rotate a cycle list so it starts from its lexicographically
    smallest element. This ensures A->B->C and B->C->A are treated
    as the same cycle.
    """
    min_idx = cycle.index(min(cycle))
    return cycle[min_idx:] + cycle[:min_idx]


def _extract_cycle_edges(G: nx.DiGraph, cycle: list) -> list:
    """
    Build edge detail dicts for each hop in the cycle, including
    the closing edge back to the start.
    """
    edges   = []
    n       = len(cycle)

    for i in range(n):
        src = cycle[i]
        tgt = cycle[(i + 1) % n]  # wraps around to close the cycle

        if G.has_edge(src, tgt):
            edge_data = G.edges[src, tgt]
            edges.append({
                "src":          src,
                "src_name":     get_node_name(G, src),
                "tgt":          tgt,
                "tgt_name":     get_node_name(G, tgt),
                "relationship": edge_data.get("relationship", "unknown"),
                "weight":       edge_data.get("weight", 1.0),
                "cve":          edge_data.get("cve"),
                "cvss":         edge_data.get("cvss"),
            })

    return edges