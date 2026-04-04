"""
graphparser.py
---------------
Parses cluster-graph.json into a NetworkX directed graph.

Expected JSON schema:
  {
    "nodes": [
      {
        "id":         str   - unique node identifier
        "type":       str   - e.g. Pod, Service, Secret, Role, ClusterRole,
                              ServiceAccount, User, ExternalActor, Database,
                              Node, Namespace, PersistentVolume, ConfigMap
        "name":       str   - human-readable display name
        "namespace":  str   - k8s namespace or "cluster" / "external"
        "risk_score": float - base risk score (0–10)
        "is_source":  bool  - true if this is a valid attack entry point
        "is_sink":    bool  - true if this is a target / high-value asset
        "cves":       list  - list of CVE IDs affecting this node
      }, ...
    ],
    "edges": [
      {
        "source":       str   - source node id
        "target":       str   - target node id
        "relationship": str   - e.g. "routes-to", "can-exec", "bound-to"
        "weight":       float - edge traversal cost (used by Dijkstra)
        "cve":          str|null - CVE on this edge (if any)
        "cvss":         float|null - CVSS score of edge CVE
      }, ...
    ]
  }
"""

import json
import networkx as nx


class GraphParseError(Exception):
    """Raised when the input file cannot be parsed into a valid graph."""
    pass


def load_graph(filepath: str) -> nx.DiGraph:
    """
    Load a cluster-graph.json file and return a NetworkX directed graph.

    All node and edge attributes from the JSON are stored on the graph
    so algorithms can access risk_score, is_source, is_sink, cves, weight,
    relationship, cve, and cvss directly.

    Args:
        filepath: Path to cluster-graph.json

    Returns:
        nx.DiGraph with all nodes and edges populated

    Raises:
        GraphParseError: if the file is missing, malformed, or has no nodes
        FileNotFoundError: if filepath does not exist
    """
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise GraphParseError(f"Invalid JSON: {e}") from e

    nodes = data.get("nodes")
    edges = data.get("edges")

    if not isinstance(nodes, list) or len(nodes) == 0:
        raise GraphParseError("JSON must contain a non-empty 'nodes' list.")
    if not isinstance(edges, list):
        raise GraphParseError("JSON must contain an 'edges' list.")

    G = nx.DiGraph()

    # --- Load nodes ---
    for node in nodes:
        if "comment" in node and len(node) == 1:
            continue  # skip comment-only entries

        node_id = node.get("id")
        if not node_id:
            continue  # skip malformed entries silently

        G.add_node(
            node_id,
            name=node.get("name", node_id),
            type=node.get("type", "Unknown"),
            namespace=node.get("namespace", "default"),
            risk_score=float(node.get("risk_score", 0.0)),
            is_source=bool(node.get("is_source", False)),
            is_sink=bool(node.get("is_sink", False)),
            cves=node.get("cves", []),
        )

    # --- Load edges ---
    skipped = 0
    for edge in edges:
        if "comment" in edge:
            continue  # skip comment-only entries

        src = edge.get("source")
        tgt = edge.get("target")

        if not src or not tgt:
            skipped += 1
            continue

        # Warn but still add if node wasn't in the nodes list
        if src not in G:
            G.add_node(src, name=src, type="Unknown", namespace="unknown",
                       risk_score=0.0, is_source=False, is_sink=False, cves=[])
        if tgt not in G:
            G.add_node(tgt, name=tgt, type="Unknown", namespace="unknown",
                       risk_score=0.0, is_source=False, is_sink=False, cves=[])

        G.add_edge(
            src,
            tgt,
            relationship=edge.get("relationship", "unknown"),
            weight=float(edge.get("weight", 1.0)),
            cve=edge.get("cve"),
            cvss=edge.get("cvss"),
        )

    return G


def graph_summary(G: nx.DiGraph) -> dict:
    """
    Return a summary dict describing the loaded graph.

    Useful for quick sanity checks and for the CLI --info flag.
    """
    sources = [n for n, d in G.nodes(data=True) if d.get("is_source")]
    sinks   = [n for n, d in G.nodes(data=True) if d.get("is_sink")]
    cve_nodes = [n for n, d in G.nodes(data=True) if d.get("cves")]

    return {
        "node_count":  G.number_of_nodes(),
        "edge_count":  G.number_of_edges(),
        "sources":     sources,
        "sinks":       sinks,
        "cve_nodes":   cve_nodes,
        "node_types":  _count_by_type(G),
    }


def get_sources(G: nx.DiGraph) -> list:
    """Return all node IDs where is_source=True."""
    return [n for n, d in G.nodes(data=True) if d.get("is_source")]


def get_sinks(G: nx.DiGraph) -> list:
    """Return all node IDs where is_sink=True."""
    return [n for n, d in G.nodes(data=True) if d.get("is_sink")]


def get_node_name(G: nx.DiGraph, node_id: str) -> str:
    """Return the human-readable name for a node id."""
    return G.nodes[node_id].get("name", node_id)


def _count_by_type(G: nx.DiGraph) -> dict:
    """Count nodes grouped by their 'type' attribute."""
    counts = {}
    for _, data in G.nodes(data=True):
        t = data.get("type", "Unknown")
        counts[t] = counts.get(t, 0) + 1
    return counts