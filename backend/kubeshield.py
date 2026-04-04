"""
kubeshield.py
-------------
KubeShield CLI — Kubernetes Attack Graph Analyser

Usage examples:
  python kubeshield.py --full-report  mock-cluster-graph.json
  python kubeshield.py --blast-radius --source internet --hops 3  mock-cluster-graph.json
  python kubeshield.py --source internet --target kube-system      mock-cluster-graph.json
  python kubeshield.py --cycles        mock-cluster-graph.json
  python kubeshield.py --critical-node mock-cluster-graph.json

Exit codes:
  0  success
  1  bad arguments / file not found
  2  graph parse error
"""

import argparse
import sys
import datetime

from graphparser   import load_graph, graph_summary, GraphParseError
from dijkstra      import find_shortest_path, find_all_attack_paths, format_path_report
from cycledetector import find_cycles, format_cycle_report
from criticalnode  import analyse, format_critical_node_report


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = """
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
  KILL CHAIN REPORT  \u2014  {timestamp}
  Cluster : {cluster}
  Nodes   : {nodes}  |  Edges: {edges}
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
"""

DIVIDER = "\u2550" * 66


# ── CLI setup ─────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kubeshield",
        description="KubeShield — Kubernetes cluster attack graph analyser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Full kill-chain report (all algorithms):
  python kubeshield.py --full-report mock-cluster-graph.json

  # Shortest attack path between two specific nodes:
  python kubeshield.py --source internet --target kube-system mock-cluster-graph.json

  # Blast radius from a node (BFS, default 3 hops):
  python kubeshield.py --blast-radius --source internet mock-cluster-graph.json

  # Blast radius with custom hop depth:
  python kubeshield.py --blast-radius --source internet --hops 2 mock-cluster-graph.json

  # Cycle detection only:
  python kubeshield.py --cycles mock-cluster-graph.json

  # Critical node analysis only:
  python kubeshield.py --critical-node mock-cluster-graph.json
        """,
    )


    p.add_argument(
        "graph_file",
        help="Path to cluster-graph.json",
    )
    p.add_argument(
    "--nvd",
    action="store_true",
    help="Fetch live CVSS scores from NIST NVD API before analysis (Bonus B2)"
)

    mode = p.add_argument_group("analysis modes (pick one, or use --full-report)")
    mode.add_argument(
        "--full-report",
        action="store_true",
        help="Run all algorithms and print the complete kill-chain report",
    )
    mode.add_argument(
        "--blast-radius",
        action="store_true",
        help="BFS blast radius from --source (requires --source)",
    )
    mode.add_argument(
        "--cycles",
        action="store_true",
        help="Detect circular permission chains (DFS)",
    )
    mode.add_argument(
        "--critical-node",
        action="store_true",
        help="Identify the node whose removal eliminates the most attack paths",
    )

    opts = p.add_argument_group("options")
    opts.add_argument(
        "--source",
        metavar="NODE_ID",
        help="Source node ID for path finding or blast radius",
    )
    opts.add_argument(
        "--target",
        metavar="NODE_ID",
        help="Target node ID for shortest path (used with --source)",
    )
    opts.add_argument(
        "--hops",
        type=int,
        default=3,
        metavar="N",
        help="Blast radius hop depth (default: 3)",
    )

    return p


# ── Mode handlers ─────────────────────────────────────────────────────────────

def run_attack_paths(G, summary) -> list:
    """Run Dijkstra across all sources/sinks. Return results."""
    print(f"\n[ SECTION 1 \u2014 ATTACK PATH DETECTION (Dijkstra) ]")
    paths = find_all_attack_paths(G)
    print(f"  \u26a0  {len(paths)} attack path(s) detected\n")
    print(format_path_report(paths))
    return paths


def run_blast_radius(G, source: str, hops: int):
    """BFS blast radius from a single source node."""
    from collections import deque

    if source not in G:
        print(f"  ERROR: node '{source}' not found in graph.", file=sys.stderr)
        sys.exit(1)

    src_name = G.nodes[source].get("name", source)
    print(f"\n[ BLAST RADIUS \u2014 Source: {src_name}  (depth={hops}) ]")

    # BFS on directed graph
    visited = {source: 0}
    queue   = deque([(source, 0)])
    by_hop  = {}

    while queue:
        current, depth = queue.popleft()
        if depth >= hops:
            continue
        for neighbor in G.successors(current):
            if neighbor not in visited:
                visited[neighbor] = depth + 1
                queue.append((neighbor, depth + 1))
                hop_key = depth + 1
                by_hop.setdefault(hop_key, []).append(neighbor)

    total = sum(len(v) for v in by_hop.values())
    print(f"  Source: {src_name}  \u2192  {total} reachable resource(s) within {hops} hops")

    for hop_num in sorted(by_hop.keys()):
        names = [G.nodes[n].get("name", n) for n in by_hop[hop_num]]
        print(f"    Hop {hop_num}: {', '.join(names)}")
    print()


def run_single_path(G, source: str, target: str):
    """Dijkstra between two specific nodes."""
    if source not in G:
        print(f"  ERROR: source node '{source}' not found.", file=sys.stderr)
        sys.exit(1)
    if target not in G:
        print(f"  ERROR: target node '{target}' not found.", file=sys.stderr)
        sys.exit(1)

    src_name = G.nodes[source].get("name", source)
    tgt_name = G.nodes[target].get("name", target)
    print(f"\n[ SHORTEST PATH \u2014 {src_name} \u2192 {tgt_name} ]")

    result = find_shortest_path(G, source, target)

    if not result["found"]:
        print(f"  No path found: {result['error']}")
        return

    print(
        f"  {result['hops']} hops  |  "
        f"Risk Score: {result['risk_score']}  [{result['severity']}]"
    )
    print("  " + "\u2500" * 60)
    for edge in result["edges"]:
        cve_tag = f"  [{edge['cve']}, CVSS {edge['cvss']}]" if edge["cve"] else ""
        print(
            f"  {edge['src_name']} ({edge['src_type']})  "
            f"--[{edge['relationship']}]-->  "
            f"{edge['tgt_name']} ({edge['tgt_type']}){cve_tag}"
        )
    print()


def run_cycles(G):
    """DFS cycle detection."""
    print(f"\n[ SECTION 3 \u2014 CIRCULAR PERMISSION DETECTION (DFS) ]")
    cycles = find_cycles(G)
    if cycles:
        print(f"  \u26a0  {len(cycles)} cycle(s) detected\n")
    print(format_cycle_report(cycles))
    return cycles


def run_critical_node(G):
    """Critical node analysis."""
    print(f"\n[ SECTION 4 \u2014 CRITICAL NODE ANALYSIS ]")
    print("  Computing... (removing each node and recounting paths)")
    result = analyse(G)
    print(format_critical_node_report(result))
    return result


def run_full_report(G, summary):
    """Run all four algorithms and print the complete kill-chain report."""
    ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cluster = summary.get("cluster", "unknown")

    print(BANNER.format(
        timestamp=ts,
        cluster=cluster,
        nodes=summary["node_count"],
        edges=summary["edge_count"],
    ))

    # Section 1 — Attack paths
    paths = run_attack_paths(G, summary)

    # Section 2 — Blast radius (all sources, depth 3)
    print(f"\n[ SECTION 2 \u2014 BLAST RADIUS ANALYSIS (BFS, depth=3) ]\n")
    for src in summary["sources"]:
        run_blast_radius(G, src, hops=3)

    # Section 3 — Cycles
    cycles = run_cycles(G)

    # Section 4 — Critical node
    cna = run_critical_node(G)

    # Summary
    print(DIVIDER)
    print("  SUMMARY")
    print(f"  Attack paths found   : {len(paths)}")
    print(f"  Circular permissions : {len(cycles)}")
    print(f"  Total blast-radius nodes exposed : {summary['edge_count']}")
    if cna["critical_node"]:
        print(f"  Critical node to remove : {cna['critical_name']}")
    print(DIVIDER)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Load graph
    try:
        G = load_graph(args.graph_file)
          # ── Bonus B2: Live CVE enrichment ─────────────────────────────────────────
        if args.nvd:
          from nvd import enrich_graph_with_nvd, format_nvd_report
          print("\n[ LIVE CVE ENRICHMENT — NIST NVD API ]")
          enrichment = enrich_graph_with_nvd(G)
          print(format_nvd_report(enrichment))
          print()
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.graph_file}", file=sys.stderr)
        sys.exit(1)
    except GraphParseError as e:
        print(f"ERROR: could not parse graph: {e}", file=sys.stderr)
        sys.exit(2)

    summary = {
        **__import__("graphparser").graph_summary(G),
        "cluster": "mock-prod-cluster",
    }

    # Dispatch to the correct mode
    if args.full_report:
        run_full_report(G, summary)

    elif args.blast_radius:
        if not args.source:
            print("ERROR: --blast-radius requires --source NODE_ID", file=sys.stderr)
            sys.exit(1)
        run_blast_radius(G, args.source, args.hops)

    elif args.cycles:
        run_cycles(G)

    elif args.critical_node:
        run_critical_node(G)

    elif args.source and args.target:
        run_single_path(G, args.source, args.target)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()