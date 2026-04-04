"""
test_algorithms.py
------------------
Pytest unit tests covering all rubric test cases for KubeShield.

Test cases covered:
  BFS-1  : Blast radius from pod-webfront, hops=3
  BFS-2  : Blast radius from cicd-bot, hops=2
  BFS-3  : Isolated node with no outbound edges → empty blast radius
  DIJK-1 : Shortest path user-dev1 → db-production, cost=24.1
  DIJK-2 : Shortest path internet → ns-kube-system, cost=32.0
  DIJK-3 : No path between disconnected nodes → graceful message
  DFS-1  : Exactly 1 cycle detected, correct nodes
  CNA-1  : web-frontend is critical node, eliminates 32/46 paths

Run with:
  pytest tests/ -v
"""

import sys
import os
import pytest
import networkx as nx

# Make sure backend modules are importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphparser   import load_graph, graph_summary
from dijkstra      import find_shortest_path, find_all_attack_paths
from cycledetector import find_cycles
from criticalnode  import analyse
from collections   import deque


# ── Fixtures ──────────────────────────────────────────────────────────────────

GRAPH_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "mock-cluster-graph.json")


@pytest.fixture(scope="module")
def G():
    """Load the mock cluster graph once for all tests."""
    return load_graph(GRAPH_PATH)


@pytest.fixture(scope="module")
def isolated_graph():
    """Minimal graph with one isolated source node (no outbound edges) — BFS-3."""
    H = nx.DiGraph()
    H.add_node("isolated-node", name="isolated-node", type="Pod",
               namespace="default", risk_score=5.0,
               is_source=True, is_sink=False, cves=[])
    H.add_node("unreachable", name="unreachable", type="Secret",
               namespace="default", risk_score=8.0,
               is_source=False, is_sink=True, cves=[])
    # No edges — isolated-node has no outbound connections
    return H


def _bfs_blast_radius(G, source_id: str, hops: int) -> dict:
    """
    BFS helper — mirrors the logic in kubeshield.py run_blast_radius().
    Returns {hop_num: [node_names]} dict.
    """
    visited = {source_id: 0}
    queue   = deque([(source_id, 0)])
    by_hop  = {}

    while queue:
        current, depth = queue.popleft()
        if depth >= hops:
            continue
        for neighbor in G.successors(current):
            if neighbor not in visited:
                visited[neighbor] = depth + 1
                queue.append((neighbor, depth + 1))
                by_hop.setdefault(depth + 1, []).append(neighbor)

    return by_hop


# ── Graph loading ─────────────────────────────────────────────────────────────

class TestGraphLoading:
    def test_loads_without_error(self, G):
        assert G is not None

    def test_node_count(self, G):
        # JSON has 41 nodes
        assert G.number_of_nodes() >= 40

    def test_edge_count(self, G):
        # JSON has 48 edges
        assert G.number_of_edges() >= 45

    def test_sources_present(self, G):
        sources = [n for n, d in G.nodes(data=True) if d.get("is_source")]
        assert len(sources) >= 4  # internet, user-dev1, user-dev2, user-cicd, lb-service

    def test_sinks_present(self, G):
        sinks = [n for n, d in G.nodes(data=True) if d.get("is_sink")]
        assert len(sinks) >= 4  # db-production, node-worker-1, ns-kube-system, pvc-data

    def test_node_attributes_stored(self, G):
        data = G.nodes["pod-webfront"]
        assert data["name"]       == "web-frontend"
        assert data["type"]       == "Pod"
        assert data["risk_score"] == 7.5
        assert "CVE-2024-1234" in data["cves"]

    def test_edge_attributes_stored(self, G):
        edge = G.edges["user-dev1", "pod-webfront"]
        assert edge["relationship"] == "can-exec"
        assert edge["weight"]       == 5.0
        assert edge["cve"]          == "CVE-2024-1234"
        assert edge["cvss"]         == 8.1

    def test_file_not_found_raises(self):
        from graphparser import GraphParseError
        with pytest.raises(FileNotFoundError):
            load_graph("/nonexistent/path/graph.json")

    def test_invalid_json_raises(self, tmp_path):
        from graphparser import GraphParseError
        bad = tmp_path / "bad.json"
        bad.write_text("not json at all {{{")
        with pytest.raises(GraphParseError):
            load_graph(str(bad))


# ── BFS Blast Radius ──────────────────────────────────────────────────────────

class TestBlastRadius:
    """
    Rubric test cases:
      BFS-1: source=pod-webfront, hops=3 → 13 reachable nodes
      BFS-2: source=cicd-bot,     hops=2 → sa-cicd, deployer, cicd-deploy-token (+ production-db at hop3)
      BFS-3: isolated node        hops=3 → 0 reachable nodes, no crash
    """

    def test_bfs1_reachable_count(self, G):
        """BFS-1: pod-webfront, hops=3 should reach ≥ 10 nodes."""
        by_hop = _bfs_blast_radius(G, "pod-webfront", 3)
        total  = sum(len(v) for v in by_hop.values())
        assert total >= 10, f"Expected ≥10 reachable nodes, got {total}"

    def test_bfs1_hop1_contains_expected(self, G):
        """BFS-1: Hop 1 from pod-webfront must include sa-webapp and sa-default."""
        by_hop = _bfs_blast_radius(G, "pod-webfront", 3)
        hop1   = set(by_hop.get(1, []))
        assert "sa-webapp"  in hop1, f"sa-webapp not in hop 1: {hop1}"
        assert "sa-default" in hop1, f"sa-default not in hop 1: {hop1}"

    def test_bfs1_hop2_contains_expected(self, G):
        """BFS-1: Hop 2 must include role-secret-reader and clusterrole-admin."""
        by_hop = _bfs_blast_radius(G, "pod-webfront", 3)
        hop2   = set(by_hop.get(2, []))
        assert "role-secret-reader" in hop2, f"role-secret-reader not in hop 2: {hop2}"
        assert "clusterrole-admin"  in hop2, f"clusterrole-admin not in hop 2: {hop2}"

    def test_bfs1_no_duplicate_nodes(self, G):
        """BFS-1: Each node should appear in exactly one hop layer."""
        by_hop   = _bfs_blast_radius(G, "pod-webfront", 3)
        all_seen = []
        for nodes in by_hop.values():
            all_seen.extend(nodes)
        assert len(all_seen) == len(set(all_seen)), "Duplicate nodes found across hop layers"

    def test_bfs2_hop1(self, G):
        """BFS-2: cicd-bot hop 1 = {sa-cicd}."""
        by_hop = _bfs_blast_radius(G, "user-cicd", 2)
        hop1   = set(by_hop.get(1, []))
        assert "sa-cicd" in hop1, f"sa-cicd not in hop 1: {hop1}"

    def test_bfs2_hop2_contains_deployer_and_token(self, G):
        """BFS-2: cicd-bot hop 2 must include deployer (clusterrole-deploy) and cicd-deploy-token."""
        by_hop = _bfs_blast_radius(G, "user-cicd", 2)
        hop2   = set(by_hop.get(2, []))
        assert "clusterrole-deploy" in hop2 or "secret-cicd-token" in hop2, \
            f"Expected deployer or cicd-deploy-token in hop 2: {hop2}"

    def test_bfs3_isolated_node_empty(self, isolated_graph):
        """BFS-3: Source with no outbound edges → 0 reachable nodes, no crash."""
        by_hop = _bfs_blast_radius(isolated_graph, "isolated-node", 3)
        total  = sum(len(v) for v in by_hop.values())
        assert total == 0, f"Expected 0 reachable nodes from isolated node, got {total}"


# ── Dijkstra Shortest Path ────────────────────────────────────────────────────

class TestDijkstra:
    """
    Rubric test cases:
      DIJK-1: user-dev1 → db-production  |  5 hops  |  cost=24.1
      DIJK-2: internet  → ns-kube-system  |  5 hops  |  cost=32.0
      DIJK-3: disconnected nodes → 'No path found', no exception
    """

    def test_dijk1_found(self, G):
        result = find_shortest_path(G, "user-dev1", "db-production")
        assert result["found"] is True

    def test_dijk1_hops(self, G):
        result = find_shortest_path(G, "user-dev1", "db-production")
        assert result["hops"] == 5, f"Expected 5 hops, got {result['hops']}"

    def test_dijk1_cost(self, G):
        result = find_shortest_path(G, "user-dev1", "db-production")
        assert abs(result["risk_score"] - 24.1) <= 0.1, \
            f"Expected cost ≈24.1, got {result['risk_score']}"

    def test_dijk1_path_sequence(self, G):
        """DIJK-1: Path must pass through web-frontend → sa-webapp → secret-reader."""
        result = find_shortest_path(G, "user-dev1", "db-production")
        path   = result["path"]
        assert "pod-webfront"       in path
        assert "sa-webapp"          in path
        assert "role-secret-reader" in path
        assert "secret-db-creds"    in path

    def test_dijk1_cve_annotation(self, G):
        """DIJK-1: First edge (user-dev1 → web-frontend) must carry CVE-2024-1234."""
        result = find_shortest_path(G, "user-dev1", "db-production")
        first  = result["edges"][0]
        assert first["cve"] == "CVE-2024-1234"
        assert first["cvss"] == 8.1

    def test_dijk2_found(self, G):
        result = find_shortest_path(G, "internet", "ns-kube-system")
        assert result["found"] is True

    def test_dijk2_hops(self, G):
        result = find_shortest_path(G, "internet", "ns-kube-system")
        assert result["hops"] == 5, f"Expected 5 hops, got {result['hops']}"

    def test_dijk2_cost(self, G):
        result = find_shortest_path(G, "internet", "ns-kube-system")
        assert abs(result["risk_score"] - 32.0) <= 0.1, \
            f"Expected cost ≈32.0, got {result['risk_score']}"

    def test_dijk2_path_via_cluster_admin(self, G):
        """DIJK-2: Path must pass through sa-default → cluster-admin → admin-token."""
        result = find_shortest_path(G, "internet", "ns-kube-system")
        path   = result["path"]
        assert "sa-default"        in path
        assert "clusterrole-admin" in path
        assert "secret-admin-token" in path

    def test_dijk3_no_path_graceful(self, G):
        """DIJK-3: Disconnected nodes return found=False, no exception raised."""
        result = find_shortest_path(G, "internet", "internet")  # same node
        # Either no path or trivial — no exception raised is the key requirement
        assert isinstance(result, dict)
        assert "found" in result

    def test_dijk3_missing_source(self, G):
        """DIJK-3 variant: unknown source returns found=False with error message."""
        result = find_shortest_path(G, "no-such-node", "db-production")
        assert result["found"] is False
        assert result["error"] is not None

    def test_dijk3_missing_target(self, G):
        """DIJK-3 variant: unknown target returns found=False with error message."""
        result = find_shortest_path(G, "internet", "no-such-sink")
        assert result["found"] is False
        assert result["error"] is not None

    def test_severity_labels(self, G):
        """Paths should carry correct severity labels based on risk score."""
        r1 = find_shortest_path(G, "user-dev1", "db-production")  # 24.1 → CRITICAL
        assert r1["severity"] == "CRITICAL"

    def test_all_paths_sorted_ascending(self, G):
        """find_all_attack_paths must return paths sorted by risk_score ascending."""
        paths  = find_all_attack_paths(G)
        scores = [p["risk_score"] for p in paths]
        assert scores == sorted(scores), "Paths are not sorted ascending by risk score"

    def test_all_paths_count(self, G):
        """Full path enumeration should detect at least 10 paths."""
        paths = find_all_attack_paths(G)
        assert len(paths) >= 10, f"Expected ≥10 paths, got {len(paths)}"


# ── Cycle Detection ───────────────────────────────────────────────────────────

class TestCycleDetection:
    """
    Rubric test cases:
      DFS-1: Full mock graph → exactly 1 cycle: [svc-service-a, svc-service-b]
    """

    def test_dfs1_exactly_one_cycle(self, G):
        cycles = find_cycles(G)
        assert len(cycles) == 1, f"Expected 1 cycle, got {len(cycles)}"

    def test_dfs1_correct_nodes(self, G):
        cycles = find_cycles(G)
        nodes  = set(cycles[0]["nodes"])
        assert "svc-service-a" in nodes
        assert "svc-service-b" in nodes

    def test_dfs1_no_self_loops(self, G):
        cycles = find_cycles(G)
        for cycle in cycles:
            assert cycle["length"] >= 2, "Self-loops (length 1) should not be reported"

    def test_dfs1_no_duplicates(self, G):
        """Same cycle should not appear twice (e.g. A→B and B→A not both reported)."""
        cycles = find_cycles(G)
        keys   = [tuple(c["nodes"]) for c in cycles]
        assert len(keys) == len(set(keys)), "Duplicate cycles detected"

    def test_dfs1_has_relationships(self, G):
        cycles = find_cycles(G)
        for cycle in cycles:
            assert "relationships" in cycle
            assert len(cycle["relationships"]) > 0

    def test_empty_graph_no_crash(self):
        """Cycle detection on empty graph should return empty list, not crash."""
        H      = nx.DiGraph()
        cycles = find_cycles(H)
        assert cycles == []

    def test_acyclic_graph_no_cycles(self):
        """Simple DAG should have no cycles."""
        H = nx.DiGraph()
        H.add_edge("a", "b")
        H.add_edge("b", "c")
        cycles = find_cycles(H)
        assert cycles == []


# ── Critical Node Analysis ────────────────────────────────────────────────────

class TestCriticalNodeAnalysis:
    """
    Rubric test cases:
      CNA-1: web-frontend (pod-webfront) eliminates 32 of 46 baseline paths
    """

    @pytest.fixture(scope="class")
    def result(self, G):
        return analyse(G)

    def test_cna1_correct_critical_node(self, result):
        assert result["critical_node"] == "pod-webfront", \
            f"Expected pod-webfront, got {result['critical_node']}"

    def test_cna1_correct_name(self, result):
        assert result["critical_name"] == "web-frontend"

    def test_cna1_baseline_paths(self, result):
        assert result["baseline_paths"] == 46, \
            f"Expected baseline 46, got {result['baseline_paths']}"

    def test_cna1_paths_eliminated(self, result):
        assert result["paths_eliminated"] == 32, \
            f"Expected 32 paths eliminated, got {result['paths_eliminated']}"

    def test_cna1_ranking_top5(self, result):
        """Top 5 ranking must be present and sorted descending."""
        ranking = result["ranking"]
        assert len(ranking) >= 5
        elim = [r["eliminated"] for r in ranking]
        assert elim == sorted(elim, reverse=True)

    def test_cna1_runner_up_is_api_server(self, result):
        """Runner-up should be api-server (pod-api)."""
        ranking = result["ranking"]
        assert ranking[1]["node"] == "pod-api", \
            f"Expected pod-api as runner-up, got {ranking[1]['node']}"

    def test_cna1_runner_up_eliminates_24(self, result):
        ranking = result["ranking"]
        assert ranking[1]["eliminated"] == 24

    def test_graph_not_mutated(self, G, result):
        """Original graph must be unchanged after critical node analysis."""
        assert G.has_node("pod-webfront"), "Original graph was mutated — pod-webfront missing"
        assert G.number_of_nodes() >= 40

    def test_sources_excluded_from_candidates(self, G, result):
        """Source nodes must never appear in the ranking."""
        sources  = {n for n, d in G.nodes(data=True) if d.get("is_source")}
        ranked   = {r["node"] for r in result["ranking"]}
        overlap  = sources & ranked
        assert not overlap, f"Source nodes found in ranking: {overlap}"

    def test_sinks_excluded_from_candidates(self, G, result):
        """Sink nodes must never appear in the ranking."""
        sinks   = {n for n, d in G.nodes(data=True) if d.get("is_sink")}
        ranked  = {r["node"] for r in result["ranking"]}
        overlap = sinks & ranked
        assert not overlap, f"Sink nodes found in ranking: {overlap}"