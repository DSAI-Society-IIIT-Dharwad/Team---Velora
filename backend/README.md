# KubeShield — Kubernetes Attack Graph Analyser

KubeShield is a CLI tool that ingests a Kubernetes cluster graph and runs four security algorithms to detect attack paths, blast radius, circular permissions, and critical nodes.

---

## Installation

**Requirements:** Python 3.10+

```bash
cd kubeshield/backend
pip install networkx fastapi uvicorn groq python-dotenv pyyaml
```

---

## CLI Usage

All commands follow this pattern:

```bash
python kubeshield.py [MODE] [OPTIONS] cluster-graph.json
```

### Run full kill-chain report (all algorithms):
```bash
python kubeshield.py --full-report mock-cluster-graph.json
```
Expected output:
```
══════════════════════════════════════════════════════════════════
  KILL CHAIN REPORT  —  2026-04-04 10:00:00
  Cluster : mock-prod-cluster
  Nodes   : 41  |  Edges: 48
══════════════════════════════════════════════════════════════════
[ SECTION 1 — ATTACK PATH DETECTION (Dijkstra) ]
  ⚠  18 attack path(s) detected
  ...
```

### Find shortest attack path between two nodes:
```bash
python kubeshield.py --source user-dev1 --target db-production mock-cluster-graph.json
```

### Blast radius from a node (BFS):
```bash
python kubeshield.py --blast-radius --source internet --hops 3 mock-cluster-graph.json
```

### Detect circular permissions (DFS):
```bash
python kubeshield.py --cycles mock-cluster-graph.json
```

### Critical node analysis:
```bash
python kubeshield.py --critical-node mock-cluster-graph.json
```

### Help:
```bash
python kubeshield.py --help
```

---

## Algorithms

### 1. Dijkstra's Shortest Path
Finds the minimum-cost attack path between any source and target node. Cost is the cumulative sum of edge weights. Used to rank attack paths by risk score.

### 2. BFS Blast Radius
Starting from a source node, performs a breadth-first search up to N hops and returns all reachable resources. Shows how far an attacker can reach from a compromised entry point.

### 3. DFS Cycle Detection
Uses Johnson's algorithm to find all simple cycles in the directed graph. A cycle means two resources mutually grant each other permissions — a critical misconfiguration.

### 4. Critical Node Analysis
For each non-source, non-sink node, removes it from a copy of the graph and recounts all simple source-to-sink paths. Ranks nodes by how many attack paths their removal eliminates.

---

## Project Structure

```
kubeshield/backend/
├── kubeshield.py          # CLI entry point — run this
├── graphparser.py         # Parses cluster-graph.json into NetworkX DiGraph
├── dijkstra.py            # Dijkstra attack paths + kill chain report
├── cycledetector.py       # DFS cycle detection
├── criticalnode.py        # Critical node analysis
├── mock-cluster-graph.json # Hackathon test dataset (41 nodes, 48 edges)
├── main.py                # FastAPI web server (bonus UI)
├── parser.py              # Kubernetes YAML scanner (bonus UI)
├── scorer.py              # Risk scoring engine (bonus UI)
├── ai.py                  # Groq AI explanations (bonus UI)
```

---

## cluster-graph.json Schema

The input file must be a JSON object with two top-level keys: `nodes` and `edges`.

### Node object

| Field        | Type         | Description |
|--------------|--------------|-------------|
| `id`         | string       | Unique node identifier used in edges |
| `name`       | string       | Human-readable display name |
| `type`       | string       | Resource type: `Pod`, `Service`, `Secret`, `Role`, `ClusterRole`, `ServiceAccount`, `User`, `ExternalActor`, `Database`, `Node`, `Namespace`, `PersistentVolume`, `ConfigMap` |
| `namespace`  | string       | Kubernetes namespace, or `"cluster"` / `"external"` |
| `risk_score` | float (0–10) | Base risk score for this node |
| `is_source`  | bool         | `true` if this is an attack entry point (e.g. internet, user) |
| `is_sink`    | bool         | `true` if this is a high-value target (e.g. production-db, kube-system) |
| `cves`       | list[string] | CVE IDs affecting this node, e.g. `["CVE-2024-1234"]` |

Example node:
```json
{
  "id": "pod-webfront",
  "type": "Pod",
  "name": "web-frontend",
  "namespace": "default",
  "risk_score": 7.5,
  "is_source": false,
  "is_sink": false,
  "cves": ["CVE-2024-1234"]
}
```

### Edge object

| Field          | Type         | Description |
|----------------|--------------|-------------|
| `source`       | string       | Source node `id` |
| `target`       | string       | Target node `id` |
| `relationship` | string       | Relationship label, e.g. `"can-exec"`, `"bound-to"`, `"routes-to"` |
| `weight`       | float        | Traversal cost used by Dijkstra (higher = riskier) |
| `cve`          | string/null  | CVE ID on this specific edge, or `null` |
| `cvss`         | float/null   | CVSS score of the edge CVE, or `null` |

Example edge:
```json
{
  "source": "user-dev1",
  "target": "pod-webfront",
  "relationship": "can-exec",
  "weight": 5.0,
  "cve": "CVE-2024-1234",
  "cvss": 8.1
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Bad arguments or file not found |
| 2    | Graph parse error (malformed JSON) |
