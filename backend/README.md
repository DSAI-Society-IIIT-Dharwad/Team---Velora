# KubeShield — Kubernetes Attack Graph Analyser
# 🛡️ KubeShield: Kubernetes Attack Graph Analyser

KubeShield is a CLI tool that ingests a Kubernetes cluster graph and runs four security algorithms to detect attack paths, blast radius, circular permissions, and critical nodes.
**See your Kubernetes cluster through the eyes of an attacker.**

Securing a Kubernetes cluster can feel like navigating a maze blindfolded. Between complex RBAC configurations, open network policies, over-privileged service accounts, and nested microservices, it's incredibly easy to miss the hidden pathways that lead to a full cluster compromise.

**KubeShield** is an open-source security analysis tool that brings light to the shadows. By ingesting your cluster's topology as a graph, KubeShield runs advanced mathematical algorithms to find exploitable attack chains *before* malicious actors do. 

We don't just hand you an overwhelming list of isolated vulnerabilities; we show you how they connect, rank them by risk, and provide **clear, actionable, step-by-step remediation advice**.

---

## Installation
## ✨ Why KubeShield?

**Requirements:** Python 3.10+
- **Context is Everything**: A CVE in an isolated pod is a minor issue. That same CVE in a pod with a direct RBAC path to `cluster-admin` is an emergency. KubeShield understands the blast radius.
- **Actionable Advice, Not Just Alerts**: Through our intelligent remediation engine, every detected attack path comes with specific fixes—like *"Rotate this secret"*, *"Remove `exec` from this Role"*, or *"Patch CVE-2024-1234"*.
- **Fast & Flexible**: Built entirely in Python with `NetworkX`, KubeShield analyzes massive cluster graphs in milliseconds via an easy-to-use CLI.

---

## 🧠 How KubeShield Thinks (The Algorithms)

We employ four core algorithms to audit your infrastructure:

1. **Targeted Attack Paths (Kill Chains)** 🎯
   *Uses Dijkstra's Algorithm.* Finds the "path of least resistance" between an entry point (e.g., the public internet) and a high-value target (e.g., your production database).
2. **Blast Radius Analysis** 💥
   *Uses Breadth-First Search (BFS).* Asks: *"If this specific node is compromised, how far can the attacker reach?"* Maps outward up to N hops to reveal your true exposure.
3. **Circular Permission Detection** 🔄
   *Uses Depth-First Search (DFS) & Johnson’s Algorithm.* Uncovers "toxic loops" where resources mutually grant each other permissions—a critical RBAC misconfiguration enabling privilege escalation.
4. **Critical Node Identification** 🛑
   Identifies the absolute "choke points" in your cluster. We tell you which single node, if secured or removed, will break the highest number of attack chains.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+

### Quick Installation

```bash
git clone https://github.com/your-org/kubeshield.git
cd kubeshield/backend
pip install networkx fastapi uvicorn groq python-dotenv pyyaml
```

---

## CLI Usage
## 💻 Usage & Commands

All commands follow this pattern:
KubeShield operates via a clean, intuitive CLI. All commands use your exported cluster graph JSON.

**1. Run a Full Kill-Chain Report (Highly Recommended)**  
Generates a comprehensive security audit of your entire cluster, including actionable fixes.
```bash
python kubeshield.py [MODE] [OPTIONS] cluster-graph.json
python kubeshield.py --full-report cluster-graph.json
```

### Run full kill-chain report (all algorithms):
**2. Find the Shortest Attack Path**  
Wondering if an external user can reach your database?
```bash
python kubeshield.py --full-report mock-cluster-graph.json
python kubeshield.py --source user-dev1 --target db-production cluster-graph.json
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
**3. Calculate Blast Radius**  
Simulate a breach from the internet, up to 3 hops deep.
```bash
python kubeshield.py --source user-dev1 --target db-production mock-cluster-graph.json
python kubeshield.py --blast-radius --source internet --hops 3 cluster-graph.json
```

### Blast radius from a node (BFS):
**4. Detect Circular Permissions (Privilege Escalation Loops)**  
```bash
python kubeshield.py --blast-radius --source internet --hops 3 mock-cluster-graph.json
python kubeshield.py --cycles cluster-graph.json
```

### Detect circular permissions (DFS):
**5. Find Critical Nodes**  
Find out which resource you should patch *first* to break the most attack paths.
```bash
python kubeshield.py --cycles mock-cluster-graph.json
python kubeshield.py --critical-node cluster-graph.json
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
## 🏗️ Under the Hood

### 1. Dijkstra's Shortest Path
Finds the minimum-cost attack path between any source and target node. Cost is the cumulative sum of edge weights. Used to rank attack paths by risk score.
### Project Architecture
KubeShield's backend is modular and easily extensible:
- `kubeshield.py`: The friendly CLI entry point.
- `graphparser.py`: Ingests and normalizes the JSON cluster topology.
- `remediator.py`: Generates the actionable, context-aware remediation text.
- `dijkstra.py`, `cycledetector.py`, `criticalnode.py`, `pathfinder.py`: The algorithmic brains of the operation.

### 2. BFS Blast Radius
Starting from a source node, performs a breadth-first search up to N hops and returns all reachable resources. Shows how far an attacker can reach from a compromised entry point.
*(Note: The project also includes scaffolding for a FastAPI backend (`main.py`) and AI-assisted explanations (`ai.py`) if you choose to expand this into a web application!)*

### 3. DFS Cycle Detection
Uses Johnson's algorithm to find all simple cycles in the directed graph. A cycle means two resources mutually grant each other permissions — a critical misconfiguration.
### Integrating Your Own Data
KubeShield relies on a simple, standard JSON format (`cluster-graph.json`). You can easily generate this from your own K8s scanners or use it alongside other security tools.

### 4. Critical Node Analysis
For each non-source, non-sink node, removes it from a copy of the graph and recounts all simple source-to-sink paths. Ranks nodes by how many attack paths their removal eliminates.
<details>
<summary><b>Click to see the JSON Schema requirements</b></summary>

---
Your input must be a JSON object with `nodes` and `edges`.

## Project Structure
**Node Object**

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
| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique identifier |
| `name` | `string` | Human-readable name |
| `type` | `string` | `Pod`, `Service`, `Secret`, `Role`, `ClusterRole`, `ServiceAccount`, `User`, `ExternalActor`, `Database`, `Node`, `Namespace`, `PersistentVolume`, `ConfigMap` |
| `risk_score` | `float` | Base risk score (0-10) |
| `is_source` | `boolean` | `true` if this is a valid attack entry point |
| `is_sink` | `boolean` | `true` if this is a high-value asset |
| `cves` | `list[str]` | E.g. `["CVE-2024-1234"]` |

---
**Edge Object**

## cluster-graph.json Schema
| Field | Type | Description |
|---|---|---|
| `source` | `string` | Source node `id` |
| `target` | `string` | Target node `id` |
| `relationship` | `string` | E.g., `"can-exec"`, `"bound-to"` |
| `weight` | `float` | Traversal cost (higher = riskier) |
| `cve` / `cvss` | `str` / `float` | Edge-specific vulnerabilities |

The input file must be a JSON object with two top-level keys: `nodes` and `edges`.
</details>

### Node object
---

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
## 🚦 Exit Codes

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
| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Bad arguments or file not found |
| `2`  | Graph parse error (malformed JSON) |

### Edge object
---

| Field          | Type         | Description |
|----------------|--------------|-------------|
| `source`       | string       | Source node `id` |
| `target`       | string       | Target node `id` |
| `relationship` | string       | Relationship label, e.g. `"can-exec"`, `"bound-to"`, `"routes-to"` |
| `weight`       | float        | Traversal cost used by Dijkstra (higher = riskier) |
| `cve`          | string/null  | CVE ID on this specific edge, or `null` |
| `cvss`         | float/null   | CVSS score of the edge CVE, or `null` |
## 🤝 Contributing
We welcome contributions! Whether you're adding new graph algorithms, improving the remediation engine, or building out the UI, your pull requests are deeply appreciated. 

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
*Built with security and sanity in mind.* 🛡️
