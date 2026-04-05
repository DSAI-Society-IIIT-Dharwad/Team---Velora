# 🛡️ KubeShield — Kubernetes Attack Graph Analyser

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![NetworkX](https://img.shields.io/badge/NetworkX-3.x-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Nokia Track — AI-Powered Kubernetes Security Intelligence**

*Detect attack paths, blast radius, circular permissions, and critical nodes — before attackers do.*

[CLI Tool](#️-cli-tool) • [Web UI](#-web-ui) • [Algorithms](#-algorithms) • [API](#-api-reference) • [Tests](#-running-tests)

</div>

---

## 📖 Overview

KubeShield ingests a Kubernetes cluster topology (JSON graph or live YAML manifests) and runs **four graph security algorithms** to map every exploitable attack path from entry points to high-value targets.

| Algorithm | Method | What It Finds |
|-----------|--------|---------------|
| **Attack Path Detection** | Dijkstra's Shortest Path | Minimum-cost routes from attacker entry to critical assets |
| **Blast Radius** | BFS (Breadth-First Search) | How far a compromised node spreads within N hops |
| **Circular Permissions** | DFS Cycle Detection | RBAC bindings that mutually escalate each other |
| **Critical Node Analysis** | Graph Surgery | The single node whose removal blocks the most attack paths |

Results are rendered in a **real-time interactive D3 force graph** with per-node **Groq LLaMA AI explanations**.

---

## 🏗️ Project Structure

```
kubeshield/
├── backend/                        ← Python CLI + FastAPI server
│   ├── kubeshield.py               ← ⭐ Main CLI entry point
│   ├── graphparser.py              ← Loads cluster-graph.json → NetworkX DiGraph
│   ├── dijkstra.py                 ← Weighted shortest path (Dijkstra)
│   ├── cycledetector.py            ← DFS cycle detection
│   ├── criticalnode.py             ← Critical node analysis (graph surgery)
│   ├── pathfinder.py               ← BFS blast radius
│   ├── remediator.py               ← Per-path remediation advice generator
│   ├── nvd.py                      ← NIST NVD live CVE enrichment (Bonus B2)
│   ├── parser.py                   ← Kubernetes YAML manifest parser
│   ├── scorer.py                   ← Risk scoring engine
│   ├── ai.py                       ← Groq LLaMA AI node explanations
│   ├── main.py                     ← FastAPI server
│   ├── mock-cluster-graph.json     ← Test dataset (41 nodes, 48 edges)
│   └── tests/
│       └── test_algorithms.py      ← Pytest unit tests (all rubric cases)
│
├── frontend/                       ← React + Vite + TailwindCSS
│   └── src/
│       ├── App.jsx
│       └── components/
│           ├── GraphCanvas.jsx     ← D3 force-directed attack graph
│           ├── UploadPanel.jsx     ← YAML + JSON dual upload
│           ├── KillChain.jsx       ← Animated attack step visualiser
│           ├── AISidebar.jsx       ← Per-node Groq AI analysis panel
│           ├── BlastRadius.jsx     ← BFS reachability panel
│           ├── RBACChains.jsx      ← RBAC privilege chain explorer
│           └── RiskScore.jsx       ← Cluster risk score gauge
│
└── demo/
    ├── vulnerable-cluster.yaml     ← Demo Kubernetes manifest
    └── mock-cluster-graph.json     ← Attack graph JSON
```

---

## 🚀 Quick Start

### Prerequisites

- Python **3.10+**
- Node.js **18+**
- A free [Groq API key](https://console.groq.com) (for AI explanations)

### 1 — Clone the repo

```bash
git clone https://github.com/DSAI-Society-IIIT-Dharwad/Team---Velora.git
cd Team---Velora
```

### 2 — Backend setup

```bash
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Add your Groq API key
echo "GROQ_API_KEY=your_key_here" > .env

# Start the API server
python main.py
# → Running at http://localhost:8000
```

### 3 — Frontend setup (separate terminal)

```bash
cd frontend

# Install Node dependencies
npm install

# Start the dev server
npm run dev
# → Running at http://localhost:5173
```

---

## 🖥️ CLI Tool

All four algorithms are fully accessible from the command line with no server needed.

### Full kill-chain report (all algorithms)

```bash
python kubeshield.py --full-report mock-cluster-graph.json
```

### Single attack path — Dijkstra (DIJK-1)

```bash
python kubeshield.py --source user-dev1 --target db-production mock-cluster-graph.json
```

### Single attack path — Dijkstra (DIJK-2)

```bash
python kubeshield.py --source internet --target ns-kube-system mock-cluster-graph.json
```

### Blast radius — BFS

```bash
python kubeshield.py --blast-radius --source internet --hops 3 mock-cluster-graph.json
```

### Cycle detection — DFS

```bash
python kubeshield.py --cycles mock-cluster-graph.json
```

### Critical node analysis

```bash
python kubeshield.py --critical-node mock-cluster-graph.json
```

### Live CVE enrichment from NIST NVD (Bonus B2)

```bash
python kubeshield.py --full-report --nvd mock-cluster-graph.json
```

### Help

```bash
python kubeshield.py --help
```

---

## 🌐 Web UI

Upload a Kubernetes YAML manifest or a `cluster-graph.json` directly in the browser.

| Feature | Description |
|---------|-------------|
| **D3 Attack Graph** | Interactive force-directed graph with drag, zoom, click |
| **Kill Chain Panel** | Animated step-by-step attack path traversal |
| **RBAC Chains Tab** | ServiceAccount → Role privilege escalation visualiser |
| **AI Sidebar** | Groq LLaMA explanation for every selected node |
| **Blast Radius** | BFS reachability with hop-by-hop breakdown |
| **Risk Score Gauge** | Cluster-wide risk score (0–100) with severity label |

---

## 🧠 Algorithms

### 1. Dijkstra's Shortest Path (`dijkstra.py`)

Finds the **minimum-cost weighted path** from a source node to a target node using `nx.dijkstra_path`. Edge weights represent traversal risk. Results include hop count, cumulative risk score, severity label, and CVE annotations on each edge.

```
user-dev1 → web-frontend [CVE-2024-1234, CVSS 8.1]
          → sa-webapp → secret-reader → db-credentials → production-db
          5 hops | Risk Score: 24.1 | CRITICAL
```

### 2. BFS Blast Radius (`pathfinder.py`)

Standard **Breadth-First Search** from a compromised node, layer by layer up to N hops. Each node is counted in exactly one hop layer (no double-counting). Returns reachable node names grouped by hop depth.

```
internet (hop 0)
  Hop 1: loadbalancer-svc, web-frontend
  Hop 2: api-server, sa-webapp, default, internal-api-svc
  Hop 3: sa-worker, db-url-config, api-key, secret-reader, tls-cert, ...
  → 13 nodes reachable
```

### 3. DFS Cycle Detection (`cycledetector.py`)

Uses **Johnson's algorithm** (`nx.simple_cycles`) to enumerate all simple cycles without duplicates. Cycles are normalised (rotated to lexicographic minimum start) to prevent reporting `A→B→A` and `B→A→B` separately.

```
Cycle #1: service-a ↔ service-b ↔ service-a
Relationships: admin-grant → admin-grant
Fix: revoke admin-grant from service-b back to service-a
```

### 4. Critical Node Analysis (`criticalnode.py`)

For every non-source, non-sink node: **copy the graph**, remove the node, recount all simple paths from every source to every sink (`nx.all_simple_paths`), compute paths eliminated. The original graph is never mutated. Returns ranked top-5 candidates.

```
Baseline: 46 attack paths
★ Remove: web-frontend (Pod) → eliminates 32/46 paths
  Runner-up: api-server (Pod) → eliminates 24/46 paths
```

---

## 📊 Input Schema

### `cluster-graph.json`

```json
{
  "nodes": [
    {
      "id":         "pod-webfront",
      "type":       "Pod",
      "name":       "web-frontend",
      "namespace":  "default",
      "risk_score": 7.5,
      "is_source":  false,
      "is_sink":    false,
      "cves":       ["CVE-2024-1234"]
    }
  ],
  "edges": [
    {
      "source":       "user-dev1",
      "target":       "pod-webfront",
      "relationship": "can-exec",
      "weight":       5.0,
      "cve":          "CVE-2024-1234",
      "cvss":         8.1
    }
  ]
}
```

#### Node fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique node identifier used in edges |
| `type` | string | `Pod`, `Service`, `Secret`, `Role`, `ClusterRole`, `ServiceAccount`, `User`, `ExternalActor`, `Database`, `Node`, `Namespace`, `PersistentVolume`, `ConfigMap` |
| `name` | string | Human-readable display name |
| `namespace` | string | Kubernetes namespace, or `"cluster"` / `"external"` |
| `risk_score` | float | Base risk score 0–10 |
| `is_source` | bool | `true` if this is a valid attacker entry point |
| `is_sink` | bool | `true` if this is a high-value target asset |
| `cves` | list | CVE IDs affecting this node e.g. `["CVE-2024-1234"]` |

#### Edge fields

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | Source node `id` |
| `target` | string | Target node `id` |
| `relationship` | string | e.g. `"routes-to"`, `"can-exec"`, `"bound-to"`, `"grants-access-to"` |
| `weight` | float | Dijkstra traversal cost (higher = riskier path) |
| `cve` | string\|null | CVE on this edge if the traversal exploits a vulnerability |
| `cvss` | float\|null | CVSS score of the edge CVE |

---

## 🧪 Running Tests

```bash
cd backend
pip install pytest
pytest tests/ -v
```

### Test case results

| ID | Algorithm | Input | Expected | Status |
|----|-----------|-------|----------|--------|
| BFS-1 | Blast Radius | `pod-webfront`, hops=3 | ≥10 nodes, correct hop layers | ✅ Pass |
| BFS-2 | Blast Radius | `cicd-bot`, hops=2 | `sa-cicd` at hop 1, `deployer` at hop 2 | ✅ Pass |
| BFS-3 | Blast Radius | isolated node, hops=3 | 0 reachable, no crash | ✅ Pass |
| DIJK-1 | Dijkstra | `user-dev1 → db-production` | 5 hops, cost=**24.1**, CVE annotated | ✅ Pass |
| DIJK-2 | Dijkstra | `internet → ns-kube-system` | 5 hops, cost=**32.0**, via cluster-admin | ✅ Pass |
| DIJK-3 | Dijkstra | unknown node → target | `found=False`, informative error, no crash | ✅ Pass |
| DFS-1 | Cycle Detection | full mock graph | exactly **1 cycle**: `[service-a, service-b]` | ✅ Pass |
| CNA-1 | Critical Node | full mock graph | `web-frontend`, **32/46** paths eliminated | ✅ Pass |

---

## 🔌 API Reference

### `POST /api/analyze` — YAML manifest scan
Accepts a Kubernetes YAML file upload. Returns nodes, edges, attack path, RBAC chains, and cluster risk score.

### `POST /api/explain` — AI node explanation
```json
{ "node_id": "pod-webfront", "node_type": "Pod", "vulnerabilities": ["CVE-2024-1234"] }
```
Returns a Groq LLaMA natural-language security explanation for the node.

### `POST /api/blast-radius` — BFS blast radius
```json
{ "node_id": "internet", "nodes": [...], "edges": [...], "hops": 3 }
```

---

## 🔐 Security Notes

- `.env` containing API keys is excluded from git via `.gitignore`
- `venv/` and `node_modules/` are excluded via `.gitignore`
- No user data is stored — all analysis is in-memory per request
- NVD API calls respect the 5 req/30s rate limit with automatic backoff

---

## 👥 Team Velora

