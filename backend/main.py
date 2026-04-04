from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from parser import parse_yaml
from scorer import score_graph
from pathfinder import find_attack_path, calculate_blast_radius, trace_rbac_chains
from ai import explain_node
import uvicorn

app = FastAPI(title="KubeShield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()

    graph_data  = parse_yaml(content)
    scored      = score_graph(graph_data)
    path        = find_attack_path(scored)
    rbac_chains = trace_rbac_chains(scored)

    return {
        "nodes":        scored["nodes"],
        "edges":        scored["edges"],
        "attack_path":  path,
        "cluster_risk": scored["cluster_risk"],
        "rbac_chains":  rbac_chains,
    }

@app.post("/api/explain")
async def explain(data: dict):
    explanation = explain_node(
        data["node_id"],
        data["node_type"],
        data["vulnerabilities"]
    )
    return {"explanation": explanation}

@app.post("/api/blast-radius")
async def blast_radius(data: dict):
    """
    Accepts: { node_id, nodes, edges, hops }
    Returns: blast radius report for the given node
    """
    graph_data = {
        "nodes": data["nodes"],
        "edges": data["edges"],
    }
    result = calculate_blast_radius(graph_data, data["node_id"], data.get("hops", 2))
    return result

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)