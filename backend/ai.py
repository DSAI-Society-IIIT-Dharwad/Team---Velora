import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

def explain_node(node_id: str, node_type: str, vulnerabilities: list) -> dict:
    if not vulnerabilities:
        return {
            "risk_explanation": "No vulnerabilities detected on this node.",
            "fix": "This node appears secure. Continue monitoring.",
            "severity": "SAFE"
        }

    vuln_list = "\n".join(f"- {v}" for v in vulnerabilities)

    prompt = f"""You are a Kubernetes security expert. Analyze this vulnerable cluster node and respond in JSON only.

Node ID: {node_id}
Node Type: {node_type}
Vulnerabilities found:
{vuln_list}

Respond ONLY with this exact JSON format, no markdown, no extra text:
{{
  "risk_explanation": "2-3 sentence plain English explanation of why this is dangerous",
  "fix": "Exact Kubernetes YAML fix or kubectl command to remediate this",
  "severity": "CRITICAL or HIGH or MEDIUM or LOW"
}}"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=400,
        )

        import json
        raw = response.choices[0].message.content.strip()
        return json.loads(raw)

    except Exception as e:
        return {
            "risk_explanation": f"Could not generate explanation: {str(e)}",
            "fix": "Please check your Groq API key and try again.",
            "severity": "UNKNOWN"
        }