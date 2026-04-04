"""
nvd.py
------
Integrates with the NIST National Vulnerability Database (NVD) API
to fetch live CVSS scores for CVE IDs found in the cluster graph.

Bonus B2: Live CVE Scoring (+5 marks)

API: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXX
Rate limit: 5 requests / 30 seconds (unauthenticated)
Fallback: returns mock CVSS score if API unavailable or rate-limited.
"""

import time
import urllib.request
import urllib.error
import json

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limit: max 5 requests per 30 seconds (NVD unauthenticated limit)
_REQUEST_TIMES: list = []
_RATE_WINDOW   = 30   # seconds
_RATE_LIMIT    = 5    # requests per window

# Fallback scores for known CVEs in the mock dataset (used if API down)
_FALLBACK_CVSS = {
    "CVE-2024-1234": 8.1,
    "CVE-2023-4567": 7.2,
    "CVE-2024-9999": 6.5,
    "CVE-2024-3116": 9.0,
}


def _respect_rate_limit() -> None:
    """Sleep if necessary to stay within NVD's 5 req/30s limit."""
    now = time.time()
    # Remove timestamps older than the window
    global _REQUEST_TIMES
    _REQUEST_TIMES = [t for t in _REQUEST_TIMES if now - t < _RATE_WINDOW]
    if len(_REQUEST_TIMES) >= _RATE_LIMIT:
        sleep_for = _RATE_WINDOW - (now - _REQUEST_TIMES[0]) + 0.5
        if sleep_for > 0:
            time.sleep(sleep_for)
    _REQUEST_TIMES.append(time.time())


def fetch_cvss(cve_id: str) -> dict:
    """
    Fetch CVSS score and severity for a single CVE from NIST NVD.

    Args:
        cve_id: CVE identifier, e.g. 'CVE-2024-1234'

    Returns:
        dict with keys: cve_id, cvss_score, severity, source
          source is 'nvd' if fetched live, 'fallback' if API unavailable
    """
    _respect_rate_limit()

    url = f"{NVD_API_URL}?cveId={cve_id}"

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "KubeShield/1.0 (hackathon security tool)"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return _fallback(cve_id, reason="not found in NVD")

        cve_data = vulns[0].get("cve", {})
        metrics  = cve_data.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if version_key in metrics and metrics[version_key]:
                entry  = metrics[version_key][0]
                data_v = entry.get("cvssData", {})
                score  = data_v.get("baseScore", 0.0)
                sev    = data_v.get("baseSeverity",
                         _score_to_severity(score)).upper()
                return {
                    "cve_id":     cve_id,
                    "cvss_score": score,
                    "severity":   sev,
                    "source":     "nvd",
                    "version":    version_key[-3:],
                }

        return _fallback(cve_id, reason="no CVSS metrics in NVD record")

    except urllib.error.HTTPError as e:
        return _fallback(cve_id, reason=f"HTTP {e.code}")
    except Exception as e:
        return _fallback(cve_id, reason=str(e)[:60])


def enrich_graph_with_nvd(G) -> dict:
    """
    Scan all edges in graph G for CVE IDs and fetch live CVSS scores.
    Updates edge data in place and returns a summary report.

    Args:
        G: NetworkX DiGraph from graphparser.load_graph()

    Returns:
        dict with keys:
          enriched  (list) - CVEs successfully fetched from NVD
          fallback  (list) - CVEs that used fallback scores
          unchanged (list) - edges with no CVE
    """
    enriched  = []
    fallback  = []

    for src, tgt, data in G.edges(data=True):
        cve_id = data.get("cve")
        if not cve_id:
            continue

        result = fetch_cvss(cve_id)
        # Update edge with live (or fallback) CVSS score
        data["cvss"]          = result["cvss_score"]
        data["cvss_source"]   = result["source"]
        data["cvss_severity"] = result["severity"]

        if result["source"] == "nvd":
            enriched.append(result)
        else:
            fallback.append(result)

    return {"enriched": enriched, "fallback": fallback}


def format_nvd_report(enrichment: dict) -> str:
    """Format the NVD enrichment summary for the CLI report."""
    enriched = enrichment.get("enriched", [])
    fallback = enrichment.get("fallback", [])

    lines = []
    lines.append(f"  CVEs fetched from NIST NVD   : {len(enriched)}")
    lines.append(f"  CVEs using fallback scores   : {len(fallback)}")

    for item in enriched:
        lines.append(
            f"    ✓  {item['cve_id']:<20}  "
            f"CVSS {item['cvss_score']}  [{item['severity']}]  "
            f"(v{item.get('version','?')})"
        )
    for item in fallback:
        lines.append(
            f"    ⚠  {item['cve_id']:<20}  "
            f"CVSS {item['cvss_score']}  [FALLBACK — {item.get('reason','')}]"
        )

    return "\n".join(lines)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fallback(cve_id: str, reason: str = "") -> dict:
    """Return a fallback result using the mock-data score."""
    score = _FALLBACK_CVSS.get(cve_id, 5.0)
    return {
        "cve_id":     cve_id,
        "cvss_score": score,
        "severity":   _score_to_severity(score),
        "source":     "fallback",
        "reason":     reason,
    }


def _score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"