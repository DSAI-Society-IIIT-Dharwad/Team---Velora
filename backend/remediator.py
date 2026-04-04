"""
remediator.py
-------------
Generates specific, actionable remediation advice for each attack path.

Called by dijkstra.format_path_report() to append a FIX block under
each detected path, satisfying Deliverable 2.3 of the scoring rubric.

Remediation rules (in priority order):
  1. CVE on edge           → patch or upgrade the affected node
  2. cluster-admin binding → replace with least-privilege Role
  3. RoleBinding edge      → remove specific RoleBinding
  4. Secret access edge    → rotate secret and restrict RBAC
  5. falls-back-to default → disable automounting
  6. default path          → reduce privileges
"""


# ── Relationship-based remediation rules ─────────────────────────────────────

_REL_RULES = {
    "falls-back-to": (
        "Set `automountServiceAccountToken: false` on {src} "
        "to prevent automatic default SA binding."
    ),
    "admin-grant": (
        "Revoke admin-grant from {tgt} to {src}. "
        "Replace with a least-privilege Role scoped to required operations only."
    ),
    "can-exec-on": (
        "Remove `exec` verb from Role {src}. "
        "Restrict pod-exec permissions to break this privilege-escalation hop."
    ),
    "grants-access-to": (
        "Rotate secret {src} immediately. "
        "Apply a NetworkPolicy to restrict which pods can reach {tgt}."
    ),
    "impersonates": (
        "Revoke impersonation permission for {src}. "
        "Use short-lived OIDC tokens instead of impersonation grants."
    ),
}

# Node-type-based rules (applied when relationship rule doesn't match)
_TYPE_RULES = {
    "ClusterRole": (
        "Scope ClusterRole {tgt} to a namespace-scoped Role "
        "— cluster-wide privileges are rarely required."
    ),
    "Secret": (
        "Enable Kubernetes Secrets encryption at rest (EncryptionConfig). "
        "Audit which ServiceAccounts can read {tgt} via `kubectl get rolebindings -A`."
    ),
    "Database": (
        "Place {tgt} behind a NetworkPolicy that whitelists only required pods. "
        "Rotate database credentials."
    ),
    "Node": (
        "Apply PodSecurityAdmission to prevent privileged containers from "
        "reaching {tgt}. Patch node CVEs via OS update."
    ),
    "PersistentVolume": (
        "Restrict PVC {tgt} with a StorageClass that enforces ReadOnlyMany "
        "for non-owning pods."
    ),
    "Namespace": (
        "Add a LimitRange and ResourceQuota to namespace {tgt}. "
        "Audit ClusterRoleBindings that grant access."
    ),
}


def generate_remediation(path_edges: list) -> str:
    """
    Generate specific remediation advice for a single attack path.

    Args:
        path_edges: List of edge detail dicts from dijkstra._extract_edge_details()
                    Each dict has: src, src_name, src_type, tgt, tgt_name,
                                   tgt_type, relationship, cve, cvss

    Returns:
        Multi-line string with one FIX bullet per relevant hop.
        Always returns at least one remediation item.
    """
    fixes = []

    for edge in path_edges:
        rel      = edge.get("relationship", "")
        src_name = edge.get("src_name", edge.get("src", "?"))
        tgt_name = edge.get("tgt_name", edge.get("tgt", "?"))
        tgt_type = edge.get("tgt_type", "")
        cve      = edge.get("cve")
        cvss     = edge.get("cvss")

        # Rule 1: CVE on this edge — always emit a patch advisory
        if cve:
            severity = "critical" if (cvss or 0) >= 9.0 else "high-priority"
            fixes.append(
                f"  → Patch {cve} (CVSS {cvss}) on {src_name}: "
                f"update container image or apply vendor hotfix immediately "
                f"({severity})."
            )

        # Rule 2: cluster-admin binding
        if tgt_name and "cluster-admin" in tgt_name.lower():
            fixes.append(
                f"  → Replace cluster-admin ClusterRoleBinding on {src_name} "
                f"with a least-privilege Role scoped to required verbs only."
            )
            continue

        # Rule 3: Relationship-specific rule
        if rel in _REL_RULES:
            fixes.append(
                "  → " + _REL_RULES[rel].format(src=src_name, tgt=tgt_name)
            )
            continue

        # Rule 4: bound-to a Role/ClusterRole
        if rel == "bound-to":
            fixes.append(
                f"  → Remove RoleBinding that binds {src_name} to {tgt_name}. "
                f"Audit whether {src_name} needs these permissions."
            )
            continue

        # Rule 5: Target-type fallback
        if tgt_type in _TYPE_RULES:
            fixes.append(
                "  → " + _TYPE_RULES[tgt_type].format(src=src_name, tgt=tgt_name)
            )

    # Always guarantee at least one item
    if not fixes:
        last = path_edges[-1] if path_edges else {}
        fixes.append(
            f"  → Apply least-privilege RBAC: audit and remove unnecessary "
            f"permissions leading to {last.get('tgt_name', 'target node')}."
        )

    return "\n".join(fixes)


def generate_cycle_remediation(cycle_names: list, cycle_relationships: list = None) -> str:
    """
    Generate remediation for a detected permission cycle.

    Args:
        cycle_names:         List of node names in the cycle
        cycle_relationships: Optional list of relationship labels along the cycle

    Returns:
        Single-line remediation string
    """
    if len(cycle_names) < 2:
        return "  → Audit this node for self-referential permission grants."

    a, b = cycle_names[0], cycle_names[1]
    rel  = cycle_relationships[0] if cycle_relationships else "mutual grant"

    return (
        f"  → Break cycle: revoke {rel} from {b} back to {a}. "
        f"Cycles indicate mutual privilege escalation — a critical misconfiguration."
    )