import yaml
import uuid
import re

# Complete OWASP K8s Top 10 risk weights
RISK_WEIGHTS = {
    "hostNetwork":              40,
    "hostPID":                  40,
    "hostIPC":                  35,
    "privileged":               45,
    "allowPrivilegeEscalation": 35,
    "wildcard_rbac":            35,
    "cluster_admin":            45,
    "exposed_secret":           25,
    "secret_env_var":           25,
    "hardcoded_password":       30,
    "missing_network_policy":   20,
    "nodeport_exposed":         30,
    "host_path_mount":          30,
    "docker_sock_mount":        50,
    "latest_image_tag":         15,
    "no_resource_limits":       15,
    "run_as_root":              30,
    "writable_root_fs":         25,
    "automount_sa_token":       20,
    "capabilities_added":       30,
    "net_raw_capability":       35,
}

# Sensitive keywords to detect hardcoded passwords
SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "token", "key",
    "api_key", "apikey", "credential", "auth", "jwt",
    "private", "certificate", "cert"
]

def clean_yaml_text(text: str) -> str:
    """Normalize line endings and remove problematic characters."""
    # Fix Windows line endings
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    # Remove lines with backticks (markdown code fences in comments)
    lines = text.splitlines()
    cleaned = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('```'):
            continue
        cleaned.append(line)
    return '\n'.join(cleaned)

def parse_yaml(content: bytes) -> dict:
    nodes = []
    edges = []

    # Decode bytes to string
    text = content.decode("utf-8", errors="ignore")

    # Clean the text — fix \r\n and backticks
    text = clean_yaml_text(text)

    # Split on apiVersion: lines to handle missing --- separators
    chunks = re.split(r'(?=^apiVersion:)', text, flags=re.MULTILINE)
    chunks = [c.strip() for c in chunks if c.strip()]

    all_docs = []
    for chunk in chunks:
        try:
            docs = list(yaml.safe_load_all(chunk))
            for doc in docs:
                if doc and isinstance(doc, dict) and "kind" in doc:
                    all_docs.append(doc)
        except Exception:
            continue

    if not all_docs:
        return {"nodes": [], "edges": [], "cluster_risk": 0}

    node_map = {}

    for doc in all_docs:
        kind      = doc.get("kind", "Unknown")
        metadata  = doc.get("metadata", {}) or {}
        name      = metadata.get("name", f"unnamed-{uuid.uuid4().hex[:6]}")
        namespace = metadata.get("namespace", "default")
        node_id   = f"{kind.lower()}-{name}"
        node_map[name] = node_id

        vulns = []
        risk  = 0

        # ── Pod / Deployment / DaemonSet / StatefulSet / Job ──
        if kind in ["Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"]:
            spec = doc.get("spec", {}) or {}
            if kind == "CronJob":
                spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}) or {}
            elif kind != "Pod":
                spec = spec.get("template", {}).get("spec", {}) or {}

            # ── Host-level access ──
            if spec.get("hostNetwork"):
                vulns.append("hostNetwork enabled — shares host network namespace")
                risk += RISK_WEIGHTS["hostNetwork"]

            if spec.get("hostPID"):
                vulns.append("hostPID enabled — can see all host processes")
                risk += RISK_WEIGHTS["hostPID"]

            if spec.get("hostIPC"):
                vulns.append("hostIPC enabled — can access host IPC namespace")
                risk += RISK_WEIGHTS["hostIPC"]

            if spec.get("automountServiceAccountToken") is True:
                vulns.append("automountServiceAccountToken enabled")
                risk += RISK_WEIGHTS["automount_sa_token"]

            # ── Containers ──
            containers = (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])

            for c in containers:
                if not isinstance(c, dict):
                    continue

                sc = c.get("securityContext", {}) or {}

                if sc.get("privileged"):
                    vulns.append(f"privileged container: {c.get('name','?')}")
                    risk += RISK_WEIGHTS["privileged"]

                if sc.get("allowPrivilegeEscalation"):
                    vulns.append(f"allowPrivilegeEscalation: {c.get('name','?')}")
                    risk += RISK_WEIGHTS["allowPrivilegeEscalation"]

                if sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is False:
                    vulns.append(f"runs as root: {c.get('name','?')}")
                    risk += RISK_WEIGHTS["run_as_root"]

                if sc.get("readOnlyRootFilesystem") is False:
                    vulns.append("writable root filesystem")
                    risk += RISK_WEIGHTS["writable_root_fs"]

                caps       = sc.get("capabilities", {}) or {}
                added_caps = caps.get("add", []) or []
                if added_caps:
                    vulns.append(f"dangerous capabilities added: {', '.join(added_caps)}")
                    risk += RISK_WEIGHTS["capabilities_added"]
                if "NET_RAW" in added_caps:
                    risk += RISK_WEIGHTS["net_raw_capability"]
                if "SYS_ADMIN" in added_caps:
                    risk += 20  # extra weight for SYS_ADMIN
                if "NET_ADMIN" in added_caps:
                    risk += 15

                # Image tag
                image = c.get("image", "")
                if image.endswith(":latest") or ":" not in image:
                    vulns.append(f"unpinned image tag: {image}")
                    risk += RISK_WEIGHTS["latest_image_tag"]

                # Resource limits
                resources = c.get("resources", {}) or {}
                if not resources.get("limits"):
                    vulns.append(f"no resource limits: {c.get('name','?')}")
                    risk += RISK_WEIGHTS["no_resource_limits"]

                # ── FIX 2: Detect BOTH secretKeyRef AND hardcoded passwords ──
                for env in (c.get("env", []) or []):
                    if not isinstance(env, dict):
                        continue
                    env_name  = env.get("name", "").lower()
                    env_value = env.get("value", "")

                    # secretKeyRef
                    vf = env.get("valueFrom", {}) or {}
                    if vf.get("secretKeyRef"):
                        vulns.append(f"secret exposed as env var: {env.get('name','?')}")
                        risk += RISK_WEIGHTS["secret_env_var"]

                    # Hardcoded password in plain value
                    elif env_value and isinstance(env_value, str):
                        if any(kw in env_name for kw in SENSITIVE_KEYWORDS):
                            vulns.append(f"hardcoded sensitive value in env: {env.get('name','?')}")
                            risk += RISK_WEIGHTS["hardcoded_password"]

                # Volume mounts
                for vm in (c.get("volumeMounts", []) or []):
                    if isinstance(vm, dict):
                        mp = vm.get("mountPath", "")
                        if "docker.sock" in mp:
                            vulns.append("docker.sock mounted — full container escape possible")
                            risk += RISK_WEIGHTS["docker_sock_mount"]
                        elif any(mp.startswith(p) for p in ["/host", "/proc", "/sys", "/root"]):
                            vulns.append(f"sensitive hostPath mount: {mp}")
                            risk += RISK_WEIGHTS["host_path_mount"]

                # Args — check for insecure flags
                args = c.get("args", []) or []
                for arg in args:
                    if isinstance(arg, str):
                        if "--enable-skip-login" in arg:
                            vulns.append("dashboard skip-login enabled — no authentication")
                            risk += 35
                        if "--insecure-bind-address" in arg:
                            vulns.append("insecure bind address — exposes on all interfaces")
                            risk += 25
                        if "--disable-settings-authorizer" in arg:
                            vulns.append("settings authorizer disabled")
                            risk += 20

            # Volumes
            for vol in (spec.get("volumes", []) or []):
                if isinstance(vol, dict):
                    hp   = vol.get("hostPath", {}) or {}
                    path = hp.get("path", "")
                    if "docker.sock" in path:
                        vulns.append("docker.sock volume — host Docker daemon fully exposed")
                        risk += RISK_WEIGHTS["docker_sock_mount"]
                    elif path == "/":
                        vulns.append("host root filesystem mounted — complete host access")
                        risk += RISK_WEIGHTS["host_path_mount"] + 20
                    elif any(path.startswith(p) for p in ["/etc", "/proc", "/sys"]):
                        vulns.append(f"sensitive hostPath volume: {path}")
                        risk += RISK_WEIGHTS["host_path_mount"]

            node_type = "pod"

        # ── Service ──
        elif kind == "Service":
            spec     = doc.get("spec", {}) or {}
            svc_type = spec.get("type", "ClusterIP")
            if svc_type == "NodePort":
                ports     = spec.get("ports", []) or []
                port_nums = [str(p.get("nodePort", "")) for p in ports if isinstance(p, dict)]
                vulns.append(f"NodePort exposed to internet: {', '.join(filter(None, port_nums))}")
                risk += RISK_WEIGHTS["nodeport_exposed"]
            elif svc_type == "LoadBalancer":
                vulns.append("LoadBalancer — publicly accessible")
                risk += RISK_WEIGHTS["nodeport_exposed"]
            node_type = "service"

        # ── ClusterRole / Role ──
        elif kind in ["ClusterRole", "Role"]:
            rules = doc.get("rules", []) or []
            for rule in (rules if isinstance(rules, list) else []):
                if not isinstance(rule, dict):
                    continue
                verbs      = rule.get("verbs", [])     or []
                resources  = rule.get("resources", []) or []
                api_groups = rule.get("apiGroups", []) or []
                if "*" in verbs:
                    vulns.append(f"wildcard verbs on: {', '.join(resources) or 'all'}")
                    risk += RISK_WEIGHTS["wildcard_rbac"]
                if "*" in resources:
                    vulns.append("wildcard resources — access to all K8s resource types")
                    risk += RISK_WEIGHTS["wildcard_rbac"]
                if "*" in api_groups:
                    vulns.append("wildcard apiGroups")
                    risk += RISK_WEIGHTS["wildcard_rbac"]
            node_type = "rbac"

        # ── ClusterRoleBinding / RoleBinding ──
        elif kind in ["ClusterRoleBinding", "RoleBinding"]:
            role_ref = doc.get("roleRef", {}) or {}
            if role_ref.get("name") == "cluster-admin":
                vulns.append("cluster-admin binding — grants full cluster control")
                risk += RISK_WEIGHTS["cluster_admin"]
            node_type = "rbac"

        # ── Secret ──
        elif kind == "Secret":
            secret_type = doc.get("type", "Opaque")
            data        = doc.get("data", {}) or {}
            vulns.append(f"secret resource ({secret_type}) with {len(data)} key(s) exposed")
            risk += RISK_WEIGHTS["exposed_secret"]
            node_type = "secret"

        # ── ConfigMap ──
        elif kind == "ConfigMap":
            data = doc.get("data", {}) or {}
            sensitive_keys = [
                k for k in data.keys()
                if any(s in k.lower() for s in SENSITIVE_KEYWORDS)
            ]
            if sensitive_keys:
                vulns.append(f"sensitive keys in ConfigMap: {', '.join(sensitive_keys)}")
                risk += RISK_WEIGHTS["exposed_secret"]
                # Check if actual values look like passwords
                for k in sensitive_keys:
                    v = data.get(k, "")
                    if isinstance(v, str) and len(v) > 3:
                        vulns.append(f"plaintext sensitive value in ConfigMap key: {k}")
                        risk += RISK_WEIGHTS["hardcoded_password"]
            node_type = "secret"

        # ── ServiceAccount ──
        elif kind == "ServiceAccount":
            if doc.get("automountServiceAccountToken") is True:
                vulns.append("automountServiceAccountToken enabled")
                risk += RISK_WEIGHTS["automount_sa_token"]
            node_type = "serviceaccount"

        # ── NetworkPolicy ──
        elif kind == "NetworkPolicy":
            spec         = doc.get("spec", {}) or {}
            pod_selector = spec.get("podSelector", {})
            if pod_selector == {} or pod_selector is None:
                vulns.append("NetworkPolicy applies to ALL pods — verify scope")
            node_type = "networkpolicy"

        # ── Ingress ──
        elif kind == "Ingress":
            vulns.append("Ingress — external traffic entry point")
            risk += 20
            node_type = "service"

        elif kind == "Namespace":
            node_type = "other"

        else:
            node_type = "other"

        nodes.append({
            "id":              node_id,
            "name":            name,
            "kind":            kind,
            "type":            node_type,
            "namespace":       namespace,
            "vulnerabilities": list(set(vulns)),
            "risk":            min(risk, 100),
        })

    # ── FIX 3: Better error message node if nothing parsed ──
    if not nodes:
        return {
            "nodes": [],
            "edges": [],
            "cluster_risk": 0,
            "error": "No valid Kubernetes resources found. Please upload a valid K8s YAML file."
        }

    # ── FIX 4: Namespace-aware edge building ──
    for n in nodes:
        if n["type"] == "pod":
            for other in nodes:
                if other["id"] == n["id"]:
                    continue
                # Only connect nodes in same namespace OR cluster-wide resources
                same_ns = (
                    n["namespace"] == other["namespace"] or
                    other["kind"] in ["ClusterRoleBinding", "ClusterRole"]
                )
                if same_ns and other["type"] in ["service", "secret", "rbac", "serviceaccount", "networkpolicy"]:
                    edges.append({
                        "source": n["id"],
                        "target": other["id"],
                        "weight": (n["risk"] + other["risk"]) / 2,
                    })

        elif n["type"] == "service":
            for other in nodes:
                if other["type"] == "secret" and other["namespace"] == n["namespace"]:
                    edges.append({
                        "source": n["id"],
                        "target": other["id"],
                        "weight": (n["risk"] + other["risk"]) / 2,
                    })

        elif n["type"] == "rbac":
            for other in nodes:
                if other["type"] == "serviceaccount":
                    edges.append({
                        "source": n["id"],
                        "target": other["id"],
                        "weight": (n["risk"] + other["risk"]) / 2,
                    })

    return {
        "nodes":        nodes,
        "edges":        edges,
        "cluster_risk": 0,
    }