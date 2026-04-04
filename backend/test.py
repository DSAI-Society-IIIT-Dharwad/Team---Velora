import re, yaml

# Simulate exactly what FastAPI sends to parser
with open('C:/Users/Nandita/kubeshield/demo/vulnerable2.yaml', 'rb') as f:
    content = f.read()

print(f"File size: {len(content)} bytes")
print(f"First 100 chars: {content[:100]}")

text = content.decode("utf-8", errors="ignore")
chunks = re.split(r'(?=^apiVersion:)', text, flags=re.MULTILINE)
chunks = [c.strip() for c in chunks if c.strip()]
print(f"Found {len(chunks)} chunks")

all_docs = []
for chunk in chunks:
    try:
        docs = list(yaml.safe_load_all(chunk))
        for doc in docs:
            if doc and isinstance(doc, dict) and "kind" in doc:
                all_docs.append(doc)
                print(f"  ✅ kind={doc.get('kind')} name={doc.get('metadata',{}).get('name')}")
    except Exception as e:
        print(f"  ❌ ERROR: {e}")

print(f"\nTotal docs: {len(all_docs)}")

# Now simulate scoring
for doc in all_docs:
    kind = doc.get('kind')
    name = doc.get('metadata', {}).get('name')
    spec = doc.get('spec', {}) or {}
    if kind in ['Deployment', 'Pod', 'DaemonSet']:
        if kind != 'Pod':
            spec = spec.get('template', {}).get('spec', {}) or {}
        print(f"\n{kind}/{name}:")
        print(f"  hostNetwork: {spec.get('hostNetwork')}")
        print(f"  hostPID: {spec.get('hostPID')}")
        containers = (spec.get('containers', []) or []) + (spec.get('initContainers', []) or [])
        print(f"  containers: {len(containers)}")
        for c in containers:
            if isinstance(c, dict):
                sc = c.get('securityContext', {}) or {}
                print(f"    container: {c.get('name')} privileged={sc.get('privileged')} runAsUser={sc.get('runAsUser')}")
                vols = c.get('volumeMounts', []) or []
                for v in vols:
                    print(f"      volumeMount: {v.get('mountPath')}")