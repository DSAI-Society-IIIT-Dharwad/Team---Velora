"""
test.py
-------
Quick smoke test for the YAML parser.
Run from the backend/ directory:
  python test.py
"""
import re
import yaml
import os

# Use a path relative to this file — works on any machine
DEMO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'demo')
YAML_FILE = os.path.join(DEMO_DIR, 'vulnerable2.yaml')

with open(YAML_FILE, 'rb') as f:
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
                print(f"  kind={doc.get('kind')} name={doc.get('metadata',{}).get('name')}")
    except Exception as e:
        print(f"  ERROR: {e}")

print(f"\nTotal docs: {len(all_docs)}")