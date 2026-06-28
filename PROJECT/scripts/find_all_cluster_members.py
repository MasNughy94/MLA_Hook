"""Find all members of each multi-member cluster from the file catalog."""
import json
from collections import defaultdict

# Load cluster info
with open('analysis/cluster_report.json') as f:
    clusters = json.load(f)

# Load file catalog for per-file tag info
with open('analysis/roo_file_catalog.json') as f:
    catalog = json.load(f)

print(f"Catalog entries: {len(catalog)}")
print(f"Catalog type: {type(catalog).__name__}")

# Check catalog structure
if isinstance(catalog, dict):
    print(f"Keys: {list(catalog.keys())[:5]}")
    sample_key = list(catalog.keys())[0]
    print(f"Sample entry: {json.dumps(catalog[sample_key], indent=2)[:200]}")
elif isinstance(catalog, list):
    print(f"First item keys: {list(catalog[0].keys())[:10]}")
