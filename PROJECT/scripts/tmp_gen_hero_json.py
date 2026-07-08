"""Generate hero_db schema JSON in semantic_v3 format."""
import json

# Load tag analysis
with open(r'analysis/hero_db_schema_analysis.json') as f:
    data = json.load(f)

fa = data['field_analysis']
total_entries = data['total_entries']

# Semantic name mapping based on tag analysis
def classify_tag(tag_num, info):
    """Generate classifications for a tag."""
    uv = info.get('unique_vals', 0)
    vals = info.get('samples', [])
    mn, mx = info.get('min', 0), info.get('max', 0)
    always_zero = info.get('always_zero', False)
    svals = set(vals)
    presence = info.get('presence', 0)
    
    classifications = []
    
    # 1. Constants / always zero
    if always_zero or (uv == 1 and 0 in svals):
        classifications.append({
            "name": "Reserved_Zero",
            "confidence": 0.95,
            "evidence": "Always 0 â€” unused field slot"
        })
    
    if uv == 1:
        classifications.append({
            "name": "Constant",
            "confidence": 0.95,
            "evidence": f"Always {list(svals)[0]}"
        })
        return classifications
    
    # 2. Boolean flag (values in range [0, 1])
    if svals <= {0, 1}:
        classifications.append({
            "name": "Flag_01",
            "confidence": 0.90,
            "evidence": "Boolean flag (0/1)"
        })
        return classifications
    
    # 3. Small enums 1-5 (class/faction)
    small_vals = [v for v in svals if 0 <= v <= 5]
    if len(small_vals) == len(svals) and len(svals) >= 4 and mx <= 5:
        classifications.append({
            "name": "ClassFaction_Enum",
            "confidence": 0.85,
            "evidence": f"Values 1-5: class or faction enum ({len(svals)} unique)"
        })
        return classifications
    
    # 4. Star/quality (1-8)
    small_vals = [v for v in svals if 0 <= v <= 8]  
    if len(small_vals) == len(svals) and len(svals) >= 4 and mx <= 8:
        classifications.append({
            "name": "StarQuality_Enum",
            "confidence": 0.80,
            "evidence": f"Values 1-8: star/quality rating ({len(svals)} unique)"
        })
        return classifications
    
    # 5. Small enum (2-10 unique, small range)
    if 2 <= uv <= 10 and mx <= 100:
        classifications.append({
            "name": "Small_Enum",
            "confidence": 0.75,
            "evidence": f"{uv} unique values in [{mn}, {mx}]"
        })
        return classifications
    
    # 6. Hero ID range (1000-9999)
    id_vals = [v for v in svals if 1000 <= v <= 9999]
    if len(id_vals) >= 3:
        classifications.append({
            "name": "EntityID_4Digit",
            "confidence": 0.70,
            "evidence": f"{len(id_vals)} values in 4-digit ID range: {id_vals[:5]}"
        })
    
    # 7. Skill ID range (50000-60000)
    skill_vals = [v for v in svals if 50000 <= v <= 60000]
    if len(skill_vals) >= 3:
        classifications.append({
            "name": "Skill_Reference",
            "confidence": 0.60,
            "evidence": f"{len(skill_vals)} values in skill reference range: {skill_vals[:5]}"
        })
    
    # 8. Large reference (50000+)
    large_vals = [v for v in svals if v >= 50000]
    if len(large_vals) >= 1 and not skill_vals:
        classifications.append({
            "name": "Large_Ref",
            "confidence": 0.50,
            "evidence": f"Range includes values >= 50000: {large_vals[:3]}"
        })
    
    # 9. Medium reference (100-10000)
    ref_vals = [v for v in svals if 100 <= v <= 10000 and v > 0]
    if uv >= 5 and len(ref_vals) >= 3:
        classifications.append({
            "name": "Reference_Index",
            "confidence": 0.55,
            "evidence": f"{len(ref_vals)} reference values, {uv} unique, range [{mn}, {mx}]"
        })
    
    # 10. Generic enum sizes
    if 11 <= uv <= 20:
        classifications.append({
            "name": "Medium_Enum",
            "confidence": 0.45,
            "evidence": f"{uv} unique values, medium-controlled vocabulary"
        })
    elif 21 <= uv <= 50:
        classifications.append({
            "name": "Large_Enum",
            "confidence": 0.40,
            "evidence": f"{uv} unique values, large-controlled vocabulary"
        })
    
    # 11. Unstructured integer
    if uv >= 30:
        classifications.append({
            "name": "Generic_Integer",
            "confidence": 0.35,
            "evidence": f"{uv} unique values â€” unstructured integer reference"
        })
    
    if not classifications:
        classifications.append({
            "name": "Unknown",
            "confidence": 0.20,
            "evidence": f"{uv} unique, range [{mn}, {mx}]"
        })
    
    return classifications

def best_guess(classifications):
    """Pick best classification."""
    if not classifications:
        return "Unknown", 0.0
    best = max(classifications, key=lambda c: c['confidence'])
    return best['name'], best['confidence']

# Build fields dict
fields = {}
field_index = 0

# Process tags sorted by their byte value
for tag_str in sorted(fa.keys(), key=lambda x: int(x)):
    tag_num = int(tag_str)
    info = fa[tag_str]
    
    tag_hex = f"0x{tag_num:02x}"
    tc = chr(tag_num) if 32 <= tag_num < 127 else None
    
    vals = info.get('samples', [])
    mn = info.get('min', 0)
    mx = info.get('max', 0)
    uv = info.get('unique_vals', 0)
    
    # Full observed values from samples
    observed = list(dict.fromkeys(vals))  # ordered unique
    
    classifications = classify_tag(tag_num, info)
    best_name, best_conf = best_guess(classifications)
    
    field_key = f"Field_{field_index}"
    fields[field_key] = {
        "field_index": field_index,
        "tag": tag_num,
        "tag_hex": tag_hex,
        "tag_char": tc,
        "value_range": [mn, mx],
        "unique_values": uv,
        "observed_values": observed,
        "classifications": classifications,
        "best_name": best_name,
        "best_confidence": round(best_conf, 2)
    }
    field_index += 1

# Detect entry signature patterns
import os
from collections import defaultdict

DEC_BATCH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\decrypted\dec_batch'
TARGET = '0217cbdae530696836de83aa3c162e1a.mt.dec'

def parse_entries(path):
    with open(path, 'rb') as f:
        d = f.read()
    body = d[69:]
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            records.append({'offset': i, 'tag': tag, 'val': val})
    ents = []
    if records:
        gap = 30
        cur = [records[0]]
        for r in records[1:]:
            if r['offset'] - cur[-1]['offset'] > gap:
                ents.append(cur)
                cur = [r]
            else:
                cur.append(r)
        if cur:
            ents.append(cur)
    return ents

entries = parse_entries(os.path.join(DEC_BATCH, TARGET))

sig_groups = defaultdict(list)
for eidx, entry in enumerate(entries):
    sig_groups[tuple(sorted(set(r['tag'] for r in entry)))].append(eidx)

# Build entry_type_summary
entry_types = []
for signature, eidxs in sorted(sig_groups.items(), key=lambda x: -len(x[1]))[:30]:
    tag_list = sorted(signature)
    tag_hexes = [f"0x{t:02x}" for t in tag_list]
    chars = ''.join(chr(t) if 32 <= t < 127 else '.' for t in tag_list)
    
    entry_types.append({
        "tag_signature": tag_hexes,
        "char_signature": chars,
        "entry_count": len(eidxs),
        "percentage": round(len(eidxs) / total_entries * 100, 1),
        "example_entry_index": eidxs[0]
    })

# Build output structure
output = {
    "metadata": {
        "game": "Mobile Legends Adventure (com.moonton.mobilehero)",
        "description": "Complete semantic reconstruction of Roo binary format data",
        "total_clusters": 7092,
        "merged_clusters": 49
    },
    "entity_types": {
        "hero_db": {
            "entity_type": "hero_db",
            "file_count": 55,
            "avg_entry_count": round(5716),  # from deep_value_analysis cluster avg
            "cluster_count": 1,
            "description": "Hero Master DB â€” central entity registry with 255 tag-based field selectors across 2980 heterogeneous entries",
            "entry_type_catalog": entry_types,
            "fields": fields
        }
    }
}

# Write output
outpath = r'semantic/hero_db_schema.json'
with open(outpath, 'w') as f:
    json.dump(output, f, indent=2)

print(f"Written {outpath}")
print(f"  Fields: {len(fields)}")
print(f"  Entry types cataloged: {len(entry_types)}")
