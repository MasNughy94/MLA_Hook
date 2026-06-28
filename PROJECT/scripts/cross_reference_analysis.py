"""
Cross-reference analysis: map corpus clusters to known game entity types.
Reads cluster definitions, parses sample files, and identifies entity types
based on entry counts, ID ranges, and value patterns.
"""
import os, sys, json
import struct
from collections import defaultdict
from itertools import groupby

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'
CLUSTER_REPORT = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis\cluster_report.json'
CORPUS_SUMMARY = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis\corpus_summary.json'

# Known game entity count patterns (from typical gacha games)
GAME_PATTERNS = [
    ("hero_db",       200, 350,   "Hero/character database"),
    ("skill_db",      800, 1200,  "Skill database"),
    ("item_db",       500, 2000,  "Item/equipment database"),
    ("stage_db",      100, 500,   "Stage/mission definitions"),
    ("language_ko",   800, 1500,  "Korean language strings"),
    ("language_en",   800, 1500,  "English language strings"),
    ("language_ja",   800, 1500,  "Japanese language strings"),
    ("monster_db",    300, 800,   "Monster/enemy database"),
    ("status_db",     50,  100,   "Status effect/buff definitions"),
    ("team_db",       50,  200,   "Team/composition data"),
    ("quest_db",      100, 500,   "Quest/mission data"),
    ("shop_db",       50,  300,   "Shop/item shop data"),
    ("gacha_db",      50,  200,   "Gacha/summon rates"),
    ("event_db",      20,  100,   "Event definitions"),
    ("achievement_db", 50, 200,   "Achievement definitions"),
]

def parse_roo_file(filepath):
    """Parse a decompressed .mt file and return structured data."""
    with open(filepath, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        records.append((i, tag, v1, v2))
    
    template = [(i, tag, v1, v2) for i, tag, v1, v2 in records if tag == 0 and (v1 != 0 or v2 != 0)]
    overrides = [(i, tag, v1, v2) for i, tag, v1, v2 in records if tag != 0]
    empty = [(i, tag, v1, v2) for i, tag, v1, v2 in records if tag == 0 and v1 == 0 and v2 == 0]
    
    # Cluster entries by gap threshold
    gap_threshold = 30
    entries = []
    if overrides:
        sorted_ov = sorted(overrides, key=lambda x: x[0])
        current = [sorted_ov[0]]
        for rec in sorted_ov[1:]:
            if rec[0] - current[-1][0] > gap_threshold:
                entries.append(current)
                current = [rec]
            else:
                current.append(rec)
        if current:
            entries.append(current)
    
    return {
        'filepath': filepath,
        'filename': os.path.basename(filepath),
        'file_size': len(data),
        'body_size': len(body),
        'num_records': len(records),
        'num_template': len(template),
        'num_override': len(overrides),
        'num_empty': len(empty),
        'entries': entries,
        'num_entries': len(entries),
    }

def extract_entry_fields(entries):
    """Build per-position field values across all entries."""
    if not entries:
        return {}
    
    # Build position->tag mapping from entries
    pos_tags = {}  # position_index -> tag
    pos_values = defaultdict(list)  # position_index -> [values]
    
    for entry in entries:
        for idx, (offset, tag, v1, v2) in enumerate(entry):
            val = v1 | (v2 << 8)
            if idx not in pos_tags:
                pos_tags[idx] = tag
            pos_values[idx].append(val)
    
    result = {}
    for pos in sorted(pos_tags.keys()):
        vals = pos_values[pos]
        result[pos] = {
            'tag': pos_tags[pos],
            'tag_hex': f'0x{pos_tags[pos]:02x}',
            'count': len(vals),
            'min': min(vals),
            'max': max(vals),
            'unique': len(set(vals)),
            'values_sample': sorted(set(vals))[:30],
        }
    return result

def classify_field(field_info):
    """Classify a field based on its value pattern."""
    vals = field_info['values_sample']
    unique = field_info['unique']
    total = field_info['count']
    min_v, max_v = field_info['min'], field_info['max']
    
    classifications = []
    
    # Check if it's a primary key (sequential, 1-per-entry)
    if unique == total and total > 5:
        expected = list(range(min_v, min_v + total))
        actual = sorted(vals[:total] if len(vals) >= total else vals)
        if actual == expected[:len(actual)]:
            classifications.append(('primary_key_seq', 0.95))
        elif all(isinstance(v, int) for v in vals) and unique == total:
            classifications.append(('primary_key_unique', 0.85))
    
    # Check if it's a boolean flag
    if set(vals) <= {0, 1}:
        classifications.append(('flag', 0.95))
    elif set(vals) <= {0, 1, 2}:
        classifications.append(('small_flag', 0.8))
    
    # Check if enum
    if unique <= 8 and total > unique * 3:
        classifications.append(('small_enum', 0.85))
    elif unique <= 20 and total > unique * 2:
        classifications.append(('enum', 0.7))
    
    # Check if level/percentage (0-100 or 0-10000)
    if max_v <= 100 and unique > 3:
        classifications.append(('level_or_pct', 0.6))
    elif max_v <= 10000 and unique > 10:
        classifications.append(('value_range', 0.4))
    
    # Check if it's an ID reference
    if min_v >= 1 and max_v <= 200 and unique == total:
        classifications.append(('small_entity_id', 0.65))
    elif min_v >= 1 and max_v <= 1000 and unique == total:
        classifications.append(('entity_id', 0.5))
    
    # Check if constant
    if unique == 1:
        classifications.append(('constant', 0.9))
    
    # Default
    if not classifications:
        classifications.append(('generic_u16', 0.2))
    
    # Sort by confidence
    classifications.sort(key=lambda x: -x[1])
    return classifications

def classify_entries(entries):
    """Classify what type of game data the entries represent."""
    num = len(entries)
    matches = []
    for name, lo, hi, desc in GAME_PATTERNS:
        if lo <= num <= hi:
            confidence = 1.0 - abs(num - (lo+hi)//2) / ((hi-lo)//2 + 1)
            matches.append((name, confidence, desc, num))
    matches.sort(key=lambda x: -x[1])
    return matches

def analyze_cluster(cluster_entry, corpus_index):
    """Analyze all sample files in a cluster."""
    members = cluster_entry['sample_members'][:3]  # up to 3 sample files
    num_tags = cluster_entry['num_tags']
    tags = cluster_entry['tags']
    
    results = []
    for member in members:
        filepath = os.path.join(DEC_BATCH, member)
        if not os.path.exists(filepath):
            continue
        
        parsed = parse_roo_file(filepath)
        fields = extract_entry_fields(parsed['entries'])
        
        # Add corpus info
        cinfo = corpus_index.get(member, {})
        
        results.append({
            'filename': member,
            'file_size': parsed['file_size'],
            'body_size': parsed['body_size'],
            'num_entries': parsed['num_entries'],
            'num_override': parsed['num_override'],
            'override_density': f"{parsed['num_override'] / max(parsed['num_records'], 1) * 100:.0f}%",
            'entries_per_field': parsed['num_entries'] // max(len(fields), 1) if fields else 0,
            'fields': fields,
            'entity_matches': classify_entries(parsed['entries']),
        })
    
    return {
        'num_members': cluster_entry['num_members'],
        'num_tags': num_tags,
        'tags': tags,
        'samples': results,
    }

def print_cluster_analysis(cluster_name, analysis):
    """Print a formatted analysis of a cluster."""
    print(f"\n{'='*60}")
    print(f"CLUSTER: {cluster_name}")
    print(f"  Members: {analysis['num_members']}, Tags: {analysis['num_tags']}")
    print(f"  Tags: {', '.join(analysis['tags'][:10])}{'...' if len(analysis['tags']) > 10 else ''}")
    
    for sample in analysis['samples']:
        print(f"\n  --- Sample: {sample['filename']} ---")
        print(f"  Size: {sample['file_size']:,} bytes, Body: {sample['body_size']:,}")
        print(f"  Entries: {sample['num_entries']}, Overrides: {sample['num_override']}")
        
        # Entity type matches
        if sample['entity_matches']:
            print(f"  Entity matches:")
            for name, conf, desc, num in sample['entity_matches'][:3]:
                print(f"    {desc} ({num} entries): confidence {conf:.0%}")
        
        # Internal fields
        print(f"  Fields ({len(sample['fields'])}):")
        for pos, finfo in sorted(sample['fields'].items())[:15]:
            classifications = classify_field(finfo)
            best_type = classifications[0][0] if classifications else 'unknown'
            best_conf = classifications[0][1] if classifications else 0
            
            tag = finfo['tag']
            ch = chr(tag) if 32 <= tag < 127 else '.'
            
            print(f"    pos={pos:2d} tag=0x{tag:02x}('{ch}'): "
                  f"range=[{finfo['min']:5d}-{finfo['max']:5d}], "
                  f"unique={finfo['unique']:4d}/{finfo['count']}, "
                  f"type={best_type} ({best_conf:.0%})")
        
        if len(sample['fields']) > 15:
            print(f"    ... +{len(sample['fields']) - 15} more fields")

def main():
    # Load cluster report
    print("Loading cluster report...")
    with open(CLUSTER_REPORT, 'r') as f:
        clusters = json.load(f)
    
    # Load corpus summary for quick lookup
    print("Loading corpus summary...")
    corpus_index = {}
    with open(CORPUS_SUMMARY, 'r') as f:
        for entry in json.load(f):
            corpus_index[entry['file']] = entry
    
    # Analyze merged clusters with multiple members
    clusters_to_analyze = sorted(
        [c for c in clusters if c['num_members'] > 1],
        key=lambda c: (c['num_members'] * c['num_members']) / max(c['num_tags'], 1),
        reverse=True
    )
    
    print(f"Found {len(clusters_to_analyze)} merged clusters with >1 member")
    
    # Analyze top 30 most interesting clusters
    results = {}
    for c in clusters_to_analyze[:30]:
        key = f"{c['num_members']}f_{c['num_tags']}t"
        if key in results:
            key = f"{key}_{c['num_members']}f_{c['num_tags']}t_{hash(tuple(c['tags'][:5])) % 1000}"
        results[key] = analyze_cluster(c, corpus_index)
    
    # Print analysis
    for cluster_name, analysis in sorted(results.items(), key=lambda x: -x[1]['num_members']):
        print_cluster_analysis(cluster_name, analysis)
    
    # Summary table
    print(f"\n{'='*60}")
    print("SUMMARY TABLE")
    print(f"{'Cluster':<20} {'Members':>8} {'Tags':>5} {'Entries':>8} {'Best Match':<25} {'Conf':>6}")
    print("-" * 75)
    
    for cluster_name, analysis in sorted(results.items(), key=lambda x: -x[1]['num_members']):
        sample = analysis['samples'][0] if analysis['samples'] else {}
        num_entries = sample.get('num_entries', 0)
        best_match = sample.get('entity_matches', [])
        if best_match:
            name, conf, desc, num = best_match[0]
            best_name = desc[:25]
            best_conf = f"{conf:.0%}"
        else:
            best_name = "unknown"
            best_conf = "-"
        
        print(f"{cluster_name:<20} {analysis['num_members']:>8} {analysis['num_tags']:>5} {num_entries:>8} {best_name:<25} {best_conf:>6}")

if __name__ == '__main__':
    main()
