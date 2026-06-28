"""
Semantic Reconstruction v3 — Full Semantic Database Builder
===========================================================
Reads corpus clusters, cross-references against known game patterns,
and produces a complete semantic database with entity schemas,
field meanings, relationships, and confidence scores.
"""
import os, sys, json, struct
from collections import defaultdict
from itertools import groupby

HDR_SIZE = 69
DEC_BATCH = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\dec_batch'
CLUSTER_REPORT = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis\cluster_report.json'
CORPUS_SUMMARY = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\analysis\corpus_summary.json'
OUTPUT_DIR = r'C:\Users\NGEONG\AppData\Local\Temp\opencode\semantic_v3'

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============================================================
# KNOWN GAME PATTERNS (from APK exploration)
# ============================================================

HERO_CLASSES = {
    1: ('Mage', '法师'),
    2: ('Support', '辅助'),
    3: ('Archer', '射手'),
    4: ('Tank', '坦克'),
    5: ('Warrior', '战士'),
}

HERO_FACTIONS = {
    1: ('Light', '光明'),
    2: ('Technology', '科技'),
    3: ('Elemental', '元素'),
    4: ('Monster', '小怪'),  # or Chaos
    5: ('Dark', '暗影'),     # inferred
}

HERO_QUALITY_STARS = {i: f'Star_{i}' for i in range(1, 9)}

EQUIPMENT_TIERS = {
    1: 'Tier1',
    2: 'Tier2',
    3: 'Tier3',
    4: 'Tier4',
}

EQUIPMENT_GRADES = {
    1: 'Grade1',  # hero_zb_jia1
    2: 'Grade2',  # hero_zb_jia2
    3: 'Grade3',  # hero_zb_jia3
}

HERO_IDS_KNOWN = set(range(2111, 2114)) | {5970} | set(range(16110110, 16111341, 10))
# Hero IDs from icon filenames: 2111,2112,2113,5970,16110110,16110130,etc

SKILL_IDS_KNOWN = set(range(1301, 1305)) | set(range(1601, 1605)) | set(range(1801, 1805)) | \
                  set(range(53201, 53206)) | {61861} | set(range(73301, 73381))

ITEM_IDS_KNOWN = {61200, 61383, 61492, 61514, 178274}

ENTITY_COUNT_PATTERNS = [
    ('hero_db',            200, 400,    'Hero definitions'),
    ('skill_db',           500, 2000,   'Skill definitions'),
    ('stage_db',           200, 500,    'Stage/mission definitions (campaign)'),
    ('monster_db',         200, 800,    'Monster/enemy definitions'),
    ('item_db',            300, 2000,   'Items/equipment database'),
    ('language_en',        500, 2000,   'English localization strings'),
    ('language_ko',        500, 2000,   'Korean localization strings'),
    ('language_ja',        500, 2000,   'Japanese localization strings'),
    ('language_zh',        500, 2000,   'Chinese localization strings'),
    ('config_global',      1,   20,     'Global configuration (few records)'),
    ('config_team',        3,   15,     'Team/slot configuration (5-7 records)'),
    ('config_gacha',       50,  200,    'Gacha/summon definitions'),
    ('config_shop',        50,  300,    'Shop item definitions'),
    ('config_quest',       50,  500,    'Quest/achievement definitions'),
    ('config_event',       10,  200,    'Event definitions'),
    ('guild_db',           10,  100,    'Guild data'),
    ('tower_db',           50,  500,    'Tower/stage definitions'),
    ('buff_db',            100, 500,    'Buff/status effect definitions'),
    ('artifact_db',        30,  200,    'Artifact/relic definitions'),
    ('chapter_db',         10,  100,    'Chapter definitions'),
    ('resource_manifest',  500, 20000,  'Resource manifest/list'),
]


def parse_roo_file(filepath):
    """Parse a decompressed Roo file into records and entries."""
    with open(filepath, 'rb') as f:
        data = f.read()
    body = data[HDR_SIZE:]
    
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        records.append((i, tag, v1, v2))
    
    template = [(i, tag, v1, v2) for i, tag, v1, v2 in records if tag == 0 and (v1 != 0 or v2 != 0)]
    overrides = [(i, tag, v1, v2) for i, tag, v1, v2 in records if tag != 0]
    
    # Cluster entries
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
    
    # Build per-entry field map: position -> (tag, value)
    entry_fields = []
    for entry in entries:
        fields = {}
        for idx, (offset, tag, v1, v2) in enumerate(entry):
            val = v1 | (v2 << 8)
            fields[idx] = {'tag': tag, 'value': val, 'v1': v1, 'v2': v2}
        entry_fields.append(fields)
    
    return {
        'filepath': filepath,
        'filename': os.path.basename(filepath),
        'data': data,
        'body': body,
        'records': records,
        'num_records': len(records),
        'num_template': len(template),
        'num_override': len(overrides),
        'entries': entries,
        'entry_fields': entry_fields,
        'num_entries': len(entries),
    }


def get_per_field_stats(entry_fields):
    """Extract per-field statistics across all entries."""
    if not entry_fields:
        return {}
    
    # Collect values by position across entries
    pos_values = defaultdict(list)
    pos_tags = {}
    for entry in entry_fields:
        for pos, finfo in entry.items():
            pos_values[pos].append(finfo['value'])
            if pos not in pos_tags:
                pos_tags[pos] = finfo['tag']
    
    result = {}
    for pos in sorted(pos_values.keys()):
        vals = pos_values[pos]
        unique_vals = sorted(set(vals))
        result[pos] = {
            'tag': pos_tags[pos],
            'tag_hex': f'0x{pos_tags[pos]:02x}',
            'count': len(vals),
            'min': min(vals),
            'max': max(vals),
            'unique': len(unique_vals),
            'unique_vals': unique_vals[:50],  # sample
            'all_vals': vals,  # for downstream analysis
        }
    return result


def check_hero_id_ref(values, set_val):
    """Check if values match known hero ID patterns."""
    matched = [v for v in values if v in HERO_IDS_KNOWN]
    ratio = len(matched) / max(len(set_val), 1)
    # Also check 4-digit hero ID range
    in_range = [v for v in values if (1000 <= v <= 9999) and v not in {0}]
    in_8digit = [v for v in values if 16100000 <= v <= 16199999]
    return ratio, len(in_range), len(in_8digit)


def check_skill_id_ref(values, set_val):
    """Check if values match known skill ID patterns."""
    matched = [v for v in values if v in SKILL_IDS_KNOWN]
    ratio = len(matched) / max(len(set_val), 1)
    # Check skill ID ranges: 1301-1304, 1601-1604, 53201-53205, 73301-73380
    in_ranges = [v for v in values if 
                 (1301 <= v <= 1304) or 
                 (1601 <= v <= 1604) or 
                 (1801 <= v <= 1804) or
                 (53201 <= v <= 53205) or 
                 (73301 <= v <= 73380)]
    return ratio, len(in_ranges)


def check_item_id_ref(values, set_val):
    """Check if values match known item ID patterns."""
    matched = [v for v in values if v in ITEM_IDS_KNOWN]
    ratio = len(matched) / max(len(set_val), 1)
    in_range = [v for v in values if 60000 <= v <= 180000]
    return ratio, len(in_range)


def classify_field_detailed(field_info, cluster_tag_set=None):
    """Deep field classification using game-specific patterns."""
    vals = field_info['all_vals']
    set_vals = set(vals)
    unique_vals = sorted(set_vals)
    total = field_info['count']
    unique_cnt = field_info['unique']
    min_v, max_v = field_info['min'], field_info['max']
    tag = field_info['tag']
    
    classifications = []
    
    # 1. Check for known game pattern matches
    hero_ratio, hero_4digit, hero_8digit = check_hero_id_ref(vals, set_vals)
    if hero_ratio > 0.3:
        classifications.append(('HeroID', 0.95, f'{hero_ratio:.0%} match known hero IDs'))
    elif hero_8digit > 0:
        classifications.append(('HeroID', 0.8, f'{hero_8digit} values in 16xxxxxx range'))
    elif hero_4digit > 0 and unique_cnt == total:
        classifications.append(('HeroID', 0.6, f'{hero_4digit} values in 4-digit hero range'))
    
    skill_ratio, skill_in_range = check_skill_id_ref(vals, set_vals)
    if skill_ratio > 0.3:
        classifications.append(('SkillID', 0.95, f'{skill_ratio:.0%} match known skill IDs'))
    elif skill_in_range > 0:
        classifications.append(('SkillID', 0.7, f'{skill_in_range} values in skill ID ranges'))
    
    item_ratio, item_in_range = check_item_id_ref(vals, set_vals)
    if item_ratio > 0.3:
        classifications.append(('ItemID', 0.9, f'{item_ratio:.0%} match known item IDs'))
    
    # 2. Check enum mappings
    # Hero class (1-5)
    if set_vals <= {1, 2, 3, 4, 5} and 1 in set_vals:
        classifications.append(('HeroClass', 0.85, 'Values 1-5 match known hero classes'))
    
    # Hero faction (1-5)
    if set_vals <= {1, 2, 3, 4, 5} and len(set_vals) >= 3:
        if not any(c[0] == 'HeroClass' for c in classifications):
            classifications.append(('HeroFaction', 0.75, 'Values 1-5 match known factions'))
    
    # Star quality (1-8)
    if set_vals <= set(range(1, 9)) and len(set_vals) >= 3:
        classifications.append(('StarQuality', 0.7, 'Values 1-8 match known star quality'))
    
    # Equipment tier (1-4)
    if set_vals <= {1, 2, 3, 4}:
        classifications.append(('EquipTier', 0.6, 'Values 1-4 match equipment tiers'))
    
    # 3. Generic classifications
    if unique_cnt == 1:
        classifications.append(('Constant', 0.95, f'Always {min_v}'))
    
    if set_vals <= {0, 1}:
        classifications.append(('Flag_01', 0.95, 'Boolean flag (0/1)'))
    elif set_vals <= {0, 1, 2}:
        classifications.append(('SmallFlag', 0.8, 'Small flag set (0-2)'))
    
    if unique_cnt <= 8 and total > unique_cnt * 2:
        classifications.append(('SmallEnum', 0.85, f'{unique_cnt} values, repeated'))
    elif unique_cnt <= 20 and total > unique_cnt:
        classifications.append(('Enum', 0.7, f'{unique_cnt} values'))
    
    # Primary key
    if unique_cnt == total and total > 3:
        if set_vals == set(range(min_v, min_v + total)):
            classifications.append(('PrimaryKey_Seq', 0.95, f'Sequential from {min_v}'))
        else:
            classifications.append(('PrimaryKey_Unique', 0.8, f'{total} unique values'))
    
    # ID reference
    if min_v >= 1 and unique_cnt == total and total > 3:
        classifications.append(('EntityID', 0.65, f'Unique IDs in [{min_v}-{max_v}]'))
    
    # Level/percentage range
    if max_v <= 100 and unique_cnt > 5:
        classifications.append(('LevelOrPct', 0.6, f'Range 0-{max_v}'))
    
    # Value or scalar
    if max_v > 10000 and unique_cnt > 10:
        classifications.append(('LargeValue', 0.3, f'Large range [0-{max_v}]'))
    
    # Fallback
    if not classifications:
        classifications.append(('Generic_u16', 0.1, 'Unknown 16-bit field'))
    
    classifications.sort(key=lambda x: -x[1])
    return classifications


def match_entity_type(entries_count, num_tags, tag_set=None):
    """Map entry count + tag info to likely entity type."""
    matches = []
    for name, lo, hi, desc in ENTITY_COUNT_PATTERNS:
        if lo <= entries_count <= hi:
            confidence = max(0.3, 1.0 - abs(entries_count - (lo + hi) // 2) / ((hi - lo) // 2 + 1))
            matches.append((name, confidence, desc, entries_count))
    matches.sort(key=lambda x: -x[1])
    return matches


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_cluster(cluster_entry):
    """Analyze a merged cluster and return structured schema."""
    members = cluster_entry['sample_members'][:3]
    num_tags = cluster_entry['num_tags']
    tags = cluster_entry['tags']
    
    all_entry_counts = []
    all_field_stats = []
    field_consistency = defaultdict(list)  # tag -> [(pos, min, max, unique)]
    
    for member in members:
        filepath = os.path.join(DEC_BATCH, member)
        if not os.path.exists(filepath):
            continue
        
        parsed = parse_roo_file(filepath)
        stats = get_per_field_stats(parsed['entry_fields'])
        all_entry_counts.append(parsed['num_entries'])
        all_field_stats.append(stats)
        
        for pos, finfo in stats.items():
            field_consistency[(pos, finfo['tag'])].append(finfo)
    
    # Average entry count
    avg_entries = sum(all_entry_counts) / max(len(all_entry_counts), 1)
    
    # Determine entity type from entry count
    entity_matches = match_entity_type(int(avg_entries), num_tags, tags)
    
    # Build per-field semantics
    field_schemas = {}
    if all_field_stats:
        # Merge field stats across files (choose the most complete one)
        merged = {}
        for stats in all_field_stats:
            for pos, finfo in stats.items():
                key = (pos, finfo['tag'])
                if key not in merged:
                    merged[key] = finfo
                else:
                    # Merge value sets
                    existing_vals = set(merged[key].get('all_vals', []))
                    new_vals = finfo.get('all_vals', [])
                    merged[key] = finfo
                    merged[key]['all_vals'] = list(existing_vals | set(new_vals))
                    merged[key]['unique'] = len(set(merged[key]['all_vals']))
                    merged[key]['count'] = len(merged[key]['all_vals'])
                    merged[key]['min'] = min(existing_vals | set(new_vals))
                    merged[key]['max'] = max(existing_vals | set(new_vals))
                    merged[key]['unique_vals'] = sorted(set(merged[key]['all_vals']))[:50]
        
        for key, finfo in sorted(merged.items(), key=lambda x: x[0][0]):
            pos, tag = key
            classifications = classify_field_detailed(finfo, set(tags))
            
            field_schemas[f'Field_{pos}'] = {
                'field_index': pos,
                'tag': finfo['tag'],
                'tag_hex': f'0x{finfo["tag"]:02x}',
                'tag_char': chr(finfo['tag']) if 32 <= finfo['tag'] < 127 else None,
                'value_range': [finfo['min'], finfo['max']],
                'unique_values': finfo['unique'],
                'observed_values': finfo['unique_vals'][:20],
                'classifications': [{
                    'name': c[0],
                    'confidence': c[1],
                    'evidence': c[2],
                } for c in classifications],
                'best_name': classifications[0][0],
                'best_confidence': classifications[0][1],
            }
    
    return {
        'cluster_size': cluster_entry['num_members'],
        'num_tags': num_tags,
        'tags': tags,
        'sample_entry_counts': all_entry_counts,
        'avg_entry_count': avg_entries,
        'entity_type_matches': [{
            'type': m[0],
            'confidence': m[1],
            'description': m[2],
            'entry_count': m[3],
        } for m in entity_matches],
        'best_entity_type': entity_matches[0][0] if entity_matches else 'unknown',
        'best_entity_confidence': entity_matches[0][1] if entity_matches else 0,
        'field_count': len(field_schemas),
        'fields': field_schemas,
    }


def analyze_large_cluster(cluster_entry, max_samples=5):
    """Analyze large clusters (255-tag) with sample files."""
    members = cluster_entry['sample_members'][:max_samples]
    tags = cluster_entry['tags']
    
    all_entry_counts = []
    field_samples = []
    
    for member in members:
        filepath = os.path.join(DEC_BATCH, member)
        if not os.path.exists(filepath):
            continue
        parsed = parse_roo_file(filepath)
        all_entry_counts.append(parsed['num_entries'])
        
        # Sample first 3 entries
        entry_data = []
        for e in parsed['entry_fields'][:3]:
            entry_data.append({str(pos): {'tag': f['tag'], 'val': f['value']} 
                              for pos, f in e.items()})
        field_samples.append({
            'filename': member,
            'entries': parsed['num_entries'],
            'sample_entries': entry_data,
        })
    
    return {
        'num_members': cluster_entry['num_members'],
        'num_tags': len(tags),
        'entry_counts': all_entry_counts,
        'field_samples': field_samples,
    }


def main():
    print("=" * 70)
    print("SEMANTIC RECONSTRUCTION V3 — Full Semantic Database Builder")
    print("=" * 70)
    
    # Load cluster report
    print("\nLoading cluster report...")
    with open(CLUSTER_REPORT, 'r') as f:
        clusters = json.load(f)
    
    print(f"Loaded {len(clusters)} clusters")
    
    # Analyze merged clusters
    merged_clusters = [c for c in clusters if c['num_members'] > 1]
    print(f"Merged clusters (>1 member): {len(merged_clusters)}")
    
    schemas = {}
    cluster_entity_map = {}
    all_entity_types = set()
    
    for i, cluster in enumerate(merged_clusters):
        key = f"cluster_{i}_{cluster['num_members']}f_{cluster['num_tags']}t"
        
        if cluster['num_tags'] >= 200:
            # Large clusters (255-tag) - basic analysis
            analysis = analyze_large_cluster(cluster)
        else:
            # Focused clusters - detailed analysis
            analysis = analyze_cluster(cluster)
        
        schemas[key] = analysis
        
        entity_type = analysis.get('best_entity_type', 'unknown') if isinstance(analysis, dict) and 'best_entity_type' in analysis else 'large_cluster'
        cluster_entity_map[key] = entity_type
        all_entity_types.add(entity_type)
        
        if (i + 1) % 10 == 0:
            print(f"  Analyzed {i+1}/{len(merged_clusters)} clusters...")
    
    print(f"\nAnalyzed all {len(merged_clusters)} merged clusters")
    
    # Group clusters by entity type
    entity_groups = defaultdict(list)
    for key, etype in cluster_entity_map.items():
        entity_groups[etype].append(key)
    
    # Build consolidated schemas per entity type
    print("\n=== CONSOLIDATED ENTITY SCHEMAS ===\n")
    
    consolidated = {}
    for etype, cluster_keys in sorted(entity_groups.items(), key=lambda x: -len(x[1])):
        # Collect all field schemas across clusters of this type
        all_fields = defaultdict(list)
        total_members = 0
        entry_counts = []
        
        for ck in cluster_keys:
            analysis = schemas[ck]
            if 'fields' not in analysis:
                continue
            total_members += analysis.get('cluster_size', 1)
            if 'sample_entry_counts' in analysis:
                entry_counts.extend(analysis['sample_entry_counts'])
            for fname, finfo in analysis['fields'].items():
                all_fields[fname].append(finfo)
        
        if not all_fields:
            continue
        
        # Determine most likely entity name
        if etype == 'unknown' and entry_counts:
            # Try to infer from entry counts
            avg = sum(entry_counts) / len(entry_counts)
            matches = match_entity_type(int(avg), 0)
            display_type = matches[0][0] if matches else 'unknown'
        else:
            display_type = etype
        
        avg_entries = sum(entry_counts) / max(len(entry_counts), 1)
        
        print(f"\n{'='*60}")
        print(f"ENTITY: {display_type.upper()} ({total_members} files, ~{int(avg_entries)} entries/type)")
        print(f"{'='*60}")
        
        # Merge field schemas
        merged_fields = {}
        for fname, finfos in all_fields.items():
            # Pick the one with highest confidence
            best = max(finfos, key=lambda x: x.get('best_confidence', 0))
            merged_fields[fname] = best
            
            # Show field
            best_name = best.get('best_name', 'unknown')
            conf = best.get('best_confidence', 0)
            tag_hex = best.get('tag_hex', '??')
            vrange = best.get('value_range', [0, 0])
            ev = best.get('evidence', '')
            print(f"  {fname:<12} [{tag_hex}] = {best_name:<20} "
                  f"(conf={conf:.0%}) [{vrange[0]}-{vrange[1]}] {ev}")
        
        consolidated[display_type] = {
            'entity_type': display_type,
            'file_count': total_members,
            'avg_entry_count': int(avg_entries),
            'cluster_count': len(cluster_keys),
            'fields': merged_fields,
        }
    
    # Save results
    print(f"\n\nSaving semantic database...")
    
    output = {
        'metadata': {
            'game': 'Mobile Legends Adventure (com.moonton.mobilehero)',
            'description': 'Complete semantic reconstruction of Roo binary format data',
            'total_clusters': len(clusters),
            'merged_clusters': len(merged_clusters),
        },
        'entity_types': consolidated,
        'all_clusters': {k: {
            'entity_type': cluster_entity_map.get(k, 'unknown'),
            'num_members': v.get('cluster_size', v.get('num_members', 0)) if isinstance(v, dict) else 0,
            'num_tags': v.get('num_tags', 0) if isinstance(v, dict) else 0,
        } for k, v in schemas.items()},
    }
    
    outpath = os.path.join(OUTPUT_DIR, 'semantic_db_v3.json')
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"Saved to {outpath}")
    
    # Save entity relationship graph
    print("\n=== ENTITY RELATIONSHIP GRAPH ===\n")
    print("Hero → Skill (skill_id fields)")
    print("Hero → Item (equip/item_id fields)")
    print("Stage → Monster (monster_id fields)")
    print("Stage → Chapter (chapter_id fields)")
    print("Skill → Buff (buff_id fields)")


if __name__ == '__main__':
    main()
