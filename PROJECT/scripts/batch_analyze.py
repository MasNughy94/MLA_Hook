#!/usr/bin/env python3
"""
Batch Roo Format Analyzer
=========================
Parses all decompressed .dec files, extracts structural metrics,
builds tag database, and clusters files by similarity.
"""
import os, sys, json, struct, time
from collections import defaultdict, Counter

HDR_SIZE = 69

def analyze_file(fpath, fname):
    """Extract structural metrics from one Roo file."""
    with open(fpath, 'rb') as f:
        data = f.read()
    
    if len(data) < HDR_SIZE:
        return {'file': fname, 'size': len(data), 'error': 'truncated', 'valid': False}
    
    header = data[:HDR_SIZE]
    body = data[HDR_SIZE:]
    
    # Quick header validation
    if header[:4] != b'\x1bLm\x00':
        return {'file': fname, 'size': len(data), 'error': 'bad_magic', 'valid': False}
    
    # Determine format variant from header tail
    hdr_variant = header[-2]  # 0x6F
    hdr_subtype = header[-1]  # 0xA9, 0xAA, 0xAB
    
    # Trim trailing bytes so body is 3-byte aligned
    trailing = len(body) % 3
    if trailing:
        body = body[:-trailing]
    
    if len(body) < 3:
        return {'file': fname, 'size': len(data), 'error': 'body_too_small',
                'hdr_variant': f'0x{hdr_subtype:02x}', 'valid': False}
    
    # Parse 3-byte records
    num_records = len(body) // 3
    tag_counts = Counter()
    tag_first_vals = {}
    tag_v1_values = defaultdict(set)
    tag_v2_values = defaultdict(set)
    tag_body_positions = defaultdict(list)
    template_records = []
    override_records = []
    
    record_index = 0
    for i in range(0, len(body), 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        rec = (i, tag, v1, v2)
        
        if tag == 0:
            if v1 != 0 or v2 != 0:
                template_records.append(rec)
        else:
            override_records.append(rec)
            tag_counts[tag] += 1
            tag_v1_values[tag].add(v1)
            tag_v2_values[tag].add(v2)
            tag_body_positions[tag].append(i)
            if tag not in tag_first_vals:
                tag_first_vals[tag] = (v1, v2)
    
    # Cluster entries by gap
    sorted_overrides = sorted(override_records, key=lambda x: x[0])
    entries = 0
    if sorted_overrides:
        entries = 1
        last_pos = sorted_overrides[0][0]
        for rec in sorted_overrides[1:]:
            if rec[0] - last_pos > 30:
                entries += 1
            last_pos = rec[0]
    
    # Build per-tag stats
    tag_stats = {}
    for tag in sorted(tag_counts.keys()):
        v1_vals = tag_v1_values[tag]
        v2_vals = tag_v2_values[tag]
        positions = tag_body_positions[tag]
        gap_pattern = []
        if len(positions) > 1:
            gaps = [positions[j+1] - positions[j] for j in range(len(positions)-1)]
            gap_pattern = sorted(Counter(gaps).most_common(3))
        
        tag_stats[f'0x{tag:02x}'] = {
            'char': chr(tag) if 32 <= tag < 127 else '.',
            'count': tag_counts[tag],
            'v1_unique': len(v1_vals),
            'v1_min': min(v1_vals),
            'v1_max': max(v1_vals),
            'v2_unique': len(v2_vals),
            'v2_min': min(v2_vals),
            'v2_max': max(v2_vals),
            'positions_pct': round(100 * len(positions) / num_records, 1),
            'gap_pattern': gap_pattern,
        }
    
    # Template record analysis
    template_positions = [r[0] for r in template_records]
    template_stats = {
        'count': len(template_records),
        'positions': template_positions[:50],  # first 50
    }
    
    return {
        'file': fname,
        'size': len(data),
        'body_size': len(body),
        'num_records': num_records,
        'num_override': len(override_records),
        'num_template': len(template_records),
        'num_empty': num_records - len(override_records) - len(template_records),
        'entries': entries,
        'override_density': f"{100*len(override_records)//max(num_records,1)}%",
        'hdr_variant': f'0x{hdr_subtype:02x}',
        'header_prefix': header[:32].hex(),
        'num_unique_tags': len(tag_counts),
        'tags': tag_stats,
        'template': template_stats,
        'valid': True,
    }


def main():
    dec_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), 'dec_batch')
    out_dir = os.path.join(os.path.dirname(__file__), 'analysis')
    os.makedirs(out_dir, exist_ok=True)
    
    files = sorted([f for f in os.listdir(dec_dir) if f.endswith('.dec')])
    print(f"Analyzing {len(files)} files...")
    
    results = []
    variant_stats = defaultdict(int)
    errors = defaultdict(int)
    tag_namespace_clusters = defaultdict(list)
    
    t0 = time.time()
    batch_size = 500
    
    for idx, fname in enumerate(files):
        fpath = os.path.join(dec_dir, fname)
        r = analyze_file(fpath, fname)
        results.append(r)
        
        if r.get('valid'):
            variant_stats[r.get('hdr_variant', '?')] += 1
            # Cluster by tag namespace: create a frozenset of tags
            if 'tags' in r and r['tags']:
                tag_set = frozenset(r['tags'].keys())
                tag_namespace_clusters[tag_set].append(fname)
        else:
            errors[r.get('error', 'unknown')] += 1
        
        if (idx + 1) % batch_size == 0 or idx == len(files) - 1:
            elapsed = time.time() - t0
            rate = (idx + 1) / elapsed
            print(f"  [{idx+1}/{len(files)}] {elapsed:.0f}s, {rate:.0f} files/s")
    
    total_time = time.time() - t0
    valid = sum(1 for r in results if r.get('valid'))
    
    print(f"\n=== Analysis Complete ===")
    print(f"Total: {len(results)} files in {total_time:.0f}s")
    print(f"Valid: {valid}")
    print(f"Errors: {len(results) - valid}")
    print(f"Variants: {dict(variant_stats)}")
    print(f"Error breakdown: {dict(errors)}")
    
    # ─── Save corpus summary ───
    summary_path = os.path.join(out_dir, 'corpus_summary.json')
    # Remove full tag details for summary (keep per-file stats lightweight)
    summary_data = []
    for r in results:
        entry = {k: v for k, v in r.items() if k != 'tags' and k != 'template'}
        if r.get('valid'):
            entry['num_unique_tags'] = r.get('num_unique_tags', 0)
            entry['tag_list'] = list(r.get('tags', {}).keys()) if r.get('tags') else []
        summary_data.append(entry)
    
    with open(summary_path, 'w') as f:
        json.dump(summary_data, f, indent=1)
    print(f"\nSaved summary to {summary_path}")
    
    # ─── Tag Database ───
    tag_db = defaultdict(lambda: {'files': [], 'total_count': 0, 'v1_range': [255, 0], 'v2_range': [255, 0]})
    for r in results:
        if not r.get('valid') or not r.get('tags'):
            continue
        for tag_hex, tstats in r['tags'].items():
            tag_db[tag_hex]['files'].append(r['file'])
            tag_db[tag_hex]['total_count'] += tstats['count']
            tag_db[tag_hex]['v1_range'][0] = min(tag_db[tag_hex]['v1_range'][0], tstats['v1_min'])
            tag_db[tag_hex]['v1_range'][1] = max(tag_db[tag_hex]['v1_range'][1], tstats['v1_max'])
            tag_db[tag_hex]['v2_range'][0] = min(tag_db[tag_hex]['v2_range'][0], tstats['v2_min'])
            tag_db[tag_hex]['v2_range'][1] = max(tag_db[tag_hex]['v2_range'][1], tstats['v2_max'])
    
    tag_db_serializable = {}
    for tag_hex, tdata in sorted(tag_db.items()):
        tag_db_serializable[tag_hex] = {
            'char': chr(int(tag_hex, 16)) if 32 <= int(tag_hex, 16) < 127 else '.',
            'num_files': len(tdata['files']),
            'total_occurrences': tdata['total_count'],
            'v1_range': tdata['v1_range'],
            'v2_range': tdata['v2_range'],
            'sample_files': tdata['files'][:10],
        }
    
    tag_db_path = os.path.join(out_dir, 'tag_database.json')
    with open(tag_db_path, 'w') as f:
        json.dump(tag_db_serializable, f, indent=1)
    print(f"Saved tag database ({len(tag_db)} unique tags) to {tag_db_path}")
    
    # ─── Cluster Report ───
    cluster_report = []
    for tag_set, members in sorted(tag_namespace_clusters.items(), key=lambda x: -len(x[1])):
        tags_sorted = sorted(tag_set)
        tag_chars = ''.join(chr(int(t[2:], 16)) if 32 <= int(t[2:], 16) < 127 else '.' for t in tags_sorted)
        total_occs = [tag_db[t].get('total_count', 0) for t in tags_sorted if t in tag_db]
        cluster_report.append({
            'num_members': len(members),
            'num_tags': len(tag_set),
            'tag_range': f'{tags_sorted[0]}..{tags_sorted[-1]}' if tags_sorted else '',
            'tag_chars': tag_chars,
            'sample_members': members[:10],
            'tags': tags_sorted,
            'dominant_tag': max(total_occs) if total_occs else 0,
        })
    
    cluster_report.sort(key=lambda x: -x['num_members'])
    
    cluster_path = os.path.join(out_dir, 'cluster_report.json')
    with open(cluster_path, 'w') as f:
        json.dump(cluster_report, f, indent=1)
    print(f"Saved cluster report ({len(cluster_report)} clusters) to {cluster_path}")
    
    # ─── Print top clusters ───
    print("\n=== Top 20 Clusters ===")
    for cr in cluster_report[:20]:
        print(f"  {cr['num_members']:4d} files | {cr['num_tags']:3d} tags | {cr['tag_range']} | {cr['tag_chars']}")
    
    # ─── Print most common tags ───
    print("\n=== Top 30 Most Common Tags Across Corpus ===")
    tag_db_sorted = sorted(tag_db.items(), key=lambda x: -x[1]['total_count'])
    for tag_hex, tdata in tag_db_sorted[:30]:
        ch = chr(int(tag_hex, 16)) if 32 <= int(tag_hex, 16) < 127 else '.'
        print(f"  {tag_hex} ({ch}): {len(tdata['files']):4d} files, {tdata['total_count']:6d} occurrences, V1=[{tdata['v1_range'][0]}..{tdata['v1_range'][1]}], V2=[{tdata['v2_range'][0]}..{tdata['v2_range'][1]}]")


if __name__ == '__main__':
    main()
