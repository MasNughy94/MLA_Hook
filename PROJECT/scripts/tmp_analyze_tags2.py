import json, struct

with open(r'analysis/hero_db_schema_analysis.json') as f:
    data = json.load(f)

fa = data['field_analysis']

def get_char(tag_num):
    return chr(tag_num) if 32 <= tag_num < 127 else '.'

# Known patterns to search for
# Tag keys in fa are strings like '1', '10', '255' representing tag numbers
class_like = []
star_like = []
id_range = []
skill_ids = []
large_vals = []
moderate_ref = []

for tag_str, info in fa.items():
    tag_num = int(tag_str)
    tag_hex = info['tag']
    vals = info.get('samples', [])
    uv = info.get('unique_vals', 0)
    presence = info.get('presence', 0)
    total = data['total_entries']
    mn, mx = info.get('min', 0), info.get('max', 0)
    
    # Class enum (1-5): values mostly in 1-5 range
    class_vals = [v for v in vals if 1 <= v <= 5]
    if len(class_vals) >= 3 and mx <= 10:
        class_like.append((tag_num, get_char(tag_num), sorted(set(vals))))
    
    # Star quality (1-8): values mostly in 1-8 range  
    star_vals = [v for v in vals if 1 <= v <= 8]
    if len(star_vals) >= 4 and len(star_vals) == len(vals) and mx <= 10 and uv <= 8:
        star_like.append((tag_num, get_char(tag_num), sorted(set(vals))))
    
    # 4-digit IDs (1000-9999)
    id_vals = sorted(set(v for v in vals if 1000 <= v <= 9999))
    if len(id_vals) >= 2:
        id_range.append((tag_num, get_char(tag_num), uv, id_vals[:10]))
    
    # Skill IDs (53200-53206)
    skill_vals = [v for v in vals if 53200 <= v <= 53206]
    if skill_vals:
        skill_ids.append((tag_num, get_char(tag_num), skill_vals))
    
    # Large values (50000+)
    if mx >= 50000 and uv >= 2:
        large_vals.append((tag_num, get_char(tag_num), uv, mn, mx, 
                          [v for v in vals if v >= 50000][:5]))
    
    # Moderate reference values
    ref_vals = sorted(set(v for v in vals if 100 <= v <= 10000))
    if uv >= 5 and len(ref_vals) >= 3:
        moderate_ref.append((tag_num, get_char(tag_num), presence, uv, ref_vals[:8]))

print(f"Total tags: {len(fa)}")
print(f"Total entries: {data['total_entries']}")
print()

print("=== CLASS ENUM (1-5) ===")
for tn, tc, svals in class_like:
    print(f"  tag=0x{tn:02x}('{tc}'): {svals}")

print("\n=== STAR/QUALITY (1-8) ===")
for tn, tc, svals in star_like:
    print(f"  tag=0x{tn:02x}('{tc}'): {svals}")

print("\n=== 4-DIGIT IDS (1000-9999) ===")
for tn, tc, uv, ids in id_range:
    print(f"  tag=0x{tn:02x}('{tc}'): {uv} unique, samples={ids}")

print("\n=== SKILL IDS (53200-53206) ===")
for tn, tc, svals in skill_ids:
    print(f"  tag=0x{tn:02x}('{tc}'): {svals}")

print("\n=== LARGE VALUES (50000+) ===")
for tn, tc, uv, mn, mx, vs in large_vals:
    print(f"  tag=0x{tn:02x}('{tc}'): {uv} unique, range=[{mn},{mx}], large_samples={vs}")

print("\n=== MODERATE REFERENCE (100-10000, >=5 unique) ===")
for tn, tc, pres, uv, vs in moderate_ref:
    print(f"  tag=0x{tn:02x}('{tc}'): presence={pres}, unique={uv}, ref_samples={vs}")

print()
print("=== ZERO-ONLY TAGS ===")
zero_tags = [(int(k), v) for k, v in fa.items() if v.get('always_zero')]
for tn, v in zero_tags:
    tc = get_char(tn)
    pres = v['presence']
    print(f"  tag=0x{tn:02x}('{tc}'): presence={pres} (always 0=unused/reserved)")

print()
print("=== MOST COMMON TAGS ===")
tag_pres = [(int(k), v['presence'], v['unique_vals'], v.get('type', '')) for k, v in fa.items()]
tag_pres.sort(key=lambda x: -x[1])
for tn, pres, uv, typ in tag_pres[:20]:
    tc = get_char(tn)
    pct = pres / data['total_entries'] * 100
    print(f"  tag=0x{tn:02x}('{tc}'): presence={pres} ({pct:.1f}%), unique={uv}, type={typ}")
