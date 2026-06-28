import json

# Load tag analysis
with open(r'analysis/hero_db_schema_analysis.json') as f:
    data = json.load(f)

tags = data.get('tags', data)

# Known patterns to search for
# Hero classes: 1-5
# Hero factions: 1-5  
# Star/quality: 1-8
# Equipment slots: 1-6
# Skill IDs: 53200-53206, 1301-1305, etc
# Hero IDs: 1000-9999

print("=== TAGS WITH CLASS ENUM VALUES (1-5) ===")
for tag_id, info in sorted(tags.items(), key=lambda x: int(x[0])):
    tag_num = int(tag_id)
    vals = info.get('observed_values', info.get('values', []))
    if not vals:
        continue
    # Check if values include exactly [1,2,3,4,5] or subset
    svals = set(vals)
    # Check for 1-5 range values (class enum)
    class_vals = [v for v in vals if 1 <= v <= 5]
    if len(class_vals) >= 4 and max(vals) <= 10:
        tc = chr(tag_num) if 32 <= tag_num < 127 else '.'
        print(f"  tag=0x{tag_num:02x}('{tc}'): vals={sorted(vals)} (class-like)")

print("\n=== TAGS WITH STAR QUALITY VALUES (1-8) ===")
for tag_id, info in sorted(tags.items(), key=lambda x: int(x[0])):
    tag_num = int(tag_id)
    vals = info.get('observed_values', info.get('values', []))
    if not vals:
        continue
    star_vals = [v for v in vals if 1 <= v <= 8]
    if len(star_vals) >= 5 and len(star_vals) == len(vals) and max(vals) <= 10:
        tc = chr(tag_num) if 32 <= tag_num < 127 else '.'
        print(f"  tag=0x{tag_num:02x}('{tc}'): vals={sorted(vals)} (star-like)")

print("\n=== TAGS WITH 4-DIGIT VALUES (1000-9999) ===")
for tag_id, info in sorted(tags.items(), key=lambda x: int(x[0])):
    tag_num = int(tag_id)
    vals = info.get('observed_values', info.get('values', []))
    if not vals:
        continue
    id_vals = [v for v in vals if 1000 <= v <= 9999]
    if len(id_vals) >= 3:
        tc = chr(tag_num) if 32 <= tag_num < 127 else '.'
        print(f"  tag=0x{tag_num:02x}('{tc}'): {len(id_vals)}/{len(vals)} vals in 1000-9999, samples={id_vals[:10]}")

print("\n=== TAGS WITH SKILL ID VALUES (53200-53206) ===")
for tag_id, info in sorted(tags.items(), key=lambda x: int(x[0])):
    tag_num = int(tag_id)
    vals = info.get('observed_values', info.get('values', []))
    if not vals:
        continue
    skill_vals = [v for v in vals if 53200 <= v <= 53206]
    if skill_vals:
        tc = chr(tag_num) if 32 <= tag_num < 127 else '.'
        print(f"  tag=0x{tag_num:02x}('{tc}'): skill_vals={skill_vals}")

print("\n=== TAGS WITH LARGE VALUES (50000+) ===")
for tag_id, info in sorted(tags.items(), key=lambda x: int(x[0])):
    tag_num = int(tag_id)
    vals = info.get('observed_values', info.get('values', []))
    if not vals:
        continue
    large_vals = [v for v in vals if v >= 50000]
    if large_vals:
        tc = chr(tag_num) if 32 <= tag_num < 127 else '.'
        num_vals = info.get('unique_values', info.get('unique_count', 0))
        print(f"  tag=0x{tag_num:02x}('{tc}'): {num_vals} unique vals, {len(large_vals)} large >=50000, samples={large_vals[:5]}")

print("\n=== TAGS WITH MODERATE REFERENCE VALUES (100-10000, high uniqueness) ===")
for tag_id, info in sorted(tags.items(), key=lambda x: int(x[0])):
    tag_num = int(tag_id)
    vals = info.get('observed_values', info.get('values', []))
    if not vals:
        continue
    uv = info.get('unique_values', info.get('unique_count', 0))
    ref_vals = [v for v in vals if 100 <= v <= 10000 and v > 0]
    if uv >= 5 and len(ref_vals) >= 3:
        tc = chr(tag_num) if 32 <= tag_num < 127 else '.'
        count = info.get('count', info.get('presence_count', 0))
        print(f"  tag=0x{tag_num:02x}('{tc}'): count={count}, unique={uv}, ref_samples={ref_vals[:8]}")
