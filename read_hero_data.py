"""Read hero DB schema analysis for rarity, hero ID, and stat tags."""
import json

path = r'C:\Users\NGEONG\Videos\MLA\PROJECT\analysis\hero_db_schema_analysis.json'
with open(path) as f:
    data = json.load(f)

fa = data.get('field_analysis', {})

tags = {
    '6': 'rarity',
    '4': 'class', 
    '5': 'faction',
    '7': 'star_quality',
    '9': 'hero_id (HeroRosterDB)',
    '10': 'hero_id_alt',
    '131': 'hero_id (HeroStatDB)',
    '85': 'hero_id (EquipDB)',
    '132': 'stat_hp',
    '133': 'stat_atk',
    '134': 'stat_def',
    '135': 'stat_speed',
    '136': 'stat_crit',
    '206': 'skill_1',
    '207': 'skill_2',
    '208': 'skill_3',
    '209': 'skill_4',
}

print("Hero Database Fields:")
print("=" * 70)
for tag_s, meaning in tags.items():
    if tag_s in fa:
        info = fa[tag_s]
        mode_val = info.get("mode", "?")
        min_val = info.get("min", "?")
        max_val = info.get("max", "?")
        samples = info.get("samples", [])
        print("{:30s} (tag 0x{:02X}):".format(meaning, int(tag_s)))
        print("  mode={:>6s}  min={:>6s}  max={:>6s}".format(str(mode_val), str(min_val), str(max_val)))
        print("  samples={}".format(samples[:20]))
        print()

# Show hero_id distribution across all 4 ID tags
print("=" * 70)
print("HeroID samples across all known ID tags:")
for ts in ['9', '10', '85', '131']:
    if ts in fa:
        samples = fa[ts].get("samples", [])
        print("  tag 0x{:02X} ({} values): {}...".format(
            int(ts), fa[ts].get('unique_vals','?'), samples[:30]))
