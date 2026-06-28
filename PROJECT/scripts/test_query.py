"""Quick test of query layer."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mla_query import *

print("=== Search by HeroID 2111 ===")
for r in search_by_id(2111, 'HeroID')[:10]:
    print(f'  {r["entity_type"]:15s} {r["stable_id"][:20]:20s} tag={r["tag_hex"]:4s} val={r["value"]}')

print("\n=== ID types ===")
for t in list_id_types():
    print(f'  {t["id_type"]:15s} unique={t["unique_ids"]:>5d} range=[{t["id_range"][0]}-{t["id_range"][1]}]')

print("\n=== Cross-ref for 2111 ===")
results = find_cross_references(2111)
for r in results[:15]:
    print(f'  {r["entity_type"]:15s} tag={r["tag_hex"]:4s} ref={r["ref_type"]:10s}')

print("\n=== Entity type counts ===")
et = search_by_type('HeroRosterDB', 5)
print(f'Total: {et["total"]} entries')
for r in et['entries'][:5]:
    print(f'  entry={r["entry_index"]:<5d} fields={r["field_count"]:<3d} tags={r["tag_count"]:<3d}')

print("\n=== Discover name tags ===")
names = get_entity_names(10)
for r in names:
    print(f'  tag=0x{r["tag"]:02X}: {r["cnt"]:>6d} entries, {r["unique_vals"]:>4d} unique vals')
