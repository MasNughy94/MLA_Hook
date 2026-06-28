"""Test query layer extensively."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts'))
from mla_query import *

print("=== ID types with stats ===")
for t in list_id_types()[:4]:
    print("  {:12s} unique={:>5d} range=[{}-{}] tags={}".format(
        t['id_type'], t['unique_ids'], t['id_range'][0], t['id_range'][1], t['tags']))

print()
print("=== Cross-ref search for value 0 ===")
results = search_by_field(0x01, 0, 10)
print("  Found {} entities with tag=0x01 val=0".format(len(results)))

print()
print("=== Field search for tag 0xCE val=100 ===")
results = search_by_field(0xCE, 100, 10)
print("  Entities with tag=0xCE val=100:")
for r in results[:5]:
    print("    {:15s} {}".format(r['entity_type'], r['stable_id'][:20]))

print()
print("=== Discover name-candidate tags ===")
names = get_entity_names(15)
for r in names:
    print("  tag=0x{:02X}: {:>6d} entries, {:>4d} unique vals".format(
        r['tag'], r['cnt'], r['unique_vals']))

print()
print("=== Search by type ===")
r = search_by_type('MasterDB', 5)
print("  Total MasterDB entries: {}".format(r['total']))
for e in r['entries'][:5]:
    print("    entry={:<5d} fields={:<3d} tags={:<3d}".format(
        e['entry_index'], e['field_count'], e['tag_count']))
