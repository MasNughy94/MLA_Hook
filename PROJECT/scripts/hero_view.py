"""
Hero View: Human-readable Hero entity reconstruction.
Menggabungkan HeroRosterDB + HeroStatDB + relasi ke file lain.
Tidak memberi nama field tanpa bukti.
"""
import os, sys, json, sqlite3
from collections import defaultdict

DB_PATH = r'C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\cache\mla_database.db'
IMPORT_ID = 1

ENTITY_FILES = {
    'HeroRosterDB': '07b5cc5ea4a8d86273be8170720a4587.mt.dec',
    'HeroStatDB': '12eb65e862c413254ae49d2eba76eea2.mt.dec',
    'SkillDB': '17f4dd5419fdea6aff836f46154d274a.mt.dec',
    'EquipDB': '1c7efa501c5305fb7062cdcbf148c4a9.mt.dec',
    'StageDB': '1c1ac35710f3a4276a942a776e911a85.mt.dec',
    'MonsterDB': '1c4ed1eebdb4b8af5c2658f4151aa529.mt.dec',
    'AnimDB': '18f286461b12e92d9e16b27c07854a7c.mt.dec',
    'MasterDB': '0217cbdae530696836de83aa3c162e1a.mt.dec',
    'ConfigDB': '1a4fb9f36cd34d0eb0ca22000e54f8a5.mt.dec',
    'AchieveDB': '0e3bbac67f12505f7dfe45d4e6aba1ea.mt.dec',
}


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_field_name(conn, entity_type, tag):
    row = conn.execute("""
        SELECT field_name, field_type, confidence, evidence
        FROM semantic_mappings
        WHERE entity_type = ? AND tag = ?
    """, (entity_type, tag)).fetchone()
    return row if row else None


def get_entity_fields(conn, entity_id):
    rows = conn.execute("""
        SELECT f.tag, f.value
        FROM entity_fields f
        WHERE f.entity_id = ?
        ORDER BY f.tag
    """, (entity_id,)).fetchall()
    return [(r['tag'], r['value']) for r in rows]


def resolve_hero_id_value(conn, entity_id):
    row = conn.execute("""
        SELECT f.value FROM entity_fields f
        WHERE f.entity_id = ? AND f.tag = 23 AND f.value > 0
        LIMIT 1
    """, (entity_id,)).fetchone()
    return row['value'] if row else None


def get_related_stat_entities(conn, hero_entity_id):
    rows = conn.execute("""
        SELECT r.source_entity_id as stat_entity_id, r.confidence
        FROM relationships r
        WHERE r.target_entity_id = ?
          AND r.source_entity_type = 'HeroStatDB'
          AND r.relationship_type = 'cross_file_ref'
    """, (hero_entity_id,)).fetchall()
    return [(r['stat_entity_id'], r['confidence']) for r in rows]


def get_related_entities(conn, hero_entity_id, source_type):
    rows = conn.execute("""
        SELECT r.source_entity_id as entity_id, r.confidence
        FROM relationships r
        WHERE r.target_entity_id = ?
          AND r.source_entity_type = ?
          AND r.relationship_type = 'cross_file_ref'
    """, (hero_entity_id, source_type)).fetchall()
    return [(r['entity_id'], r['confidence']) for r in rows]


def get_entity_references_from(conn, hero_entity_id, target_type):
    rows = conn.execute("""
        SELECT r.target_entity_id as entity_id, r.confidence
        FROM relationships r
        WHERE r.source_entity_id = ?
          AND r.target_entity_type = ?
          AND r.relationship_type = 'cross_file_ref'
    """, (hero_entity_id, target_type)).fetchall()
    return [(r['entity_id'], r['confidence']) for r in rows]


def describe_field(tag, value, sm, entity_type):
    if sm:
        fname = sm['field_name']
        ftype = sm['field_type']
        conf = sm['confidence']
        evidence = sm['evidence']
    else:
        fname = f'unknown_0x{tag:02X}'
        ftype = 'unknown'
        conf = 0.0
        evidence = 'No semantic mapping available'

    return {
        'tag': f'0x{tag:02X}',
        'value': value,
        'field_name': fname,
        'field_type': ftype,
        'confidence': conf,
        'source_file': ENTITY_FILES.get(entity_type, entity_type),
        'source_entity_type': entity_type,
        'evidence': evidence,
    }


def reconstruct_hero_view(conn, hero_entity_id):
    hero = conn.execute("""
        SELECT e.id, e.stable_id, e.entry_index, e.source_file, e.field_count
        FROM entities e
        WHERE e.id = ?
    """, (hero_entity_id,)).fetchone()
    if not hero:
        return None

    hero_id_val = resolve_hero_id_value(conn, hero_entity_id)

    view = {
        'entity_id': hero_entity_id,
        'stable_id': hero['stable_id'],
        'entry_index': hero['entry_index'],
        'source_file': ENTITY_FILES.get('HeroRosterDB', hero['source_file']),
        'hero_id_value': hero_id_val,
        'field_count': hero['field_count'],
        'fields': {},
        'stat_block': None,
        'skills': [],
        'equipment': [],
        'stage_refs': [],
        'monster_refs': [],
        'master_refs': [],
        'achievement_refs': [],
        'anim_refs': [],
        'config_refs': [],
    }

    for tag, val in get_entity_fields(conn, hero_entity_id):
        sm = get_field_name(conn, 'HeroRosterDB', tag)
        view['fields'][tag] = describe_field(tag, val, sm, 'HeroRosterDB')

    stat_entities = get_related_stat_entities(conn, hero_entity_id)
    if stat_entities:
        stat_eid, stat_conf = stat_entities[0]
        stat_view = {
            'stat_entity_id': stat_eid,
            'relationship_confidence': stat_conf,
            'fields': {},
        }
        for tag, val in get_entity_fields(conn, stat_eid):
            sm = get_field_name(conn, 'HeroStatDB', tag)
            stat_view['fields'][tag] = describe_field(tag, val, sm, 'HeroStatDB')
        view['stat_block'] = stat_view

        if len(stat_entities) > 1:
            view['_extra_stat_blocks'] = [
                {'stat_entity_id': eid, 'confidence': c}
                for eid, c in stat_entities[1:]
            ]

    skill_entities = get_related_entities(conn, hero_entity_id, 'SkillDB')
    for sk_eid, sk_conf in skill_entities:
        sk_view = {
            'skill_entity_id': sk_eid,
            'relationship_confidence': sk_conf,
            'fields': {},
        }
        for tag, val in get_entity_fields(conn, sk_eid):
            sm = get_field_name(conn, 'SkillDB', tag)
            sk_view['fields'][tag] = describe_field(tag, val, sm, 'SkillDB')
        view['skills'].append(sk_view)

    equip_entities = get_related_entities(conn, hero_entity_id, 'EquipDB')
    for eq_eid, eq_conf in equip_entities:
        eq_view = {
            'equip_entity_id': eq_eid,
            'relationship_confidence': eq_conf,
            'fields': {},
        }
        for tag, val in get_entity_fields(conn, eq_eid):
            sm = get_field_name(conn, 'EquipDB', tag)
            eq_view['fields'][tag] = describe_field(tag, val, sm, 'EquipDB')
        view['equipment'].append(eq_view)

    for target_type in ['StageDB', 'MonsterDB', 'MasterDB', 'AchieveDB', 'ConfigDB', 'AnimDB']:
        refs = get_entity_references_from(conn, hero_entity_id, target_type)
        for ref_eid, ref_conf in refs:
            ref_view = {
                'entity_id': ref_eid,
                'relationship_confidence': ref_conf,
                'fields': {},
            }
            for tag, val in get_entity_fields(conn, ref_eid):
                sm = get_field_name(conn, target_type, tag)
                ref_view['fields'][tag] = describe_field(tag, val, sm, target_type)
            key_map = {
                'StageDB': 'stage_refs', 'MonsterDB': 'monster_refs',
                'MasterDB': 'master_refs', 'AchieveDB': 'achievement_refs',
                'ConfigDB': 'config_refs', 'AnimDB': 'anim_refs',
            }
            key = key_map.get(target_type, f'{target_type.lower()}_refs')
            if key in view:
                view[key].append(ref_view)

    return view


def print_hero_view(view, show_all_fields=False):
    if not view:
        print("  (entity not found)")
        return

    hid = view['hero_id_value']
    sid = view['stable_id']
    eid = view['entity_id']

    print(f"\n{'='*70}")
    print(f"  HERO VIEW")
    print(f"{'='*70}")
    print(f"  Stable ID:     {sid}")
    print(f"  Entity ID:     {eid}")
    print(f"  Entry Index:   {view['entry_index']}")
    print(f"  Source File:   {view['source_file']}")
    print(f"  Field Count:   {view['field_count']}")
    if hid:
        print(f"  Hero ID Value: {hid}")
    print()

    # Core roster fields
    print(f"  -- HeroRosterDB Fields --")
    core_tags = {23, 4, 5, 6, 7, 8, 9, 13, 14}
    for tag in sorted(view['fields'].keys()):
        fd = view['fields'][tag]
        is_core = tag in core_tags
        if is_core or show_all_fields:
            conf_stars = '*' * int(fd['confidence'] * 10) if fd['confidence'] > 0 else '-'
            print(f"    0x{tag:02X} = {fd['value']:<8d}  {fd['field_name']:<25s}  [{fd['field_type']:<12s}]  conf={fd['confidence']:.2f} {conf_stars}")
            print(f"      src: {fd['source_file']}")
            print(f"      evidence: {fd['evidence'][:120]}")

    unknown_tags = [t for t, fd in view['fields'].items() if fd['confidence'] < 0.3]
    if unknown_tags and not show_all_fields:
        print(f"\n     ... {len(unknown_tags)} low-confidence fields hidden "
              f"(0x{' 0x'.join(f'{t:02X}' for t in unknown_tags[:10])}{'...' if len(unknown_tags) > 10 else ''})")

    # Stat block
    if view['stat_block']:
        sb = view['stat_block']
        print(f"\n  -- HeroStatDB --")
        print(f"     Stat Entity ID: {sb['stat_entity_id']}")
        print(f"     Relationship Confidence: {sb['relationship_confidence']:.2f}")
        for tag, fd in sorted(sb['fields'].items()):
            conf_stars = '*' * int(fd['confidence'] * 10) if fd['confidence'] > 0 else '-'
            print(f"    0x{tag:02X} = {fd['value']:<8d}  {fd['field_name']:<25s}  [{fd['field_type']:<12s}]  conf={fd['confidence']:.2f} {conf_stars}")

        if '_extra_stat_blocks' in view:
            print(f"\n     [!] {len(view['_extra_stat_blocks'])} additional stat blocks (1-to-many)")
    else:
        print(f"\n  -- HeroStatDB: (no stat block linked) --")

    # Skills
    if view['skills']:
        print(f"\n  -- Skills ({len(view['skills'])}) --")
        for sk in view['skills'][:5]:
            print(f"     Skill Entity: {sk['skill_entity_id']} (conf={sk['relationship_confidence']:.2f})")
            for tag, fd in sorted(sk['fields'].items()):
                if fd['confidence'] >= 0.4 or show_all_fields:
                    print(f"      0x{tag:02X} = {fd['value']:<8d}  {fd['field_name']:<25s}  [{fd['field_type']:<12s}]  conf={fd['confidence']:.2f}")
    else:
        print(f"\n  -- Skills: (none linked) --")

    # Equipment
    if view['equipment']:
        print(f"\n  -- Equipment ({len(view['equipment'])}) --")
        for eq in view['equipment'][:5]:
            print(f"     Equip Entity: {eq['equip_entity_id']} (conf={eq['relationship_confidence']:.2f})")
            for tag, fd in sorted(eq['fields'].items()):
                if fd['confidence'] >= 0.4 or show_all_fields:
                    print(f"      0x{tag:02X} = {fd['value']:<8d}  {fd['field_name']:<25s}  [{fd['field_type']:<12s}]  conf={fd['confidence']:.2f}")
    else:
        print(f"\n  -- Equipment: (none linked) --")

    # Other references
    for ref_key in ['stage_refs', 'monster_refs', 'master_refs', 'achievement_refs', 'config_refs', 'anim_refs']:
        refs = view.get(ref_key, [])
        if refs:
            label = ref_key.replace('_refs', '').upper()
            print(f"\n  -- {label} References ({len(refs)}) --")
            for ref in refs[:3]:
                ref_type = ref_key.replace('_refs', '')
                type_name = ''.join(w.capitalize() for w in ref_type.split('_')) + 'DB'
                print(f"     {type_name} Entity: {ref['entity_id']} (conf={ref['relationship_confidence']:.2f})")


def show_hero_by_id(conn, hero_id_val):
    row = conn.execute("""
        SELECT e.id
        FROM entities e
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE et.name = 'HeroRosterDB'
          AND e.id IN (
            SELECT f.entity_id FROM entity_fields f
            WHERE f.tag = 23 AND f.value = ?
          )
          AND e.import_id = ?
        LIMIT 1
    """, (hero_id_val, IMPORT_ID)).fetchone()
    if not row:
        print(f"No HeroRosterDB entity found with hero_id = {hero_id_val}")
        return
    view = reconstruct_hero_view(conn, row['id'])
    print_hero_view(view)


def show_sample_heroes(conn, count=5):
    heroes = conn.execute("""
        SELECT e.id, e.stable_id, e.field_count
        FROM entities e
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE et.name = 'HeroRosterDB'
          AND e.id IN (
            SELECT DISTINCT f.entity_id FROM entity_fields f
            WHERE f.tag = 23 AND f.value > 0
          )
          AND e.field_count >= 3
          AND e.import_id = ?
        ORDER BY e.field_count DESC
        LIMIT ?
    """, (IMPORT_ID, count)).fetchall()
    print(f"Found {len(heroes)} HeroRosterDB entities with hero_id + >=3 fields")
    for i, h in enumerate(heroes):
        print(f"\n{'='*70}")
        print(f"  SAMPLE HERO #{i+1}: {h['stable_id']} ({h['field_count']} fields)")
        print(f"{'='*70}")
        view = reconstruct_hero_view(conn, h['id'])
        print_hero_view(view, show_all_fields=False)


def show_stats(conn):
    print(f"\n{'='*70}")
    print(f"  HERO VIEW - STATISTICS")
    print(f"{'='*70}")

    with_pk = conn.execute("""
        SELECT COUNT(DISTINCT f.entity_id)
        FROM entity_fields f
        JOIN entities e ON f.entity_id = e.id
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE et.name = 'HeroRosterDB'
          AND f.tag = 23 AND f.value > 0
          AND e.import_id = ?
    """, (IMPORT_ID,)).fetchone()[0]

    total = conn.execute("""
        SELECT COUNT(*) FROM entities e
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE et.name = 'HeroRosterDB' AND e.import_id = ?
    """, (IMPORT_ID,)).fetchone()[0]

    print(f"  HeroRosterDB entities:        {total}")
    print(f"  With hero_id (tag 0x17):      {with_pk} ({with_pk/total*100:.1f}%)")

    with_stat = conn.execute("""
        SELECT COUNT(DISTINCT r.target_entity_id)
        FROM relationships r
        WHERE r.source_entity_type = 'HeroStatDB'
          AND r.target_entity_type = 'HeroRosterDB'
          AND r.relationship_type = 'cross_file_ref'
    """).fetchone()[0]
    print(f"  With HeroStatDB relationship: {with_stat} ({with_stat/total*100:.1f}%)")

    with_skill = conn.execute("""
        SELECT COUNT(DISTINCT r.target_entity_id)
        FROM relationships r
        WHERE r.source_entity_type = 'SkillDB'
          AND r.target_entity_type = 'HeroRosterDB'
          AND r.relationship_type = 'cross_file_ref'
    """).fetchone()[0]
    print(f"  With SkillDB relationship:    {with_skill} ({with_skill/total*100:.1f}%)")

    with_equip = conn.execute("""
        SELECT COUNT(DISTINCT r.target_entity_id)
        FROM relationships r
        WHERE r.source_entity_type = 'EquipDB'
          AND r.target_entity_type = 'HeroRosterDB'
          AND r.relationship_type = 'cross_file_ref'
    """).fetchone()[0]
    print(f"  With EquipDB relationship:    {with_equip} ({with_equip/total*100:.1f}%)")

    unique_ids = conn.execute("""
        SELECT COUNT(DISTINCT f.value)
        FROM entity_fields f
        JOIN entities e ON f.entity_id = e.id
        JOIN entity_types et ON e.entity_type_id = et.id
        WHERE et.name = 'HeroRosterDB'
          AND f.tag = 23 AND f.value > 0 AND f.value < 10000
          AND e.import_id = ?
    """, (IMPORT_ID,)).fetchone()[0]
    print(f"  Unique hero_id values (4-digit): {unique_ids}")


def main():
    conn = get_conn()
    print("=" * 70)
    print("  MLA HERO VIEW RECONSTRUCTION")
    print("=" * 70)
    show_stats(conn)
    show_sample_heroes(conn, count=3)
    print(f"\n{'='*70}")
    print(f"  SPECIFIC HERO: hero_id = 1000")
    print(f"{'='*70}")
    show_hero_by_id(conn, 1000)
    conn.close()


if __name__ == '__main__':
    main()
