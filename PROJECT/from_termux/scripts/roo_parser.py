#!/usr/bin/env python3
"""
Roo Binary Format Parser
Berdasarkan dokumentasi reverse engineering Claude (29 Juni 2026).

Format:
  Header (69 bytes):
    [0x00] 4B  Magic: 1B 4C 6D 00
    [0x04] 2B  Padding (zeros)
    [0x06] 4B  "Roo\0"
    [0x0A] 1B  Format byte (0xA9 untuk game assets)
    [0x0B] 58B Markers/data blocks (contains 0xD1D1 pairs)
    [0x41]     Body: 3-byte records [tag, v1, v2]

  Record types:
    - Override (tag != 0): Instance-specific data
    - Template (tag == 0, v1/v2 != 0): Default values
    - Empty (tag == 0, v1 == 0, v2 == 0): Padding (~82%)

  Entry clustering: gap > 30 bytes (=10 records) between override records

Usage:
  python roo_parser.py <file.bin>          # Parse Roo file
  python roo_parser.py <file.bin> --json   # Output JSON
  python roo_parser.py <file.bin> --sqlite # Output SQLite database
"""

import os, sys, struct, json

ROO_MAGIC = b"\x1bL\x6d\x00"
ROO_HEADER_SIZE = 69
RECORD_SIZE = 3

# Field name mappings (dari resume Claude)
FIELD_NAMES = {
    # High confidence mappings
    0x17: ("hero_id", "HeroRosterDB", 0.90),
    0x25: ("skill_id", "SkillDB", 0.90),
    0x0C: ("equip_id", "EquipDB", 0.85),
    0x11: ("stage_id", "StageDB", 0.85),
    0x20: ("hero_stat_id", "HeroStatDB", 0.85),
    0x04: ("hero_class", "HeroRosterDB", 0.80),
    0x0A: ("master_id", "MasterDB", 0.80),
    0xF1: ("monster_id", "MonsterDB", 0.80),
    0xF2: ("item_type", "EquipDB", 0.75),
    0x84: ("base_hp", "HeroStatDB", 0.70),
    0x85: ("base_atk", "HeroStatDB", 0.70),
    0x86: ("base_def", "HeroStatDB", 0.70),
    0x05: ("faction", "HeroRosterDB", 0.70),
    0x06: ("rarity", "HeroRosterDB", 0.70),
}

# Entity type detection patterns
ENTITY_PATTERNS = {
    frozenset([0x17, 0x04, 0x05, 0x06]): "HeroRosterDB",
    frozenset([0x25]): "SkillDB",
    frozenset([0x0C]): "EquipDB",
    frozenset([0x11]): "StageDB",
    frozenset([0x20]): "HeroStatDB",
    frozenset([0x0A]): "MasterDB",
    frozenset([0xF1]): "MonsterDB",
    frozenset([0x14, 0x15, 0x16]): "ConfigDB",
}


def decode_value(v1, v2):
    """Decode a value from v1,v2 pair"""
    raw = (v1 << 8) | v2
    
    if v1 == 0 and v2 == 0:
        return raw, "zero"
    if v2 == 0 and v1 <= 8:
        return v1, "enum"
    if v1 == v2:
        return raw, "pair"
    if v1 < 0x10:
        return raw, "sparse"
    return raw, "raw"


def parse_roo(data):
    """
    Parse Roo Binary Format.
    Returns dict dengan entries, fields, metadata.
    """
    if len(data) < ROO_HEADER_SIZE:
        return {"error": f"Too small: {len(data)} bytes (need 69)"}
    
    if data[:4] != ROO_MAGIC:
        return {"error": f"Invalid magic: {data[:4].hex()} (expected 1b4c6d00)"}
    
    # --- Parse header ---
    magic = data[:4]
    padding = data[4:6]
    roo_str = data[6:10]
    fmt_byte = data[10]
    markers = data[11:69]
    
    # Parse D1D1 marker pairs
    d1d1_pairs = []
    for i in range(0, len(markers), 2):
        if i + 1 < len(markers):
            if markers[i] == 0xD1 and markers[i+1] == 0xD1:
                d1d1_pairs.append(i)
    
    body = data[ROO_HEADER_SIZE:]
    
    result = {
        "magic": magic.hex(),
        "roo_str": roo_str.decode('ascii', errors='replace'),
        "format_byte": fmt_byte,
        "markers_d1d1": len(d1d1_pairs),
        "body_offset": ROO_HEADER_SIZE,
        "body_size": len(body),
        "total_size": len(data),
    }
    
    # --- Parse records ---
    records = []
    i = 0
    while i + RECORD_SIZE <= len(body):
        tag = body[i]
        v1 = body[i+1]
        v2 = body[i+2]
        
        val, vtype = decode_value(v1, v2)
        
        records.append({
            "tag": tag,
            "tag_hex": f"0x{tag:02X}",
            "v1": v1,
            "v2": v2,
            "value": val,
            "type": vtype,
            "offset": i,
            "global_offset": ROO_HEADER_SIZE + i,
        })
        i += RECORD_SIZE
    
    result["record_count"] = len(records)
    
    # --- Cluster into entries ---
    entries = []
    current_entry = []
    last_override_offset = -1
    GAP_RECORDS = 10  # 30 bytes / 3 bytes per record
    
    for rec in records:
        # Skip empty records (padding)
        if rec["tag"] == 0 and rec["v1"] == 0 and rec["v2"] == 0:
            continue
        
        if rec["tag"] != 0:
            # Override record - potencial start of entry
            if last_override_offset >= 0:
                gap = rec["offset"] - last_override_offset
                if gap > GAP_RECORDS and len(current_entry) > 0:
                    # Gap besar → entry boundary
                    entries.append(current_entry)
                    current_entry = []
            last_override_offset = rec["offset"]
            current_entry.append(rec)
        else:
            # Template record (tag=0, v1/v2 != 0)
            current_entry.append(rec)
    
    if current_entry:
        entries.append(current_entry)
    
    result["entry_count"] = len(entries)
    
    # --- Format entries ---
    entry_list = []
    for ei, entry in enumerate(entries):
        fields = []
        for rec in entry:
            fname = FIELD_NAMES.get(rec["tag"], None)
            field_info = {
                "tag": rec["tag"],
                "tag_hex": rec["tag_hex"],
                "v1": rec["v1"],
                "v2": rec["v2"],
                "value": rec["value"],
                "type": rec["type"],
            }
            if fname:
                field_info["field_name"] = fname[0]
                field_info["confidence"] = fname[2]
            fields.append(field_info)
        
        # Tag signature
        tags = sorted(set(f["tag"] for f in fields))
        sig_hex = "-".join(f"0x{t:02X}" for t in tags)
        
        entry_list.append({
            "index": ei,
            "field_count": len(fields),
            "tag_count": len(tags),
            "tag_signature": sig_hex,
            "fields": fields,
        })
    
    result["entries"] = entry_list
    
    # --- Detect entity type ---
    if entry_list:
        tags_set = frozenset(tag for f in entry_list[0]["fields"] 
                            for tag in [f["tag"]])
        # Actually get tags from entry
        first_entry_tags = set()
        for f in entry_list[0]["fields"]:
            first_entry_tags.add(f["tag"])
        
        for pattern, etype in ENTITY_PATTERNS.items():
            if pattern.issubset(first_entry_tags):
                result["detected_type"] = etype
                break
        
        if "detected_type" not in result:
            result["detected_type"] = "Unknown"
    
    # --- Stats ---
    tag_stats = {}
    for rec in records:
        if rec["tag"] not in tag_stats:
            tag_stats[rec["tag"]] = {"count": 0, "values": {}}
        tag_stats[rec["tag"]]["count"] += 1
    
    result["tag_stats"] = {
        f"0x{t:02X}": v["count"] 
        for t, v in sorted(tag_stats.items()) 
        if v["count"] > 5  # Only show frequent tags
    }
    
    return result


def print_roo(roo, max_entries=5, max_fields=30):
    """Pretty print Roo data"""
    if "error" in roo:
        print(f"❌ {roo['error']}")
        return
    
    print(f"📦 Roo Binary")
    print(f"  Magic:     {roo['magic']}")
    print(f"  String:    {roo['roo_str']}")
    print(f"  Format:    0x{roo['format_byte']:02X}")
    print(f"  D1D1 markers: {roo['markers_d1d1']}")
    print(f"  Body:      {roo['body_size']:,} bytes")
    print(f"  Records:   {roo['record_count']:,}")
    print(f"  Entries:   {roo['entry_count']:,}")
    print(f"  Type:      {roo.get('detected_type', '?')}")
    
    if roo.get('tag_stats'):
        print(f"\n📊 Tag Frequency:")
        for tag, count in sorted(roo['tag_stats'].items(), key=lambda x: -x[1])[:10]:
            fname = FIELD_NAMES.get(int(tag, 16), None)
            name = f" ({fname[0]})" if fname else ""
            print(f"  {tag}: {count}{name}")
    
    print(f"\n📋 Entries (showing {min(max_entries, roo['entry_count'])} of {roo['entry_count']}):")
    for ei, entry in enumerate(roo['entries'][:max_entries]):
        print(f"\n  ─── Entry {entry['index']} ({entry['field_count']} fields) ───")
        for fi, f in enumerate(entry['fields'][:max_fields]):
            name = f.get('field_name', '')
            conf = f.get('confidence', 0)
            name_str = f"  ← {name}" if name else ""
            print(f"    [{f['tag_hex']:>4}] v1={f['v1']:3d} v2={f['v2']:3d} "
                  f"val={f['value']:6d} [{f['type']:>6}]{name_str}")
        if len(entry['fields']) > max_fields:
            print(f"    ... ({len(entry['fields']) - max_fields} more fields)")


def roo_to_json(roo, output_path):
    """Save Roo data as JSON"""
    with open(output_path, 'w') as f:
        json.dump(roo, f, indent=2)
    print(f"JSON saved: {output_path}")


def roo_to_csv(roo, output_dir):
    """Save entries as CSV"""
    os.makedirs(output_dir, exist_ok=True)
    
    for ei, entry in enumerate(roo['entries']):
        csv_path = os.path.join(output_dir, f"entry_{ei:04d}.csv")
        with open(csv_path, 'w') as f:
            f.write("tag,tag_hex,v1,v2,value,type,field_name,confidence\n")
            for field in entry['fields']:
                fname = field.get('field_name', '')
                conf = field.get('confidence', 0)
                f.write(f"{field['tag']},{field['tag_hex']},{field['v1']},"
                       f"{field['v2']},{field['value']},{field['type']},"
                       f"{fname},{conf}\n")
    
    print(f"CSV files saved to {output_dir}/ ({len(roo['entries'])} entries)")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    
    fpath = sys.argv[1]
    if not os.path.exists(fpath):
        print(f"File not found: {fpath}")
        return
    
    with open(fpath, 'rb') as f:
        data = f.read()
    
    roo = parse_roo(data)
    
    # Detect format from JSON args
    fmt = "print"
    for arg in sys.argv[2:]:
        if arg == '--json':
            fmt = 'json'
        elif arg == '--csv':
            fmt = 'csv'
        elif arg == '--sqlite':
            fmt = 'sqlite'
    
    if fmt == 'print':
        print_roo(roo)
    elif fmt == 'json':
        out = os.path.splitext(fpath)[0] + '.json'
        roo_to_json(roo, out)
    elif fmt == 'csv':
        out_dir = os.path.splitext(fpath)[0] + '_csv'
        roo_to_csv(roo, out_dir)
    elif fmt == 'sqlite':
        try:
            import sqlite3
            db_path = os.path.splitext(fpath)[0] + '.db'
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            
            c.execute('''CREATE TABLE IF NOT EXISTS entities
                (id INTEGER PRIMARY KEY, entry_index INTEGER, field_count INTEGER, tag_signature TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS fields
                (id INTEGER PRIMARY KEY, entity_id INTEGER, tag INTEGER, v1 INTEGER, v2 INTEGER, 
                 value INTEGER, type TEXT, field_name TEXT, confidence REAL)''')
            
            for ei, entry in enumerate(roo['entries']):
                c.execute("INSERT INTO entities (entry_index, field_count, tag_signature) VALUES (?,?,?)",
                         (ei, entry['field_count'], entry['tag_signature']))
                eid = c.lastrowid
                for f in entry['fields']:
                    c.execute("INSERT INTO fields (entity_id, tag, v1, v2, value, type, field_name, confidence) "
                             "VALUES (?,?,?,?,?,?,?,?)",
                             (eid, f['tag'], f['v1'], f['v2'], f['value'], f['type'],
                              f.get('field_name', ''), f.get('confidence', 0)))
            
            conn.commit()
            conn.close()
            print(f"SQLite database saved: {db_path}")
            print(f"  Entries: {len(roo['entries'])}")
            total_fields = sum(e['field_count'] for e in roo['entries'])
            print(f"  Fields: {total_fields}")
        except ImportError:
            print("sqlite3 not available")
    
    # Also print summary
    if fmt != 'print':
        print(f"\n📊 Summary: {roo['entry_count']} entries, {roo['record_count']} records, "
              f"type={roo.get('detected_type', '?')}")


if __name__ == '__main__':
    main()
