# Hero Database — Mobile Legends Adventure

## Reference Summary

---

## Overview

The Hero Database is not a single file but a **distributed relational database** spanning 55 files sharing a common 255-tag schema (the `55f_255t` cluster). The central index file (`0217cbdae530696836de83aa3c162e1a.mt.dec`) serves as the Master Registry, while hero-specific data lives in dedicated files.

For the complete detailed schema (255 tags, all field classifications, entry signatures), see:
- [`../semantic/hero_db_schema.md`](../semantic/hero_db_schema.md)
- [`../semantic/hero_db_schema.json`](../semantic/hero_db_schema.json)
- [`../semantic/semantic_db_v3.json`](../semantic/semantic_db_v3.json) (merged with all entity types)

For the relational architecture, see:
- [`DATABASE_ARCHITECTURE.md`](DATABASE_ARCHITECTURE.md)
- [`ENTITY_RELATIONSHIPS.md`](ENTITY_RELATIONSHIPS.md)

---

## Hero Entity Family

```
MasterDB (0217cb...)
  │
  ├── HeroRosterDB (07b5cc...)   — Hero identities, classes, factions
  │     └── HeroStatDB (12eb65...) — Hero stats, growth, attributes
  │
  ├── SkillDB (17f4dd...)        — Skill/ability definitions
  │
  ├── EquipDB (1c7efa...)        — Equipment/item definitions
  │
  ├── MonsterDB (1c4ed1...)      — Enemy/NPC definitions
  │
  ├── StageDB (1c1ac3...)        — Campaign stage/mission definitions
  │
  ├── AnimDB (18f286...)         — Animation/visual references
  │
  ├── ConfigDB (1a4fb9...)       — System configuration
  │
  └── AchieveDB (0e3bba...)      — Achievement definitions
```

---

## Key Files for Hero Reconstruction

| Priority | File | Purpose | Why |
|---|---|---|---|
| 1 | `07b5cc...` | **HeroRosterDB** | Contains HeroIDs (2111 at tag 0x09), class/faction enums, evolution paths |
| 2 | `12eb65...` | **HeroStatDB** | Contains complete stat blocks (entry 16571 has 163 fields — the most complete record) |
| 3 | `17f4dd...` | **SkillDB** | Contains skill definitions (27K entries) referenced by heroes |
| 4 | `1c7efa...` | **EquipDB** | Contains equipment definitions shared across all entities |
| 5 | `0217cb...` | **MasterDB** | Central index mapping all entity IDs to their attributes |

---

## Schema Location

| Artifact | Path | Format |
|---|---|---|
| Tag-level field analysis | `../analysis/hero_db_schema_analysis.json` | 255 tags with value ranges, samples, classifications |
| Entity schemas | `../semantic/entity_schemas.json` | 10 entity types with field catalogs |
| Entity relationships | `../semantic/entity_relationships.json` | 32 detected relationships |
| Primary keys | `../semantic/primary_keys.json` | PK candidates per entity |
| Foreign keys | `../semantic/foreign_keys.json` | FK relationships with confidence scores |
| Reference graph | `../semantic/reference_graph.json` | Machine-readable graph structure |
