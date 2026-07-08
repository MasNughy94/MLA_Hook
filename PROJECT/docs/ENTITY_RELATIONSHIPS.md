# Entity Relationships — Mobile Legends Adventure

## Detailed Relationship Database for the 55f_255t Cluster

---

## 1. Entity Schema Catalog

### 1.1 MasterDB (Central Index)
- **File**: `0217cbdae530696836de83aa3c162e1a.mt.dec`
- **Entries**: 2,980
- **Max fields per entry**: 53
- **Avg fields per entry**: 2.5
- **Signature uniqueness**: 1,652 unique tag combinations out of 2,980 entries
- **Role**: Central entity registry — maps all game objects to their attributes

**Primary Key Candidates**: Tags 0x27 (67 unique values), 0x22 (48 unique), 0x80 (33 unique)

**Referenced by**: All other entities (through shared enum values)

**Key pattern**: 54.2% of entries use only 1 tag (simple lookups); 45.8% use 2+ tags

### 1.2 EquipDB (Equipment & Items)
- **File**: `1c7efa501c5305fb7062cdcbf148c4a9.mt.dec`
- **Entries**: 27,836 (largest file)
- **Max fields per entry**: 252
- **Avg fields per entry**: 3.2
- **Signature uniqueness**: 13,256 unique tag combinations
- **Role**: Complete equipment and item catalog

**Primary Key Candidates**: Tags 0x0C (e.g., 2276, 2313, 2316), 0x19 (e.g., 2110, 2856), 0x1E (e.g., 2569, 3081)

**Foreign Key Relationships**:
- → SkillDB: 6 shared enum tags (0x07, 0x1E, 0x1F, 0x19, 0x3E, 0x05, 0x0F)
- → HeroStatDB: 11 shared enum tags (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x24, 0x28, 0x37, 0xF5)
- → HeroRosterDB: 11 shared enum tags (0x01, 0x02, 0x03, 0x05, 0x09, 0x0D, 0x14, 0x15, 0x33, 0x65, 0x7E)
- → MonsterDB: 9 shared enum tags

**Top tag**: 0xF1 (1,829 occurrences, 6.6%) — item type discriminator

### 1.3 SkillDB (Skills & Abilities)
- **File**: `17f4dd5419fdea6aff836f46154d274a.mt.dec`
- **Entries**: 27,647
- **Max fields per entry**: 66
- **Avg fields per entry**: 2.5
- **Signature uniqueness**: 10,900 unique tag combinations
- **Role**: All skill and ability definitions

**Primary Key Candidates**: Tags 0x25, 0x19, 0x1A

**Foreign Key Relationships**:
- → EquipDB: 7 shared enum tags
- → HeroRosterDB: 5 shared enum tags
- → MonsterDB: 4 shared enum tags
- → AnimDB: 1 shared enum tag

**Top tag**: 0x25 (391 occurrences) — skill type discriminator

**Key pattern**: 53.8% single-tag entries (simple skill references); 46.2% multi-tag

### 1.4 HeroStatDB (Hero Stats)
- **File**: `12eb65e862c413254ae49d2eba76eea2.mt.dec`
- **Entries**: 18,793
- **Max fields per entry**: 163 (contains the most complete object definitions)
- **Avg fields per entry**: 2.9
- **Signature uniqueness**: 8,130 unique tag combinations
- **Role**: Hero stat blocks with attribute scaling

**Primary Key Candidates**: Tags 0x20, 0x46, 0x0A

**Foreign Key Relationships**:
- → EquipDB: 12 shared enum tags (most interconnected entity)
- → SkillDB: 4 shared enum tags
- → MonsterDB: 4 shared enum tags

**Top tag**: 0x4B (336 occurrences) — stat type discriminator

**Notable**: Entry 16571 has 163 fields — the most complete record in the entire cluster, containing a complete hero stat block with skill references.

### 1.5 HeroRosterDB (Hero Registry)
- **File**: `07b5cc5ea4a8d86273be8170720a4587.mt.dec`
- **Entries**: 13,133
- **Max fields per entry**: 168
- **Avg fields per entry**: 3.8
- **Signature uniqueness**: 6,811 unique tag combinations
- **Role**: Hero identities, classifications, and evolution paths

**Primary Key Candidates**: Tags 0x17, 0x09 (HeroID 2111 found at tag 0x09), 0x0D

**Foreign Key Relationships**:
- → EquipDB: 11 shared enum tags
- → HeroStatDB: 9 shared enum tags
- → SkillDB: 5 shared enum tags
- → MonsterDB: 3 shared enum tags
- → AchieveDB: 1 shared enum tag

**Top tag**: 0x4E — hero type discriminator

**Notable**: 490 entries use tag 0x09 (HeroID carrier), ranging from 1 to 143 fields per entry

### 1.6 StageDB (Stages & Missions)
- **File**: `1c1ac35710f3a4276a942a776e911a85.mt.dec`
- **Entries**: 8,772
- **Max fields per entry**: 97
- **Avg fields per entry**: 3.0
- **Signature uniqueness**: 4,474 unique tag combinations
- **Role**: Campaign stage progression data

**Primary Key Candidates**: Tags 0x11, 0x71, 0x18

**Relationships**: References MonsterDB for enemy spawns

**Top tag**: 0x71 — stage type discriminator

### 1.7 MonsterDB (Monsters & NPCs)
- **File**: `1c4ed1eebdb4b8af5c2658f4151aa529.mt.dec`
- **Entries**: 4,857
- **Max fields per entry**: 70
- **Avg fields per entry**: 3.1
- **Signature uniqueness**: 2,663 unique tag combinations
- **Role**: Enemy and NPC definitions

**Primary Key Candidates**: Tags 0x11, 0x1C, 0x06

**Foreign Key Relationships**:
- → EquipDB: 9 shared enum tags (equipment drops)
- → HeroStatDB: 4 shared enum tags (stat comparison)
- → SkillDB: 4 shared enum tags (enemy skills)

**Top tag**: 0x45 — monster type discriminator

### 1.8 AnimDB (Animation & Visuals)
- **File**: `18f286461b12e92d9e16b27c07854a7c.mt.dec`
- **Entries**: 3,209
- **Max fields per entry**: 89
- **Avg fields per entry**: 3.3
- **Signature uniqueness**: 1,850 unique tag combinations
- **Role**: Animation, visual effects, and skeletal mesh references

**Primary Key Candidates**: Tags 0x90, 0x1C, 0x91

**Relationships**: Referenced by HeroRosterDB and SkillDB

**Top tag**: 0x90 — animation type discriminator

### 1.9 ConfigDB (System Config)
- **File**: `1a4fb9f36cd34d0eb0ca22000e54f8a5.mt.dec`
- **Entries**: 2,539
- **Max fields per entry**: 88
- **Avg fields per entry**: 5.1
- **Signature uniqueness**: 1,897 unique tag combinations
- **Role**: Game system configuration parameters

**Primary Key Candidates**: Tags 0x35, 0x0B, 0x01

**Top tag**: 0x43 — config parameter type

### 1.10 AchieveDB (Achievements)
- **File**: `0e3bbac67f12505f7dfe45d4e6aba1ea.mt.dec`
- **Entries**: 1,035
- **Max fields per entry**: 194 (most complex schema)
- **Avg fields per entry**: 8.7
- **Signature uniqueness**: 883 unique tag combinations
- **Role**: Achievement definitions and progress tracking

**Primary Key Candidates**: Tags 0x10, 0xBF, 0x09

**Relationships**: Shares enum values with HeroStatDB (tags 0x08, 0x10) indicating hero-stat-based achievement conditions

**Top tag**: 0x6A — achievement type discriminator

---

## 2. Cross-File Reference Map

### 2.1 Tag Co-occurrence Matrix

Shared enum tags indicate which classification systems are used across entity types:

| Entity | EquipDB | SkillDB | HeroStat | HeroRost | StageDB | Monster | AnimDB | Master | Config | Achieve |
|---|---|---|---|---|---|---|---|---|---|---|
| **EquipDB** | — | 7 | 12 | 11 | — | 9 | 1 | — | — | — |
| **SkillDB** | 7 | — | 4 | 5 | — | 4 | 1 | — | — | — |
| **HeroStat** | 12 | 4 | — | 9 | — | 4 | — | — | — | 2 |
| **HeroRost** | 11 | 5 | 9 | — | — | 3 | — | — | — | 1 |
| **StageDB** | — | — | — | — | — | — | — | — | — | — |
| **Monster** | 9 | 4 | 4 | 3 | — | — | — | — | — | — |
| **AnimDB** | 1 | 1 | — | — | — | — | — | — | — | — |
| **MasterDB** | 6 | 4 | 4 | 4 | — | 2 | — | — | — | — |
| **ConfigDB** | — | — | — | — | — | — | — | — | — | — |
| **Achieve** | — | — | 2 | 1 | — | — | — | — | — | — |

Values = number of shared enum tags. Higher values = stronger relationship.

### 2.2 Interconnection Density

```
EquipDB     — 30 shared enum tags across 5 entities (hub node)
HeroRosterDB — 29 shared enum tags across 5 entities (hub node)
HeroStatDB   — 31 shared enum tags across 5 entities (hub node)
SkillDB      — 21 shared enum tags across 5 entities
MonsterDB    — 20 shared enum tags across 4 entities
MasterDB     — 20 shared enum tags across 5 entities
AchieveDB    — 3 shared enum tags across 2 entities
AnimDB       — 2 shared enum tags across 2 entities
StageDB      — 0 shared enum tags (isolated)
ConfigDB     — 0 shared enum tags (isolated)
```

### 2.3 Relationship Confidence Scores

| Relationship | Confidence | Evidence Strength |
|---|---|---|
| EquipDB ↔ HeroRosterDB | **0.80** | 11 shared enum tags, cross-referenced HeroIDs |
| EquipDB ↔ HeroStatDB | **0.80** | 12 shared enum tags, stat-equipment linkage |
| HeroRosterDB ↔ HeroStatDB | **0.75** | 9 shared enum tags, 1:1 hero mapping |
| EquipDB ↔ SkillDB | **0.70** | 7 shared enum tags, skill-equip linkage |
| EquipDB ↔ MonsterDB | **0.65** | 9 shared enum tags, monster drops |
| MasterDB → All | **0.60** | Central registry pattern, shared enums with all |
| HeroRosterDB ↔ SkillDB | **0.60** | 5 shared enum tags, hero skill assignment |
| HeroStatDB ↔ MonsterDB | **0.50** | 4 shared enum tags, stat comparison |
| StageDB → MonsterDB | **0.40** | Logical relationship (stages have monsters) |

---

## 3. Field Role Classification

### 3.1 Role Definitions

Each field (tag) in an entry serves one of these roles:

| Role | Definition | Examples |
|---|---|---|
| **PrimaryKey** | Uniquely identifies the record | 4-digit ID values (1000-9999) |
| **ForeignKey** | References another entity's PK | Shared enum values, large refs (50000+) |
| **LocalIdentifier** | Index within the same file | Small values (0-999) |
| **Enumeration** | Classification/category value | Class 1-5, Faction 1-5, Star 1-8 |
| **BitFlag** | Boolean switch (0/1) | 0x09, 0x0B in MasterDB |
| **Constant** | Fixed value across all records | 0x0D, 0x45, 0x49, 0x60, 0x88 |
| **CrossFileRef** | Reference to another file in cluster | Values 50000-65535 |
| **Optional** | May be absent (present in <50% entries) | Tags with presence_pct < 50 |

### 3.2 Role Distribution (MasterDB)

| Role | Tag Count | Example Tags |
|---|---|---|
| **CrossFileRef** (50000+) | ~40 | 0x08, 0x0A, 0x1C, 0x5B, 0x65, 0x6F, 0xB0 |
| **Enumeration** (1-8) | ~15 | 0x01-0x08 (faction, class, star, element) |
| **LocalIdentifier** (100-999) | ~90 | 0x21-0x2F, 0x50-0x7F (animation, portrait, effect IDs) |
| **EntityID** (1000-9999) | ~16 | 0x03, 0x0C, 0x10, 0x11, 0x14, 0x15, 0x20, 0x25 |
| **Optional/Unused** | ~5 | 0x0D, 0x45, 0x49, 0x60, 0x88 |
| **Unknown** | ~89 | Varying presence and values |

---

## 4. File Signature Summary

Each file's uniqueness is measured by how many distinct tag signatures appear:

| Entity | Entries | Unique Signatures | Signature/Entry Ratio | Diversity |
|---|---|---|---|---|
| AchieveDB | 1,035 | 883 | 0.85 | Most diverse (near 1:1) |
| EquipDB | 27,836 | 13,256 | 0.48 | Highly diverse |
| SkillDB | 27,647 | 10,900 | 0.39 | Diverse |
| ConfigDB | 2,539 | 1,897 | 0.75 | Highly diverse |
| AnimDB | 3,209 | 1,850 | 0.58 | Diverse |
| MasterDB | 2,980 | 1,652 | 0.55 | Diverse |
| HeroRosterDB | 13,133 | 6,811 | 0.52 | Diverse |
| HeroStatDB | 18,793 | 8,130 | 0.43 | Diverse |
| StageDB | 8,772 | 4,474 | 0.51 | Diverse |
| MonsterDB | 4,857 | 2,663 | 0.55 | Diverse |

Lower ratio = more uniform structure (same tag patterns repeated). Higher ratio = more heterogeneous (each entry is nearly unique).

---

## 5. Known Entity IDs

Entity IDs were cross-referenced across the cluster:

| ID | Entity Type | Found In | Tag |
|---|---|---|---|
| 2111 | Hero | HeroRosterDB (07b5cc) | 0x09 |
| 2112 | Hero | HeroStatDB (12eb65) | 0x83 |
| 5970 | Hero | EquipDB (1c7efa) | 0x55 |
| 3019 | Hero/Item | HeroRosterDB | 0x7A |
| 6089 | Hero/Item | HeroRosterDB | 0xB7 |
| 4303 | Hero/Item | HeroStatDB | 0xF4 |
| 5380 | Entity | MasterDB | 0xFA |
| 4076 | Entity | MasterDB | 0xEC |
| 6854 | Entity | MasterDB | 0xB5 |

> **Note**: These IDs are not sequential. The gap between e.g. 2111 and 2112 suggests sparse ID assignment or grouping by hero release order.
