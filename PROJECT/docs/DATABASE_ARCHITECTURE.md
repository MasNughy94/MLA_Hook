# Database Architecture of Mobile Legends Adventure

## Roo Binary Format Data Model

---

## 1. Overview

The game's data is stored in 7,258 `.mt` files encrypted and compressed via the MT->Antm->AES-128-CBC->lmF@->LMF pipeline. After decryption, each file uses the **Roo Binary Format** (69-byte header + 3-byte tag-value records clustered into entries by gap threshold).

The total corpus breaks down into **7,092 clusters** (schemas), of which:

| Cluster Type | Count | Description |
|---|---|---|
| **Single-file clusters** | 7,043 | Files with unique schemas (1 file per cluster) |
| **Multi-file families** | 49 | Shared schemas across 2-55 files each |
| **Total files** | 7,258 | All decrypted `.mt.dec` files |

### 1.1 Multi-File Family Hierarchy

The 49 multi-member clusters represent true relational database families:

| Family | Files | Tags | Files per Cluster | Role |
|---|---|---|---|---|
| **55f_255t** | 55 | 255 | 1 cluster | Primary entity family (hero, skill, equip, etc.) |
| **23f_9t** | 23 | 9 | 1 cluster | Config/team data family |
| **11f_21t** | 11 | 21 | 1 cluster | Event/mission family |
| **10f_174t** | 10 | 174 | 1 cluster | Stage/mission family |
| **7f_22t** | 7 | 22 | 1 cluster | Guild data family |
| **6f_5t** | 6 | 5 | 1 cluster | Simple config family |
| **5f_Xt** | 15 | 9-19 | 3 clusters | Buff, artifact, and game config families |
| **4f_Xt** | 8 | 19-20 | 2 clusters | Shop/item families |
| **3f_Xt** | 6 | 10-18 | 2 clusters | Event/buff sub-families |
| **2f_254t** | 4 | 254 | 2 clusters | Localization/text families |
| **2f_Xt** | 72 | 4-140 | 36 clusters | Various lookup/reference tables |

---

## 2. The 55f_255t Cluster (Primary Entity Family)

This is the game's central database. All 55 files share a common 255-tag field schema but each file stores a different entity type. Only 10 sample files were available for analysis.

### 2.1 Entity Inventory

| # | File | Name | Entries | Max Fields | Role |
|---|---|---|---|---|---|
| 1 | `1c7efa...` | **EquipDB** | 27,836 | 252 | Equipment and item definitions |
| 2 | `17f4dd...` | **SkillDB** | 27,647 | 66 | Skill and ability definitions |
| 3 | `12eb65...` | **HeroStatDB** | 18,793 | 163 | Hero stat blocks |
| 4 | `07b5cc...` | **HeroRosterDB** | 13,133 | 168 | Hero registry |
| 5 | `1c1ac3...` | **StageDB** | 8,772 | 97 | Stage/mission definitions |
| 6 | `1c4ed1...` | **MonsterDB** | 4,857 | 70 | Monster/NPC definitions |
| 7 | `18f286...` | **AnimDB** | 3,209 | 89 | Animation/visual references |
| 8 | `0217cb...` | **MasterDB** | 2,980 | 53 | Central index/registry |
| 9 | `1a4fb9...` | **ConfigDB** | 2,539 | 88 | System configuration |
| 10 | `0e3bba...` | **AchieveDB** | 1,035 | 194 | Achievement definitions |

### 2.2 Entity Classification Groups

```
SYSTEM LAYER
  MasterDB        —— Central index, references all entities
  ConfigDB        —— Global configuration parameters

HERO LAYER
  HeroRosterDB    —— Hero identities, classes, factions
  HeroStatDB      —— Hero stats, growth rates, attributes
  SkillDB         —— Skill definitions (active, passive, ultimate)
  EquipDB         —— Equipment and item definitions

CONTENT LAYER
  StageDB         —— Campaign stages and missions
  MonsterDB       —— Enemy/NPC definitions
  AnimDB          —— Visual/animation references
  AchieveDB       —— Achievement tracking definitions
```

---

## 3. Entity Relationships

### 3.1 Primary Keys

Each entity type uses file-specific tags as primary identifiers. Primary keys are 4-digit values (1000-9999) that uniquely identify records:

| Entity | PK Tags | Sample Values | Confidence |
|---|---|---|---|
| EquipDB | 0x0C, 0x19, 0x1E | 2276, 2313, 3084 | High |
| SkillDB | 0x25, 0x19 | 2110, 2856, 5140 | High |
| HeroStatDB | 0x20, 0x46 | multiple 4-digit | Medium |
| HeroRosterDB | 0x17, 0x09 | ID 2111 found at tag 0x09 | High |
| StageDB | 0x11, 0x71 | multiple | Medium |
| MonsterDB | 0x11, 0x1C | multiple | Medium |
| AnimDB | 0x90, 0x1C | multiple | Low |
| MasterDB | 0x27, 0x22, 0x80 | multiple | Low |
| ConfigDB | 0x35, 0x0B | multiple | Low |
| AchieveDB | 0x10, 0xBF | multiple | Low |

### 3.2 Foreign Keys

Foreign key relationships are detected through **shared enum values** across files. Enum tags with identical value sets in different files indicate classification systems used by both tables:

**Strong Relationships (Multiple Shared Enum Tags):**

| Source | Target | Shared Tags | Values Example |
|---|---|---|---|
| **EquipDB** | **SkillDB** | 0x07, 0x1E, 0x19, 0x05, 0x0F, 0x3E | {2,3,5}, {3,5,8}, {7} |
| **EquipDB** | **HeroStatDB** | 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x24, 0x28, 0x37, 0xF5 | {3,6}, {5,6,7} |
| **EquipDB** | **HeroRosterDB** | 0x01, 0x02, 0x03, 0x05, 0x09, 0x0D, 0x14, 0x15, 0x33, 0x65, 0x7E | {1,2,3,5,8} |
| **SkillDB** | **HeroRosterDB** | 0x01, 0x05, 0x0A, 0x25, 0x3C | {1,2,3,8}, {2,3,5} |
| **HeroRosterDB** | **HeroStatDB** | 0x02, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x12, 0x2A | {2,3,5}, {3,4} |
| **MonsterDB** | **EquipDB** | 0x05, 0x06, 0x07, 0x0E, 0x0F, 0x14, 0x19, 0x1C, 0x1D | {4,5,6} |
| **MasterDB** | **All entities** | Shared enums with every file | Central registry |
| **AchieveDB** | **HeroStatDB** | 0x08, 0x10 | {3,8} |

### 3.3 Relationship Types

```
MasterDB --one_to_many--> [All entities]     (Central index references everything)
HeroRosterDB --one_to_one--> HeroStatDB       (Each hero has one stat block)
HeroRosterDB --one_to_many--> SkillDB         (Each hero has multiple skills)
HeroRosterDB --one_to_many--> EquipDB         (Each hero can equip multiple items)
StageDB --one_to_many--> MonsterDB            (Each stage has multiple monsters)
SkillDB --many_to_many--> EquipDB             (Skills reference equipment and vice versa)
EquipDB --many_to_many--> MonsterDB           (Equipment drops from monsters)
HeroStatDB --many_to_many--> EquipDB          (Equipment modifies hero stats)
```

### 3.4 Entity Relationship Diagram

```
                        ┌───────────────────┐
                        │     MasterDB      │  Central Index (2980 entries)
                        │  (0217cb...)      │
                        └────────┬──────────┘
                                 │
              ┌──────────────────┼──────────────────────┐
              │                  │                      │
              ▼                  ▼                      ▼
    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │   HeroRosterDB  │  │    SkillDB      │  │    EquipDB      │
    │  (07b5cc...)    │  │  (17f4dd...)    │  │  (1c7efa...)    │
    │  13,133 entries │  │  27,647 entries │  │  27,836 entries │
    │  PK: 0x09       │  │  PK: 0x25       │  │  PK: 0x0C/0x19 │
    └────────┬────────┘  └─────────────────┘  └────────┬────────┘
             │                                         │
             │                                         │
             ▼                                         ▼
    ┌─────────────────┐                       ┌─────────────────┐
    │   HeroStatDB    │                       │    StageDB      │
    │  (12eb65...)    │                       │  (1c1ac3...)    │
    │  18,793 entries │                       │  8,772 entries  │
    │  PK: 0x20/0x46  │                       │  PK: 0x11       │
    └─────────────────┘                       └────────┬────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │   MonsterDB     │
                                              │  (1c4ed1...)    │
                                              │  4,857 entries  │
                                              │  PK: 0x11/0x1C  │
                                              └─────────────────┘

    ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
    │    AnimDB       │  │    ConfigDB     │  │   AchieveDB     │
    │  (18f286...)    │  │  (1a4fb9...)    │  │  (0e3bba...)    │
    │  3,209 entries  │  │  2,539 entries  │  │  1,035 entries  │
    └─────────────────┘  └─────────────────┘  └─────────────────┘

Legend:
  ── one_to_one
  ── one_to_many
  ── many_to_many (via shared enum tags)
  PK = Primary Key tag
```

---

## 4. Reference Resolution

### 4.1 Value Encoding Scheme

Values in the Roo format use a hierarchical encoding:

| Value Range | Meaning | Example |
|---|---|---|
| 0 | Empty/NULL | No value set |
| 1-999 | Local enum or flag | Class 1 = Mage |
| 1,000-9,999 | Entity ID (Hero, Item, Stage) | 2111 = Hero ID |
| 10,000-49,999 | Config/constant value | Stat thresholds |
| 50,000-59,999 | Cross-file reference | Reference to another file in cluster |
| 60,000-65,535 | Global resource reference | System-wide resource ID |

### 4.2 Reference Resolution Strategy

When a tag value exceeds 50,000, it can be resolved by:

1. **High byte as file group index**: Values 50,000-51,999 → group 0, 52,000-53,999 → group 1, etc.
2. **Low byte as entry offset**: Within the target file, the remainder points to a specific entry
3. **Tag determines target file**: A tag like 0xCE (skill) always references SkillDB regardless of value

### 4.3 Cross-Reference Example

In MasterDB Entry 17:
- Tag 0xFA = 5380 → EquipDB entry (4-digit item ID)
- Tag 0xCE = 50924 → SkillDB reference (skill definition)
- Tag 0x15 = 50809 → HeroStatDB reference (stat block)

---

## 5. Other Database Families

### 5.1 Config/Team Family (23f_9t)

- **23 files, 9 tags each**
- Contains: config_global, config_team entity types
- Role: System configuration and team formation data
- Already documented in semantic_db_v3.json

### 5.2 Event/Mission Family (11f_21t)

- **11 files, 21 tags each**
- Contains: config_event entity type
- Role: Event definitions, mission objectives, and progress tracking

### 5.3 Stage/Mission Family (10f_174t)

- **10 files, 174 tags each**
- Role: Campaign stage data with enemy compositions, rewards, and difficulty scaling

### 5.4 Guild Family (7f_22t)

- **7 files, 22 tags each**
- Contains: guild_db entity type
- Role: Guild management, member data, and guild activities

### 5.5 Localization Family (2f_254t)

- **2 files, 254 tags each**
- Role: Text localization and language strings
- Note: Nearly matches 55f_255t in tag count but with different semantic meaning (text vs. game data)

### 5.6 Other Small Families

The remaining 2-5 file families handle specific subsystems:
- **Buff effects** (5f_15t) → buff_db
- **Artifacts** (5f_19t) → artifact_db
- **Shop data** (4f_19t, 4f_20t) → config_shop
- **Various lookups** (2f_Xt) → enumerated value tables

---

## 6. Limitations

1. **Incomplete cluster membership**: Only 10 of 55 files in the 55f_255t cluster were available for analysis. The remaining 45 files likely continue the same patterns but are not yet decrypted.

2. **File-specific tag assignment**: The same tag (e.g., 0x05) may represent a Rarity enum in EquipDB but an Element enum in HeroRosterDB. Semantic meaning must be determined per-file.

3. **Confidence varies**: Primary key and foreign key assignments are based on statistical patterns (4-digit ID frequency, enum value sharing). Ground truth requires APK code verification.

4. **Single-entry entities**: Many single-file clusters (7,043 total) are not categorized. These likely contain one-off configurations, debug data, or unused assets.
