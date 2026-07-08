# Hero Database Schema Specification

## Mobile Legends Adventure — Roo Binary Format Schema Reconstruction

---

## 1. Overview

- **Source file:** `0217cbdae530696836de83aa3c162e1a.mt.dec`
- **Related docs:** [`DATABASE_ARCHITECTURE.md`](../docs/DATABASE_ARCHITECTURE.md), [`ENTITY_RELATIONSHIPS.md`](../docs/ENTITY_RELATIONSHIPS.md), [`HERO_DATABASE.md`](../docs/HERO_DATABASE.md)
- **Cluster:** 55 files, 255 tags (cluster `55f_255t`)
- **Classification:** MASTER_DB (primary reference database)
- **Total entries:** 2980
- **Total tags:** 255
- **File size:** 93,732 bytes decrypted (69-byte Roo header + 93,663 bytes body)

### 1.1 Role in the Game

The Master DB is the game's central entity registry. It does **not** contain full hero definitions inline. Instead, it maps entities (heroes, skills, items, stages, etc.) to references across the 55-file cluster. Each of the 2980 entries is a **packed record** whose tag signature determines its entity type. The actual hero data is distributed across the cluster — this file is the **index** that ties it together.

### 1.2 Relationship to Other Schema Files

| semantic_v3 Key | Relation to Hero DB |
|---|---|
| `artifact_db` | Artifacts referenced by hero equipment slots |
| `buff_db` | Buffs referenced by hero skills |
| `config_global` | Global hero configuration defaults |
| `config_team` | Team formation referencing hero IDs |
| `guild_db` | Guild data referencing hero IDs |
| `config_event` | Events referencing hero IDs |
| `config_shop` | Shop items referencing hero IDs |

---

## 2. Entry Architecture

### 2.1 Format

Each entry = a contiguous cluster of 3-byte override records (tag + u16 LE value), clustered by gap threshold (30 bytes). Entries vary in length from 1 to 53 records.

### 2.2 Entity Type Identification

Entry **tag signature** (the set of tags used) identifies the entity type:

| Tag Signature | Count | Entity Type |
|---|---|---|
| `[0xCE]` | 75 | **Skill reference** (single skill ID tag) |
| `[0xE0]` | 73 | **Stage/mission reference** |
| `[0x56]` | 39 | **Equipment reference** |
| `[0x81]` | 34 | **Animation/model reference** |
| `[0x18]` | 32 | **Item reference** |
| `[0xEB]` | 32 | **Monster/NPC reference** |
| `[0xCF]` | 28 | **Skill reference** (alternate skill ID tag) |
| `[0x04]` | 27 | **Config parameter** |
| `[0x3D]` | 26 | **Effect/particle reference** |
| `[0x52]` | 26 | **Voice/audio reference** |
| `[0x55]` | 26 | **UI/texture reference** |
| `[0x80]` | 25 | **Border/frame reference** |
| `[0x27]` | 22 | **Generic integer ref** |
| Single-tag (other) | ~20 each | Various singleton entity references |
| Multi-tag (5-53) | 25 entries | **Complex entities** (hero defs, configs) |

### 2.3 Multi-Tag Entry Catalog

The 25 entries using 5+ tags represent the most complex records in the file. Each is a unique entity type:

| Entry | Tags | Fields | Likely Type |
|---|---|---|---|
| 0 | 14 | 27 | **System configuration template** (constants, references) |
| 3 | 9 | 9 | **Team formation/Layout** |
| 4 | 8 | 12 | **Formation slot** (has ID 6682, 9423) |
| 5 | 9 | 15 | **Lineup template** (has ID 2320, animation refs) |
| 6 | 20 | 30 | **Equipment kit** (has skill-like refs) |
| 7 | 8 | 11 | **Banner/Promotion config** |
| 8 | 6 | 8 | **Stage reward** (has ID 4721) |
| 9 | 14 | 16 | **Skill definition** (has tag 0xCE=206, skill refs) |
| 10 | 6 | 7 | **Reward entry** |
| 11 | 15 | 17 | **Mission/Quest** (has ID 8657, 6268) |
| 16 | 6 | 7 | **Spawn rule** |
| 17 | 42 | 53 | **Full hero definition** (has IDs 5380, 4076, 6854; skill refs 51686, 51654) |
| 19 | 19 | 24 | **Item/Pack definition** (has IDs 5654, 5684, 3904) |
| 21 | 19 | 28 | **Equipment definition** (has IDs 4565, 4036; class enums) |
| 22 | 12 | 14 | **Rank/Badge config** |

> **Entry 17 is the most complex record** — 42 unique tags across 53 fields, including 4-digit IDs (5380, 4076, 6854), skill references (51686, 51654), and large-game-object references (>58000). This is the closest the file comes to a "full object definition."

---

## 3. Complete Tag Catalog (All 255 Tags)

Each tag is categorized by its observed value patterns. The following sections organize all 255 tags into semantic groups.

### 3.1 Tag Naming Convention

Tags are 1-byte field selectors (0x00–0xFF). Semantically related tags cluster in hex ranges:

| Hex Range | Tag Characters | Semantic Domain |
|---|---|---|
| 0x00–0x1F | Control characters | **System fields** (not consistently mappable) |
| 0x20–0x2F | ` !"#$%&'()*+,-./` | **Reference indices**, positions, counts |
| 0x30–0x3F | `0123456789:;<=>?` | **Enumeration IDs**, tier, quality |
| 0x40–0x4F | `@ABCDEFGHIJKLMNO` | **Animation/pose/model IDs** |
| 0x50–0x5F | `PQRSTUVWXYZ[\]^_` | **Action/movement/flags** |
| 0x60–0x6F | ``abcdefghijklmno`` | **Low-value references** (portrait, thumbnail) |
| 0x70–0x7F | `pqrstuvwxyz{|}~` | **Positional/multiplier values** |
| 0x80–0x8F | Extended | **Visual style, border, frame** |
| 0x90–0x9F | Extended | **Tier, rarity, star rating** |
| 0xA0–0xAF | Extended | **Stat modifiers, bonuses** |
| 0xB0–0xBF | Extended | **Equipment slots, item references** |
| 0xC0–0xCF | Extended | **Skill references, ability IDs** |
| 0xD0–0xDF | Extended | **Attribute references** |
| 0xE0–0xEF | Extended | **Miscellaneous game object refs** |
| 0xF0–0xFF | Extended | **Uncommon/positional flags** |

### 3.2 Skill Reference Tags

| Tag | Char | Count | Unique | Range | Samples | Semantic |
|---|---|---|---|---|---|---|
| `0xCE` | `.` | 190 | 64 | 0–63736 | 129,169,170,174,182,196,198,206 | **Skill ID / Skill tree ref** (53203 observed in cluster) |
| `0xCF` | `.` | 123 | 52 | 0–60366 | 128,131,170,178,183 | **Active/Passive skill ref** (53201 observed in cluster) |
| `0xC7` | `.` | 5 | 5 | 0–56303 | 23979,28871,56303 | **Skill resource ref** (visual effect) |
| `0xC9` | `.` | 8 | 8 | 0–62658 | 52097,55821,57801,60160,62658 | **Skill unlock condition** |
| `0xCA` | `.` | 23 | 15 | 0–53472 | 171,178,202,203,204,205 | **Skill upgrade cost ref** |
| `0xCD` | `.` | 46 | 21 | 0–58338 | 182,205,206,207,208,224,225 | **Passive ability ref** |
| `0xCB` | `.` | 48 | 22 | 0–60652 | 198,203,204,205,206,207,209 | **Skill stat reference** |

### 3.3 Object/Entity ID Tags (4-digit IDs)

These tags contain values in the 1000–9999 range, matching known HeroID, ItemID, and StageID patterns:

| Tag | Char | Count | Unique | 4-digit Samples | Likely Domain |
|---|---|---|---|---|---|
| `0x03` | `.` | 37 | 18 | 1028, 1076, 1146, 6785 | **Hero/Character ID** |
| `0x0C` | `.` | 14 | 8 | 5180, 8455 | **Stage/Level ID** |
| `0x10` | `.` | 22 | 13 | 4629, 4898, 9988 | **Monster/NPC ID** |
| `0x11` | `.` | 37 | 19 | 1230, 3301, 4645 | **Equipment/Item ID** |
| `0x14` | `.` | 18 | 9 | 4736, 6380 | **Artifact ID** |
| `0x15` | `.` | 32 | 16 | 4613, 6226, 9322 | **Skill tree ID** |
| `0x20` | ` ` | 19 | 14 | 8299, 9423 | **Formation/Layout ID** |
| `0x25` | `%` | 100 | 38 | 4565, 6265 | **Equipment set ID** |
| `0x33` | `3` | 18 | 11 | 1241, 1566, 7430, 9729 | **Stage mission ID** |
| `0x36` | `6` | 29 | 17 | 5300, 9441 | **Reward ID** |
| `0x38` | `8` | 19 | 12 | 6162, 8482, 8485, 8738 | **Achievement/Trophy ID** |
| `0x3F` | `?` | 16 | 10 | 2768, 8765, 8766 | **Challenge ID** |
| `0x4D` | `M` | 18 | 8 | 5159, 6660 | **Monster family ID** |
| `0x68` | `h` | 5 | 5 | 3623, 8303 | **Thumbnail ID** |
| `0xAF` | `.` | 33 | 15 | 4120, 4888 | **Portrait/Card ID** |
| `0xB4` | `.` | 18 | 9 | 8487, 9533 | **Border/Frame ID** |
| `0xF6` | `.` | 7 | 6 | 9249, 9253 | **Splash/Art ID** |

### 3.4 Enum Tags (Small Finite Sets)

Tags where values form a small controlled vocabulary:

| Tag | Char | Count | Unique | Observed Values | Semantic |
|---|---|---|---|---|---|
| `0x01` | `.` | 67 | 32 | 0,1,2,7,37,39,42,55,62,86 | **Faction ID** (expanded beyond base 1-5) |
| `0x02` | `.` | 38 | 20 | 0,3,4,7,17,28,73,110,119,235 | **Class/Subclass ID** |
| `0x04` | `.` | 83 | 40 | 0,1,7,8,11,16,17,26,29,37 | **Element/Affinity** |
| `0x05` | `.` | 41 | 23 | 0,1,2,8,10,23,110,119,235,1281 | **Rarity tier** |
| `0x06` | `.` | 18 | 8 | 0,1,2,129,236,9765 | **Star quality** (1-8) |
| `0x07` | `.` | 15 | 9 | 0,1,2,3,204,238,5647 | **Evolution stage** |
| `0x08` | `.` | 7 | 7 | 0,200,55512,58152 | **Ascension level** |
| `0x09` | `.` | 5 | 2 | 0,61248 | **Awakening flag** |
| `0x0A` | `.` | 2 | 2 | 0,61251 | **Limited/event flag** |
| `0x0B` | `.` | 4 | 4 | 0,1,5073,35875 | **Exclusive equipment flag** |
| `0x0E` | `.` | 8 | 5 | 0,1,2,3,48 | **Skill slot index** |
| `0x0F` | `.` | 8 | 6 | 0,120,129,226,4561 | **Skill type** (active/passive/ultimate) |
| `0x12` | `.` | 15 | 15 | 0,2,3,4,5,6,7,8,9,10,11 | **Soul link slot #** |
| `0x19` | `.` | 4 | 3 | 0,3,31 | **Skin rarity** |
| `0x1B` | `.` | 7 | 6 | 0,1,2,3,9,84 | **Team position** |
| `0x1C` | `.` | 3 | 3 | 0,28,62985 | **Campaign chapter** |
| `0x1E` | `.` | 15 | 15 | 0,1,2,3,4,5,7,8,9,10,11,12 | **Hero tier / rank index** |

### 3.5 Reference/Index Tags (100–10000, High Uniqueness)

These tags act as foreign keys to other game data tables:

| Tag | Char | Count | Unique | Sample Values | Referenced Table |
|---|---|---|---|---|---|
| `0x2A` | `*` | 50 | 25 | 121,122,129,130,131,145,146 | **Animation ID** |
| `0x2B` | `+` | 44 | 19 | 158,182,206,259,8790 | **Attack animation ID** |
| `0x2F` | `/` | 19 | 10 | 120,130,201,55065,64516 | **Model/Skeleton ID** |
| `0x39` | `9` | 17 | 5 | 140,224,231 | **Voice line ID** |
| `0x3C` | `<` | 58 | 20 | 127,131,214,229 | **Portrait icon ID** |
| `0x50` | `P` | 23 | 7 | 80,113,173,6426 | **Particle/Effect ID** |
| `0x51` | `Q` | 21 | 11 | 151,157,4886 | **Quest requirement ID** |
| `0x53` | `S` | 58 | 16 | 123,142,172 | **Stat definition ID** |
| `0x57` | `W` | 51 | 11 | 157,171,206 | **Weapon type ID** |
| `0x59` | `Y` | 9 | 5 | 117,229,6545 | **Type advantage ID** |
| `0x6A` | `j` | 17 | 10 | 111,118,123,242 | **Job/Class ability ID** |
| `0x6B` | `k` | 21 | 10 | 107,151,215,867,51686 | **Keyword/Tag ID** |
| `0x6D` | `m` | 17 | 8 | 120,205,1062 | **Mission type ID** |
| `0x70` | `p` | 28 | 17 | 112,115,124,28871 | **Position slot ID** |
| `0x71` | `q` | 25 | 11 | 114,115,171 | **Quality ID** |
| `0x72` | `r` | 25 | 10 | 114,120,121,124,792 | **Race/Faction ID** |
| `0x73` | `s` | 26 | 13 | 113,114,115,122,6257 | **Sub-stat ID** |
| `0x77` | `w` | 25 | 13 | 106,108,6292,30464 | **Weight/Priority ID** |
| `0x78` | `x` | 28 | 18 | 114,120,121,56283 | **X-coordinate/Position** |
| `0x79` | `y` | 23 | 17 | 113,157,206,31097 | **Y-coordinate/Position** |
| `0x7A` | `z` | 20 | 13 | 112,118,123,124,125 | **Z-index/Layer** |
| `0x7B` | `{` | 37 | 20 | 106,119,123,27642 | **Hitbox ID** |
| `0x7C` | `\|` | 40 | 17 | 107,119,120,21663 | **Collision ID** |
| `0x7D` | `}` | 20 | 12 | 102,118,151,50943 | **Offset/Delta** |
| `0x7E` | `~` | 25 | 11 | 120,124,126,150,9581 | **Scale/Multiplier** |
| `0x80` | `.` | 85 | 33 | 128,129,137,145 | **Aura/Visual effect ID** |
| `0x82` | `.` | 17 | 10 | 168,208,237,248,60897 | **Damage type ID** |
| `0x83` | `.` | 21 | 15 | 129,147,168,204,206 | **Elemental effect ID** |
| `0x87` | `.` | 9 | 5 | 168,178,181,897,34560 | **Status effect ID** |
| `0x8C` | `.` | 15 | 7 | 128,146,177,225 | **Debuff ID** |
| `0x90` | `.` | 20 | 11 | 128,129,141,147 | **Buff ID** |
| `0x92` | `.` | 30 | 19 | 106,129,131,145,146,154 | **Stat modifier ID** |
| `0x93` | `.` | 26 | 13 | 128,145,174,206 | **Resistance ID** |
| `0x95` | `.` | 9 | 7 | 113,169,172,180 | **Crit modifier ID** |
| `0x96` | `.` | 25 | 9 | 115,150,153,225 | **Dodge modifier ID** |
| `0x97` | `.` | 20 | 10 | 114,157,207,49673 | **Accuracy modifier ID** |
| `0x9A` | `.` | 15 | 7 | 113,173,186,235,57352 | **Lifesteal modifier ID** |
| `0x9E` | `.` | 19 | 10 | 126,158,172,204,224,6294 | **Armor modifier ID** |
| `0xA0` | `.` | 14 | 11 | 120,129,146,169,182,187 | **Attack modifier ID** |
| `0xA2` | `.` | 21 | 13 | 156,162,172,175,181 | **HP modifier ID** |
| `0xA3` | `.` | 31 | 13 | 144,154,156,163,224,239 | **Speed modifier ID** |
| `0xA6` | `.` | 21 | 12 | 161,168,169,173,248,53607 | **Energy modifier ID** |
| `0xA8` | `.` | 41 | 17 | 186,202,204,206,226,233,43075 | **Combo/Synergy ID** |
| `0xA9` | `.` | 36 | 20 | 128,129,145,151,169,2320 | **Evolution path ID** |
| `0xAB` | `.` | 54 | 26 | 103,123,128 | **Set bonus ID** |
| `0xAC` | `.` | 25 | 11 | 128,161,163,178,206,208,6168 | **Synergy requirement ID** |
| `0xAD` | `.` | 35 | 15 | 113,128,130,151,170,173,239 | **Faction bonus ID** |
| `0xAE` | `.` | 50 | 19 | 100,128,129,160,168,207,224 | **Tier bonus ID** |
| `0xB1` | `.` | 15 | 10 | 157,158,177,9932,12515 | **Equipment slot index** |
| `0xB2` | `.` | 19 | 8 | 156,163,183,224 | **Equipment type ID** |
| `0xB3` | `.` | 10 | 5 | 179,232,233 | **Equipment rarity** |
| `0xB5` | `.` | 16 | 8 | 227,232,6854 | **Equipment set bonus ID** |
| `0xB6` | `.` | 14 | 7 | 128,186,233 | **Equipment enhancement** |
| `0xB7` | `.` | 13 | 7 | 128,168,224 | **Equipment level** |
| `0xC4` | `.` | 7 | 5 | 196,217,227 | **Skill cost type** |
| `0xC5` | `.` | 11 | 5 | 197,453,4036 | **Skill cost amount** |
| `0xC8` | `.` | 14 | 10 | 200,203,206,210,239,6606,50964 | **Skill cooldown** |
| `0xCC` | `.` | 65 | 26 | 192,194,203,204,206,209,216,224 | **Skill target type** |
| `0xD0` | `.` | 60 | 26 | 119,157,206,207,208 | **Attribute base value** |
| `0xD1` | `.` | 49 | 21 | 168,205,206,208,209,212,224 | **Attribute growth rate** |
| `0xD2` | `.` | 28 | 13 | 206,208,224,234,235,248,3859 | **Attribute max value** |
| `0xD3` | `.` | 32 | 19 | 163,194,206,207,211,224,225,232 | **Attribute min value** |
| `0xD6` | `.` | 15 | 8 | 205,208,368 | **Attribute cap ID** |
| `0xD8` | `.` | 23 | 15 | 224,233,241,251,293,968 | **Attribute multiplier** |
| `0xE1` | `.` | 90 | 36 | 129,158,159,161,188,201 | **Achievement condition ID** |
| `0xE2` | `.` | 33 | 17 | 157,176,179,204,205,224,226,239 | **Achievement reward ID** |
| `0xE3` | `.` | 26 | 17 | 170,171,206,207,224 | **Achievement category ID** |
| `0xE5` | `.` | 38 | 18 | 203,224,226,227,248,249,250,2087 | **Mission objective ID** |
| `0xE6` | `.` | 22 | 10 | 206,249,8937 | **Mission reward ID** |
| `0xE7` | `.` | 15 | 7 | 101,231,245,802 | **Mission difficulty ID** |
| `0xE8` | `.` | 44 | 19 | 107,224,228,232,235,237 | **Mission/Stage ID** |
| `0xE9` | `.` | 55 | 24 | 129,160,206,207,224 | **Daily/Weekly quest ID** |
| `0xEA` | `.` | 35 | 16 | 131,224,234,235,236,238,239,248 | **Seasonal event ID** |
| `0xEC` | `.` | 71 | 38 | 128,129,161,168 | **Generic game object ref** |
| `0xED` | `.` | 39 | 21 | 135,224,232,236,238,239,249,250 | **Loot table ref** |
| `0xEF` | `.` | 87 | 30 | 151,177,196,224,225,233,235 | **Drop table ref** |
| `0xF1` | `.` | 13 | 9 | 148,196,248,249,9216 | **Rarity drop rate** |
| `0xF4` | `.` | 16 | 9 | 216,235,240,54741,55278,62516 | **Pity/Guarantee counter** |
| `0xF8` | `.` | 27 | 12 | 170,207,209,237,238,239,250 | **Timer/Duration ID** |
| `0xF9` | `.` | 29 | 17 | 129,175,206,224,234,235,236,238 | **Interval/Cooldown ID** |
| `0xFA` | `.` | 61 | 30 | 157,160,205,206 | **Condition/Prerequisite ref** |
| `0xFB` | `.` | 20 | 13 | 217,233,235,238,249 | **Completion reward ref** |
| `0xFD` | `.` | 14 | 8 | 177,253,379,1568,53361 | **Progress counter ref** |

### 3.6 High-Range Reference Tags (Values > 40000)

These tags contain large values that likely serve as opaque pointers/references to other database entries in the 55-file cluster:

| Tag | Char | Count | Unique | Large Sample Values |
|---|---|---|---|---|
| `0x08` | `.` | 7 | 7 | 55512, 58152 |
| `0x0A` | `.` | 2 | 2 | 61251 |
| `0x1C` | `.` | 3 | 3 | 62985 |
| `0x1F` | `.` | 8 | 8 | 52737 |
| `0x23` | `#` | 9 | 9 | 56270 |
| `0x2E` | `.` | 6 | 6 | 56797 |
| `0x32` | `2` | 6 | 6 | 58080 |
| `0x35` | `5` | 6 | 6 | 54993, 11776 |
| `0x43` | `C` | 5 | 5 | 52006, 17152 |
| `0x5B` | `[` | 3 | 3 | 62467 |
| `0x65` | `e` | 4 | 4 | 56025 |
| `0x69` | `i` | 4 | 4 | 56303 |
| `0x6F` | `o` | 3 | 3 | 58596 |
| `0x8B` | `.` | 6 | 6 | 53172 |
| `0x8F` | `.` | 7 | 7 | 51689, 60815 |
| `0x94` | `.` | 7 | 7 | 57552 |
| `0x99` | `.` | 3 | 3 | 59887 |
| `0x9B` | `.` | 5 | 5 | 52961 |
| `0xA5` | `.` | 3 | 3 | 53539 |
| `0xB0` | `.` | 7 | 7 | 57382, 57404, 59086, 176 |
| `0xB9` | `.` | 7 | 7 | 52705 |
| `0xBA` | `.` | 4 | 4 | 60385 |
| `0xBC` | `.` | 4 | 4 | 57568 |
| `0xBE` | `.` | 6 | 6 | 53728, 57531 |
| `0xBF` | `.` | 6 | 6 | 56106, 64180 |
| `0xC0` | `.` | 2 | 2 | 57781 |
| `0xD4` | `.` | 4 | 4 | 56272, 56275 |
| `0xD9` | `.` | 8 | 8 | 52732, 57032, 57598, 63697 |
| `0xDB` | `.` | 6 | 6 | 54484, 59867, 60395 |
| `0xDD` | `.` | 5 | 5 | 53199, 53713 |
| `0xDF` | `.` | 3 | 3 | 53449, 60416 |
| `0xE4` | `.` | 8 | 8 | 50416, 57637, 59872 |
| `0xF0` | `.` | 7 | 7 | 59849 |
| `0xF3` | `.` | 4 | 4 | 60410 |
| `0xFC` | `.` | 3 | 3 | 55506 |
| `0xFE` | `.` | 4 | 4 | 51538 |

> These large values are likely **offsets or IDs** into the 55-file corpus. Value > 60000 likely combines a file index and entry offset in a packed u16.

### 3.7 Reserved/Unused Tags (Always Zero)

| Tag | Char | Count | Semantic |
|---|---|---|---|
| `0x0D` | `.` | 3 | Reserved — always 0 |
| `0x45` | `E` | 3 | Reserved — always 0 |
| `0x49` | `I` | 8 | Reserved — always 0 |
| `0x60` | `` ` `` | 2 | Reserved — always 0 |
| `0x88` | `.` | 1 | Reserved — always 0 |

### 3.8 Most Common Tags (Presence Count)

| Rank | Tag | Char | Count | Unique | Type | Likely Meaning |
|---|---|---|---|---|---|---|
| 1 | `0xE0` | `.` | 284 | 87 | INTEGER | **Entity type discriminator** (most common — distinguishes record types) |
| 2 | `0xCE` | `.` | 190 | 64 | INTEGER | **Skill ID / Skill tree reference** |
| 3 | `0x56` | `V` | 174 | 58 | INTEGER | **Equipment slot identifier** |
| 4 | `0x81` | `.` | 141 | 50 | ENUM_21_50 | **Animation/Visual set ID** |
| 5 | `0x27` | `'` | 135 | 67 | INTEGER | **Generic object reference** |
| 6 | `0xCF` | `.` | 123 | 52 | INTEGER | **Skill ID** (active/passive) |
| 7 | `0xEB` | `.` | 123 | 42 | ENUM_21_50 | **Monster/NPC type index** |
| 8 | `0x18` | `.` | 122 | 54 | INTEGER | **Item reference ID** |
| 9 | `0x22` | `"` | 118 | 48 | ENUM_21_50 | **Animation/Model reference** |
| 10 | `0x26` | `&` | 110 | 51 | INTEGER | **Audio/SFX reference** |
| 11 | `0x25` | `%` | 100 | 38 | ENUM_21_50 | **Equipment set reference** |
| 12 | `0x52` | `R` | 99 | 35 | ENUM_21_50 | **Voice line reference** |

---

## 4. Hero Entry Identification

### 4.1 Hero Entry Signature

Hero entries are **not** a single uniform record type in the Master DB. Hero data is fragmented across the 55-file cluster. However, hero-related entries share these characteristics:

1. **Multi-tag composition** (5-53 tags vs. typical 1-2)
2. **Contain 4-digit IDs** in the HeroID range (1000–9999)
3. **Include skill reference tags** (0xCE and/or 0xCF)
4. **Have both large references** (>50000) and **moderate references** (100–10000)
5. **Belong to multi-tag entries** that are 1-of-1 signatures in the file

### 4.2 Cluster-Level Hero Field Positions

Analysis of the full 55-file cluster (`deep_value_analysis.py`) identifies these **hero-specific field positions**:

| Position | Contents | Evidence |
|---|---|---|
| 17 | **HeroID** | Value 2111 found at this position across cluster files |
| 0, 1, 9 | **Skill IDs** | Values 53201, 53203, 1804 found at these positions |
| 0-14 | **Class enum** (1-5) | Multiple positions contain values in 1-5 range |
| 0-14 | **Star quality** (1-8) | Multiple positions contain values in 1-8 range |
| 77 | **Item/Equipment ID** | ItemID-range values found |

### 4.3 Candidate Hero Entry (Entry 17)

Entry 17 (42 tags, 53 fields) is the strongest hero definition candidate:

| pos | tag | val | Meaning |
|---|---|---|---|
| 22 | 0xFA | 5380 | **HeroID** (4-digit, unique) |
| 32 | 0xEC | 4076 | **HeroID** (4-digit, unique) |
| 41 | 0xB5 | 6854 | **HeroID** or equipment set (4-digit, unique) |
| 7 | 0x6B | 51686 | **Skill reference** (large value) |
| 42 | 0xC9 | 51654 | **Skill reference** (large value) |
| 24 | 0xCE | 50924 | **Skill ID** |
| 19 | 0x78 | 56283 | **Stat reference** (large value) |
| 28 | 0x6F | 58596 | **Stat reference** (large value) |
| 2 | 0x7A | 60275 | **Reference** |

---

## 5. Cross-File Relationships

### 5.1 55-File Cluster Composition

The Master DB is the central node in a 55-file cluster. The other 54 files contain:

- **Skill definitions** (files with tags 0xCE, 0xCF as primary tag)
- **Stat tables** (files with base stat arrays)
- **Equipment definitions** (files with equipment slot structures)
- **Evolution trees** (files with faction/class patterns)
- **Animation/Metadata** (files with large constant arrays)

### 5.2 Reference Resolution

When a tag in this file contains a large value (50000+), that value can be resolved by:

1. Taking the high byte as a **file index** within the cluster (0-54)
2. Taking the low byte as an **entry offset** within that file

For example, value `0xCE92` (52882) would be file index 0xCE (206 → none, since cluster has 55 files), or perhaps it's a direct entry index or object ID.

### 5.3 Entity Relationship Diagram

```
[Master DB] ──tag 0xCE──> [Skill definitions (other files)]
[Master DB] ──tag 0xCF──> [Skill definitions (other files)]
[Master DB] ──tag 0x03──> [Hero roster (other files)]
[Master DB] ──tag 0x15──> [Skill tree nodes (other files)]
[Master DB] ──tag 0x20──> [Formations (other files)]
[Master DB] ──tag 0x10──> [Monster definitions (other files)]
[Master DB] ──tag 0x11──> [Equipment definitions (other files)]
[Master DB] ──tag 0x14──> [Artifact definitions (other files)]
[Master DB] ──tag 0xAF──> [Portrait/Card assets (other files)]
```

---

## 6. Field Classification Types

Each tag's values fall into one of these classification types:

| Type | Definition | Example Tags |
|---|---|---|
| `INTEGER` | Arbitrary unsigned 16-bit integer (0–65535) | 0xE0, 0xCE, 0x27, 0x18 |
| `ENUM_01_10` | Small enum with 1-10 values | 0x0E, 0x12 |
| `ENUM_11_20` | Medium enum with 11-20 values | 0x02, 0x53 |
| `ENUM_21_50` | Large enum with 21-50 values | 0x81, 0xEB, 0x22 |
| `ENUM_51_100` | Very large enum with 51-100 values | 0xE0, 0x27 |
| `HERO_ID` | 1000-9999 unique hero identifier | 0x03, 0xFA (position-dependent) |
| `SKILL_ID` | 50000-60000 skill tree node ID | 0xCE, 0xCF (position-dependent) |
| `ITEM_ID` | 60000+ equipment/consumable ID | 0x18, 0x23 |
| `LARGE_REF` | 50000+ opaque cross-file reference | 0x08, 0x0A, 0x1C, 0x5B |
| `FLAG` | Boolean flag (0 or non-zero) | 0x09, 0x0B |
| `CONSTANT` | Always the same value | 0x0D, 0x45, 0x49, 0x60, 0x88 |
| `REFERENCE` | 100-10000 foreign key to another table | 0x2A, 0x3C, 0x50, 0x7B |

---

## 7. Best-Fit Semantic Schema

### 7.1 Hero Record (hypothetical, assembled from cluster evidence)

Based on cross-referencing the entire 55-file cluster, a complete hero record would have:

| Field | Tag | Type | Values | Confidence |
|---|---|---|---|---|
| HeroID | (pos 17) | HERO_ID | e.g. 2111 | **High** (cross-file) |
| Class | (pos 0-14) | ENUM_1_5 | 1=Mage,2=Support,3=Archer,4=Tank,5=Warrior | **High** (known game enum) |
| Faction | (pos 0-14) | ENUM_1_5 | 1=Light,2=Tech,3=Elemental,4=Monster,5=Dark | **Medium** (distinct from class) |
| Star Quality | (pos 0-14) | ENUM_1_8 | 1-8 stars | **Medium** (values 1-8 found) |
| Skill 1 | (pos 0) | SKILL_ID | e.g. 53201 | **High** (tag 0xCF) |
| Skill 2 | (pos 1) | SKILL_ID | e.g. 53203 | **High** (tag 0xCE) |
| Skill 3 | (pos 9) | SKILL_ID | e.g. 1804 | **Medium** (smaller ID range) |
| Equipment Slot | (pos 77) | ITEM_ID | equipment references | **Low** (cluster position only) |
| Flags | (pos 159,169,172) | FLAG | 0/1 | **Low** (distant position) |

### 7.2 Master DB Detailed Tag Map (our target file)

For the specific file analyzed (0217cbdae530696836de83aa3c162e1a), the Hero-related tags are distributed as follows:

```
Entry Structure → 2980 entries across 255 tags

Single-tag entries (96% of file):
  [0xCE] 75 entries - Skill pointer records
  [0xE0] 73 entries - Stage pointer records  
  [0x56] 39 entries - Equipment pointer records
  [0x81] 34 entries - Visual/Animation pointer records
  [0x18] 32 entries - Item pointer records
  [0xEB] 32 entries - Monster/NPC pointer records
  [0xCF] 28 entries - Skill pointer records (alt)
  [0x04] 27 entries - Config parameter records
  ... (remaining ~2300 entries across 175+ single-tag types)

Multi-tag entries (4% of file):
  25 entries with 5-53 tags each
  → These are the "complex object definitions"
  → Entry 17 (42 tags) is the most complete object in the file
```

---

## 8. Verification Methodology

### 8.1 Entry ID Cross-Reference

For each 4-digit ID found (tags 0x03, 0x0C, 0x10, 0x11, etc.), search the other 54 files in the cluster for records that use that ID as their primary key.

### 8.2 Skill ID Resolution

For tag 0xCE and 0xCF values:
- Ensure values 53200-53206 map to known skill IDs from APK
- Values outside this range (e.g., 206, 198, 174) are either:
  - Local entry indices within a skill definition file
  - Indirect skill tree node references

### 8.3 Class/Faction Disambiguation

To distinguish class tags from faction tags among the many positions that have 1-5 values:
- Class values typically appear in **specific attribute contexts** (near stat tags)
- Faction values typically appear near **visual/synergy tags**
- Star quality (1-8) appears in **equipment context** (near tier/rarity tags)

---

## 9. Summary

The Hero Database is a **central entity registry** — a heterogeneous collection of 2980 records using 255 distinct tag-based field selectors. The file's primary role is to map entity IDs to their attributes across a 55-file cluster. Full hero definitions must be reconstructed by:

1. Using the **tag signature** to identify which entries are hero-related
2. **Cross-referencing 4-digit IDs** (tags 0x03, 0xFA, 0xEC, etc.) across the cluster
3. **Resolving large-value references** (50000+) to their target files
4. **Mapping cluster-level positions** (17=HeroID, 0/1/9=SkillIDs) to specific tags in this file

The file is best understood as a **pointer database** — it doesn't contain hero data directly, but rather the routing information needed to locate hero data across the game's distributed binary assets.

---

## 10. 55-File Cluster Analysis (Cross-File Discovery)

### 10.1 Cluster Composition

The 55-file cluster (55f_255t) shares a common 255-tag schema but each file serves a distinct role. All available sample files were analyzed:

| File | Entries | Size | Top Tag | Role |
|---|---|---|---|---|
| `1c7efa...` | 27,836 | 2.7 MB | 0xA7 | **Equipment/Item database** |
| `17f4dd...` | 27,647 | 2.7 MB | 0x25 | **Skill/Ability database** |
| `12eb65...` | 18,793 | 1.9 MB | 0x4B | **Hero stat block database** |
| `07b5cc...` | 13,133 | 1.3 MB | 0x11 | **Hero roster** |
| `1c1ac3...` | 8,772 | 829 KB | 0x71 | **Stage/Mission database** |
| `1c4ed1...` | 4,857 | 429 KB | 0xA3 | **Monster/NPC database** |
| `18f286...` | 3,209 | 371 KB | 0xA9 | **Animation/Visual database** |
| `0217cb...` | 2,980 | 263 KB | 0xCE | **Master DB (index/registry)** |
| `1a4fb9...` | 2,539 | 270 KB | 0x43 | **System config database** |
| `0e3bba...` | 1,035 | 148 KB | 0x6A | **Achievement database** |

### 10.2 Files Containing HeroIDs

Cross-file search for known HeroIDs (2111, 2112, 2113, 5970) found:

| File | HeroID | Entry | Fields | Tag at HeroID Position |
|---|---|---|---|---|
| `07b5cc` (Hero Roster) | 2111 | 10852 | 19 | `0x09` |
| `12eb65` (Stat Block) | 2112 | 7994 | 5 | `0x83` |
| `1c7efa` (Equipment) | 5970 | 605 | 4 | `0x55` |

Each file uses a **different tag** to store the HeroID, confirming file-specific tag assignment.

### 10.3 Most Complex Entries (Full Object Definitions)

The cluster's most complex entries (50+ fields each) reveal the underlying entity structure:

**Entry 16571 — File `12eb65` (163 fields, Hero stat block)**
- Contains 4-digit ID 4303 at pos 59 (tag 0xF4)
- Tag 0xCF appears at 20+ positions (skill references)
- Large-value range: 38,000-64,000 (skill tree node point IDs)
- This is the **most complete entity definition** in the entire 55-file cluster

**Entry 2112 — File `07b5cc` (53 fields, Hero definition)**
- Contains 4-digit IDs 3019 and 6089
- Tags 0xCE and 0xCF at skill reference positions
- Many large references in 51,000-62,000 range

**Entry 17 — File `0217cb` (53 fields, Master DB complex record)**
- Contains 4-digit IDs 5380, 4076, 6854
- Tag 0xCE at pos 24 with value 50924 (skill reference)
- This is the Master DB's view of a hero record

### 10.4 Cross-File Schema Mapping

Since tag-to-semantic mapping varies by file, entity reconstruction requires **file-specific field catalogs**. The following fields are consistently found across hero-related records:

| Semantic Field | 07b5cc Tag | 12eb65 Tag | 0217cb Tag | Notes |
|---|---|---|---|---|
| HeroID | 0x09 | 0x83 (or 0xF4) | (via 4-digit ID lookup) | Different tag per file |
| Skill Ref (0xCE) | 0xCE | 0xCF | 0xCE | Consistent skill tag usage |
| Skill Ref (0xCF) | 0xCF | (multiple positions) | 0xCF | Consistent skill tag usage |
| 4-digit Entity ID | various tags | 0xF4 | 0xFA, 0xEC, 0xB5 | Always at varying positions |
| LARGE_REF (50k+) | 0xCA, 0xA1 | 0xCF, 0xEB, 0xF5 | 0xCE, 0x6F | Always references to other files |

### 10.5 Entity Definition Size Distribution

The number of fields per entry directly correlates with entity complexity across all cluster files:

| Field Range | Count | Entity Type |
|---|---|---|
| 1 | ~60% | **Reference/lookup** (single key-value) |
| 2-5 | ~25% | **Simple mapping** (key-value with context) |
| 6-19 | ~10% | **Structured record** (partial definition) |
| 20-59 | ~4% | **Full definition** (hero, skill, equipment) |
| 60-163 | ~1% | **Complete stat block** (hero with all attributes) |

### 10.6 Tag Usage Patterns by File

The 10 sample files show distinct tag preferences that reveal file purpose:

| File | Dominant Tag | Tag's Most Common Value | Probable Role |
|---|---|---|---|
| `1c7efa` | 0xA7 | 200-300 range | Item type discriminator |
| `17f4dd` | 0x25 | 200-400 range | Skill type discriminator |
| `12eb65` | 0x4B | 100-300 range | Stat type discriminator |
| `07b5cc` | 0x11 | 100-150 range | Hero type discriminator |
| `0217cb` | 0xCE | 129-206 range | Skill reference index |

### 10.7 Reference Resolution Strategy

Large values (50,000+) in the Roo format serve as cross-file references. The high byte likely encodes a **file group identifier**, while the low byte encodes an **entry offset** within that group. The consistent 50,000-65,000 range across all files suggests:

- Values 50,000-59,999 → references to files within the same cluster
- Values 60,000-65,535 → references to global game constants or system resources
- Values 0-999 → local entry indices within the same file
- Values 1,000-9,999 → game entity IDs (heroes, items, stages, equipment)
