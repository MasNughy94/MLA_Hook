# MLA Reverse Engineering — Session Utama
## Project: Mobile Legends Adventure .mt File Parsing
## Last Updated: 2026-07-01 (directory restructure)

---

## RINGKASAN EKSEKUTIF

Pipeline end-to-end (.mt → lua/data) 100% dipahami dan sudah diimplementasi.
Tool sudah bekerja: decrypt → decompress → parse → SQLite DB (221,602 entities).
Yang belum: menemukan AES key device APK secara runtime (Frida hook).

**Emulator pipeline: BERHASIL** — AES key ketemu, semua step working.
**Device APK pipeline: PARTIAL** — format sama, key berbeda/tidak diketahui.

---

## 1. PIPELINE VERIFIED — EMULATOR .MT

```
.mt file (emulator)
  ├── Header: "Antm"(4B) + version(1B) + hdr(11B)
  ├── Step 1: Strip 16-byte Antm header
  ├── Step 2: AES-128-ECB decrypt
  │            Key: f5a193d50ade553e9835595f5cd75ddd
  ├── Step 3: lmF@ custom range decoder
  │            (PROJECT/scripts/lmf_decoder.py — 100% VERIFIED)
  ├── Step 4: Roo binary format
  │            (69-byte header + 3-byte records)
  └── Step 5: Parsed game data → SQLite DB
               (PROJECT/cache/mla_database.db)
```

### Format .mt (emulator)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic: "Antm" (0x6d746e41 LE) |
| 4 | 1 | Version: 0x01=AES, 0x02=XOR |
| 5 | 11 | Header (zeros) |
| 16+ | N | Encrypted payload |

### AES Key Emulator

**Key: `f5a193d50ade553e9835595f5cd75ddd`**
- VERIFIED: berhasil decrypt 14 sample files di DEC-ASSET folder
- 32553/32553 bytes match ground truth

---

## 2. FORMAT lmF@ (Lmf_decoder.py — VERIFIED 100%)

### Header (14 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic: "lmF@" (0x40466d6c LE) |
| 4 | 1 | flags[0] (exponent for probability table) |
| 5 | 3 | flags[1..3] |
| 7 | 1 | flags[3] ^= 0x05 |
| 8 | 1 | flags[4] |
| 10 | 4 | uncompressed_size ^ 0x03EA (LE uint32) |

### Decompression Algorithm

Custom range coder + LZ77:
- Probability table initialized ke 0x400
- Window size dari flags (minimum 0x1000)
- Adaptive probability updates (shift = 5)
- Binary tree decoder untuk literals, lengths, distances
- First 16 bytes of compressed payload di-XOR dengan 0xEC sebelum decoding
- UMULL emulation untuk prob_shift calculation

**File: `PROJECT/scripts/lmf_decoder.py`**

---

## 3. FORMAT ROO BINARY (roo_parser_final.py — VERIFIED)

### Header (69 bytes, identik di semua 7243 file)

| Offset | Size | Value | Meaning |
|--------|------|-------|---------|
| 0 | 4 | 0x1B4C6D00 | Modified Lua magic |
| 4 | 2 | 0x0000 | Unknown |
| 6 | 4 | "Roo\0" | Format identifier |
| 10 | 16 | zeros | Padding |
| 26 | 2 | 0xD1D1 | Static marker |
| 28 | 34 | zeros | Padding (D1 at offset 60) |
| 62 | 6 | zeros | Padding |
| 68 | 1 | subtype | 0xA9=std, 0xAA=variant, 0xAB=other |

### Body (offset 69+)

Sequence of 3-byte records: `[tag, v1, v2]`

| Pattern | Meaning |
|---------|---------|
| 00 00 00 | Empty (82% of body) |
| 00 V1 V2 (V1≠0 or V2≠0) | Template default |
| TT V1 V2 (TT≠0) | Instance override |

Combined value: `u16 = v1 | (v2 << 8)`, little-endian
Position-encoded: `body_offset / 3 = implicit field ID`

### Entry Clustering

1. Collect all override records (tag≠0)
2. Sort by body position
3. Group consecutive records where gap ≤ 30 bytes
4. Each group = one game entity entry

**File: `PROJECT/scripts/roo_parser_final.py`**

---

## 4. ENTITY DATA — DATABASE SEMANTIC ANALYSIS

### Database: `PROJECT/cache/mla_database.db` (SQLite)

| Entity Type | Entities | Fields | Max Fields |
|------------|----------|--------|-----------|
| EquipDB | 55,672 | 180,202 | 252 |
| SkillDB | 55,294 | 140,088 | 66 |
| HeroStatDB | 37,586 | 109,234 | 163 |
| HeroRosterDB | 26,266 | 98,944 | 168 |
| StageDB | 17,544 | 51,992 | 97 |
| MonsterDB | 9,714 | 29,786 | 70 |
| AnimDB | 6,418 | 21,430 | 89 |
| MasterDB | 5,960 | 15,114 | 53 |
| ConfigDB | 5,078 | 25,914 | 88 |
| AchieveDB | 2,070 | 18,024 | 194 |
| **TOTAL** | **221,602** | **690,728** | — |

Relationships: 364,882 total

Top cross-file references:
- EquipDB → SkillDB: 39,826
- EquipDB → HeroStatDB: 36,280
- EquipDB → HeroRosterDB: 28,784
- HeroStatDB → HeroRosterDB: 21,414
- SkillDB → HeroRosterDB: 18,234

### High-Confidence Field Mappings (confidence ≥ 0.7)

| Field | Entity | Confidence |
|-------|--------|-----------|
| hero_id | HeroRosterDB | 0.90 |
| skill_id | SkillDB | 0.90 |
| equip_id | EquipDB | 0.85 |
| stage_id | StageDB | 0.85 |
| hero_stat_id | HeroStatDB | 0.85 |
| hero_class | HeroRosterDB | 0.80 |
| master_id | MasterDB | 0.80 |
| monster_id | MonsterDB | 0.80 |
| item_type | EquipDB | 0.75 |
| hero_stat_ref | HeroStatDB | 0.75 |
| base_hp/atk/def | HeroStatDB | 0.70 |
| achievement_id | AchieveDB | 0.70 |
| anim_id | AnimDB | 0.70 |
| config_key | ConfigDB | 0.70 |
| monster_type | MonsterDB | 0.70 |
| faction | HeroRosterDB | 0.70 |
| rarity | HeroRosterDB | 0.70 |

---

## 5. MOUNTON PROTECT PACKER (libagame.so)

### Technique: RELA-Injection Packing

| Aspect | Normal ELF | Moonton-Packed (this binary) |
|--------|-----------|-------------------------------|
| .init_array on disk | Real pointers | ALL ZEROS |
| .init_array at runtime | Read from segment | Populated by 53 RELA entries |
| DT_INIT | Real init function | Decoy (points to .dynstr string) |
| DT_BIND_NOW | Optional | SET |

### RELA Processing (61,660 entries total)

```
For each R_AARCH64_RELATIVE (type 1027):
  *(base + r_offset) = base + r_addend

53 entries target .init_array range (0x115d478-0x115dad8)
```

### Init Function Addresses (RELA addends)

| Entry | Offset | Entry | Offset |
|-------|--------|-------|--------|
| [0] | 0x3ff5a0 | [27] | 0x4000d0 |
| [1] | 0x3ff5cc | ... | ... |
| [2] | 0x3ff6f4 | [50] | 0x400d24 |
| ... | ... | [51] | 0x400dd8 |
| [26] | 0x4000ac | [52] | 0x400e44 |

### Why setKey Has Zero Static Callers

- Caller stored in .init_array, called by linker via indirect pointer
- Linker uses BLR (indirect), not BL (direct)
- The BL to `CCCrypto::setKey` inside the caller is a normal direct call
- But we can't identify WHICH of 53 functions it is statically
- **Solution: Frida runtime hook on `CCCrypto::getKey`**

---

## 6. FUNGSI-FUNGSI KUNCI (VERIFIED — Symbol Table libagame.so)

### CCCrypto Class

| Address | Symbol | Description |
|---------|--------|-------------|
| 0xcec678 | `CCCrypto::getKey` | Return AES key (0 static callers) |
| 0xcec6a4 | `CCCrypto::getKey2` | Return alternate key |
| 0xceca74 | `CCCrypto::setKey` | Set m_sKey from hex string (0 callers) |
| 0xcec5c0 | `CCCrypto::aes_decrypt` | AES decrypt (v1 path) |
| 0xceccec | `CCCrypto::xor_decrypt` | XOR decrypt (v2 path) |
| 0xcecd24 | `CCCrypto::uncompressData` | lmF@ decompressor (704 bytes) |
| 0xcecc44 | `CCCrypto::xor_encrypt` | XOR encrypt |
| 0xced7a8 | `CCCrypto::aes_encrypt` | AES encrypt (string overload) |
| 0xcedfe4 | `CCCrypto::aes_decrypt` | AES decrypt (string overload) |

### AES Class (Custom, not OpenSSL)

| Address | Symbol | Description |
|---------|--------|-------------|
| 0xcf3998 | `AES::MakeKey` | Key schedule |
| 0xcf335c | `AES::EncryptBlock` | Single block encrypt |
| 0xcf367c | `AES::DecryptBlock` | Single block decrypt |
| 0xcf468c | `AES::Encrypt` | Multi-block encrypt |
| 0xcf47f8 | `AES::Decrypt` | Multi-block decrypt |

### TEA / oi_symmetry

| Address | Symbol | Description |
|---------|--------|-------------|
| 0x43aa80 | `TeaDecryptECB` | Standard TEA, 16 cycles, REV32 on I/O |
| 0x43a9a4 | `TeaEncryptECB` | TEA encrypt |
| 0x43ae3c | `oi_symmetry_decrypt2` | CFB mode + TeaDecryptECB |
| 0x43ab80 | `oi_symmetry_encrypt2` | CFB encrypt |
| 0x43b33c | `getkey` | Hex string → 16-byte key |

### XXTEA

| Address | Symbol | Description |
|---------|--------|-------------|
| 0x5b2664 | `xxtea_encrypt` | XXTEA encrypt |
| 0x5b2714 | `xxtea_decrypt` | XXTEA decrypt |
| 0x47112c | `LuaStack::setXXTEAKeyAndSign` | Set XXTEA key & sign |
| 0x470f8c | `LuaStack::cleanupXXTEAKeyAndSign` | Cleanup XXTEA |

### File I/O

| Address | Symbol | Description |
|---------|--------|-------------|
| 0x474028 | `cocos2dx_lua_loader` | Lua require() handler |
| 0x7d27e8 | `FileUtils::getInstance` | Singleton getter |
| 0x7d2f38 | `FileUtilsAndroid::getDataFromFile` | Get Data from file |
| 0x7d2888 | `FileUtilsAndroid::getData` | Read file + decryptData |
| 0xc82ab0 | `Data::decryptData` | Main decrypt entry (812 bytes) |

### Compression

| Address | Symbol | Description |
|---------|--------|-------------|
| 0xca41c4 | `ZipUtils::inflateMemory` | zlib inflate |
| 0xca4638 | `ZipUtils::isGZipBuffer` | Check gzip magic |
| 0xca4318 | `ZipUtils::deflateMemoryWithHint` | zlib deflate |
| 0xca4398 | `ZipUtils::deflateMemory` | zlib deflate |

### Lua Engine

| Address | Symbol | Description |
|---------|--------|-------------|
| 0x47249c | `LuaStack::luaLoadBuffer` | Load Lua chunk (240 bytes) |
| 0x66b13c | `luaL_loadbuffer` | Lua API |
| 0x46ecb4 | `LuaEngine::getInstance` | Lua engine singleton |

### lmF@ Decompressor (from emulator binary)

| Address | Description |
|---------|-------------|
| 0xcf2110 | Block decompression driver (sub_CF2110) |
| 0xcf0b04 | Range decoder / Huffman (sub_CF0B04) |
| 0xcf1a44 | Buffer refill helper (sub_CF1A44) |

---

## 7. DATA::DECRYPTDATA — DETAIL CONTROL FLOW

```
Data::decryptData(this @ x20)
  Assumes: Data struct = {_ptr:+0x00, _size:+0x08, _tmp:+0x10, _flags:+0x18}

  ① size < 16?  → EXIT (too small)
  ② ptr[0:4] != "Antm"?  → EXIT (not .mt)
  ③ *(uint32*)(ptr+8) == 0x00ABCDEF?  → EXIT (already decrypted)

  version = ptr[4]
  payload_size = *(uint32*)(ptr+8) ^ 0x00ABCDEF

  ═══ VERSION 2 PATH (XOR) ═══
  CCCrypto::xor_decrypt(ptr+0x10, payload_size)   // in-place
  if isGZipBuffer(ptr+0x10, payload_size):
      inflateMemory → new buffer
  else:
      uncompressData → lmF@ decompress

  ═══ VERSION 1 PATH (AES) ═══
  temp_buf = malloc(payload_size + 1)
  key = CCCrypto::getKey()   // returns m_sKey
  CCCrypto::aes_decrypt(ptr+0x10, temp_buf, key, payload_size)
  if isGZipBuffer(temp_buf):
      inflateMemory → new buffer
  else:
      uncompressData → lmF@ decompress

  ═══ EXIT ═══
  Data::clear(this)  // free old buffer
  this->_ptr = result
  this->_size = result_size
```

---

## 8. ENCRYPTION VARIANTS

| Version | Algo | Key Source | Status |
|---------|------|-----------|--------|
| v1 | AES-128-ECB | `CCCrypto::getKey()` | Emulator: key known |
| v2 | XOR | Fixed table | Unknown |
| lmF@ | Custom range coder | None | Fully reversed |

---

## 9. BINARY SOURCES

| Source | Path | Notes |
|--------|------|-------|
| Emulator APK | `sources/emulator_mt/libagame.so` | AES key: f5a193d5... |
| Device APK | `sources/MLADVENTURE2/lib/arm64-v8a/libagame.so` | 18.87 MB, key unknown |
| Frida-gadget | `sources/MLADVENTURE2/lib/arm64-v8a/libfrida-gadget.so` | For injection |
| Disassembly | `sources/disassembly_output.txt` | Full ARM64 text section |
| Lua offsets | `sources/lua_offsets.h` | Lua/tolua++ function offsets |
| APK original | `sources/MLADVENTURE.apk` | 684 MB |
| APK extracted | `sources/MLADVENTURE2/` | 712 MB |
| Ghidra project | `sources/Project MLA/` | 492 MB |

---

## 10. FILE-FILE PENTING

### Scripts (PROJECT/scripts/)

| File | Fungsi |
|------|--------|
| `lmf_decoder.py` | lmF@ decompressor — **WORKING 100%** |
| `roo_parser_final.py` | Roo binary parser — **WORKING** |
| `hero_view.py` | Hero entity viewer |
| `build_mla_db.py` | SQLite DB builder |
| `analyze_semantic_model.py` | Field semantic mapping |
| `mt_tool.py` | Decrypt/encrypt .mt files |
| `hook_crypto.py` | Frida crypto hook |
| `hook_crypto2.py` | Frida crypto hook v2 |
| `hook_crypto3.py` | Frida crypto hook v3 |
| `frida_attach.py` | Attach to running process |
| `connect_and_hook.py` | Connect + hook combo |

### Docs (PROJECT/docs/)

| File | Fungsi |
|------|--------|
| `PIPELINE_VERIFIED.md` | Complete verified pipeline |
| `ROO_FORMAT_SPEC.md` | Complete Roo format spec |
| `DECRYPTDATA_SPEC.md` | Data::decryptData detail |
| `INIT_GRAPH.md` | Startup call graph |
| `STARTUP_SEQUENCE.md` | Moonton Protect packing |
| `VERIFIED.md` | All verified symbols |
| `DATABASE_ARCHITECTURE.md` | DB schema |
| `ENTITY_RELATIONSHIPS.md` | Entity relationships |
| `HERO_DATABASE.md` | Hero data docs |

### Data (data/)

| Path | Isi |
|------|-----|
| `data/mt_dump/` | 7000+ .mt files (device APK) |
| `data/DEC-ASSET/` | emulator .mt samples (verified dengan key emulator) |
| `data/decrypted_output/` | Hasil decrypt percobaan (~7370 files) |
| `data/e/` | 2 sample .mt files |

### Database

| File | Isi |
|------|-----|
| `PROJECT/cache/mla_database.db` | SQLite: 221K entities, 690K fields |

---

## 11. FRIDA SETUP (STATUS: 2026-07-01)

- Frida v17.14.1 — **TERINSTAL** (pip: frida, frida-tools)
- Android Studio — **TERINSTAL**
- Android SDK — **TERINSTAL** (C:\Users\NGEONG\AppData\Local\Android\Sdk\)
- Build tools: 36.1.0, 37.0.0
- Platform: android-36
- BlueStacks X — **UNINSTALLED**

### Yang Perlu Dilakukan

1. Buat AVD emulator (Android Studio) — target ARM64 atau x86_64
2. Install game APK di emulator
3. Download frida-server (ARM64)
4. Push frida-server ke emulator via `adb push`
5. Jalankan frida-server di emulator
6. Hook: `CCCrypto::getKey` atau `CCCrypto::setKey`
7. Capture AES key dari memory proses game

---

## 12. NEXT STEPS (URUTAN PRIORITAS)

1. **Setup AVD emulator** — jalankan via Android Studio AVD Manager
2. **Install game APK** — install MLADVENTURE.apk di emulator
3. **Frida hook `CCCrypto::getKey`** — capture AES key dari running process
4. **Verifikasi key emulator vs device** — apakah sama?
5. **Jika key berbeda** — reverse device .mt encryption path
6. **Buat tool decryptor lengkap** — untuk device APK

---

## 13. STRUKTUR DIREKTORI

```
MLA/ (3.8 GB)
├── sources/          ← APK, native binary, Ghidra project
│   ├── MLADVENTURE.apk
│   ├── MLADVENTURE2/              ← APK extracted
│   ├── Project MLA/               ← Ghidra project (492 MB)
│   ├── libagame.so
│   ├── libfrida-gadget.so
│   ├── apktool.jar
│   ├── lua_offsets.h
│   ├── disassembly_output.txt
│   └── logcat.txt
│
├── data/             ← .mt files, hasil decrypt
│   ├── mt_dump/                    ← 7000+ device .mt files
│   ├── DEC-ASSET/                  ← emulator .mt samples
│   ├── decrypted_output/           ← hasil decrypt
│   └── e/                         ← 2 sample .mt
│
└── PROJECT/          ← Working directory
    ├── SESSION_UTAMA.md            ← source of truth utama
    ├── scripts/                    ← tools & scripts
    │   ├── lmf_decoder.py          ← WORKING
    │   ├── roo_parser_final.py    ← WORKING
    │   ├── mt_tool.py             ← WORKING
    │   └── [Frida hooks, dll]
    ├── docs/                       ← semua dokumentasi
    ├── cache/
    │   └── mla_database.db         ← 221K entities
    └── [analysis, reports, logs, dll]
```

---

## 14. ATURAN PROJECT

- Bahasa: mix Indonesia & English
- Source of truth: file di `PROJECT/`
- Tidak ada asumsi tanpa bukti
- Confidence score wajib untuk setiap mapping
- Frida runtime = jalan terakhir untuk key discovery

---

*Dokumen ini adalah source of truth project. Update setiap kali ada temuan baru.*
