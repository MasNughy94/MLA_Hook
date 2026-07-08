# 01 — STRUKTUR PROYEK MLA

> Analisis struktur folder, file, dan hubungan antar komponen dalam proyek **Mobile Legends Adventure Reverse Engineering**.

---

## 1. DIAGRAM FOLDER (Tingkat Atas)

```
MLA/
├── .github/              # GitHub CI/CD workflows
├── .gitignore
├── .gitmodules
├── data/                 # Asset mentah & dekripsi
│   ├── DEC-ASSET/        # Asset game terdekripsi (folder 0..b, e)
│   ├── decrypted_output/ # Output dekripsi tambahan
│   ├── e/                # (belum terklasifikasi)
│   └── mt_dump/          # Dump file .mt mentah dari APK
│       └── assets/
├── dumps/                # [BARU] Dump dari hook runtime pada device
│   ├── luac/
│   │   └── mla_dumps/    # 4904 file .luac (Lua bytecode)
│   ├── frida_config/
│   │   └── MLADVENTURE_DUMP/
│   │       ├── frida_config.json
│   │       ├── frida_config2.json
│   │       ├── frida_config3.json
│   │       ├── listen_config.json
│   │       ├── hook.js
│   │       └── monitor.log
│   ├── pbr_dump.txt      # 112508 baris — log LUA_LOAD + battle params
│   └── mla_debug.txt     # 5 baris — inisialisasi hook
├── PROJECT/              # Inti riset & reverse engineering
│   ├── analysis/         # Hasil analisis file .mt / Roo / entity
│   ├── cache/            # Cache pemrosesan
│   ├── decrypted/        # File .mt terdekripsi
│   ├── docs/             # Dokumentasi format
│   ├── emulator_mt/      # File .mt dari emulator (AES key known)
│   ├── from_termux/      # Script/work dari Termux Android
│   ├── input/            # Input mentah untuk script
│   ├── logs/             # Log eksekusi script
│   ├── parsed/           # Output parser
│   ├── reports/          # Laporan analisis
│   ├── research/         # Catatan riset
│   ├── scripts/          # 200+ script Python/JS/C++
│   ├── semantic/         # Database semantik & relasi entity
│   └── SESSION/          # Catatan sesi reverse engineering
├── sources/              # Source code pihak ketiga
│   ├── MLADVENTURE2/     # Framework/tool MLADVENTURE
│   └── PROJECT MLA/      # Toolkit Project MLA
├── query_db.py           # Query database entity
├── query_db2.py .. query_db6.py
├── query_master_entries.py / query_master2.py
├── query_sqlite_entities.py / query_sqlite_schema.py
├── query_tags.py / query_tags2.py
└── readme.txt            # Dokumentasi proyek (dibuat sebelumnya)
```

---

## 2. FUNGSI SETIAP FOLDER

### 2.1 `data/` — Asset Game Mentah

| Subfolder | Isi |
|-----------|-----|
| `DEC-ASSET/0..b, e/` | File asset game hasil dekripsi AES (key: `moontonAgame1234`). Terbagi dalam folder heksadesimal (0-f) untuk organisasi hirarkis. |
| `decrypted_output/` | Output dari script dekripsi batch. Berisi file .mt yang sudah didekripsi. |
| `mt_dump/assets/` | Dump langsung file .mt dari APK game sebelum dekripsi. |

**Pipeline data:** `.mt` (encrypted) → AES-128-ECB decrypt → `lmF@` decompress → Roo parser → SQLite DB (221k entities).

### 2.2 `dumps/` — [BARU] Hasil Hook Runtime

| Subfolder/File | Isi | Ukuran |
|----------------|-----|--------|
| `luac/mla_dumps/` | 4904 file **Lua bytecode** (.luac) | Bervariasi (7 byte - ~4 MB) |
| `pbr_dump.txt` | Log real-time hook: `[PBR] LUA_LOAD name=... size=...` + battle param dump | 112.508 baris, 6.3 MB |
| `mla_debug.txt` | Log inisialisasi hook | 5 baris |
| `frida_config/MLADVENTURE_DUMP/` | Konfigurasi Frida + hook stub + monitor log | 6 file |

**Asal:** Dipull via ADB dari `/sdcard/Android/data/com.moonton.mobilehero/files/` dan `/sdcard/MLADVENTURE_DUMP/`.

### 2.3 `PROJECT/` — Inti Reverse Engineering

| Subfolder | Fungsi |
|-----------|--------|
| `scripts/` | **200+ file** — inti toolkit RE. Python (90%), JavaScript (Frida), C++ (Unicorn emulator). |
| `semantic/` | Database semantik: schemas entity, relasi foreign key, graph referensi, hero DB schema (`.json` & `.md`). |
| `analysis/` | Hasil analisis mendalam terhadap format file (cluster, homogeneous, structural). |
| `decrypted/` | File .mt hasil dekripsi dari emulator + device. |
| `docs/` | Dokumentasi format `.mt`, Roo, TLV, dll. |
| `research/` | Catatan riset: fungsi kripto, key expansion, XXTEA, AES. |
| `SESSION/` | Catatan sesi reverse engineering (3 file: daily log, session utama, continue note). |
| `emulator_mt/` | File .mt spesifik dari pipeline emulator (AES key berhasil). |
| `from_termux/` | Script/workflow yang dijalankan dari Termux Android. |
| `logs/` `cache/` `input/` `parsed/` `reports/` | Pendukung pipeline analisis. |

### 2.4 `sources/` — Pustaka Pihak Ketiga

| Subfolder | Isi |
|-----------|-----|
| `MLADVENTURE2/` | Framework MLADVENTURE — tool untuk dekompilasi/dekripsi asset game Moonton. |
| `PROJECT MLA/` | Toolkit Project MLA — koleksi script RE untuk game Moonton. |

### 2.5 Root `query_*.py`

9 file query untuk mengekstrak data dari:

- **Entity/hero database** — `query_db.py` s.d. `query_db6.py`
- **Master entries** — `query_master_entries.py`, `query_master2.py`
- **SQLite schema** — `query_sqlite_schema.py`, `query_sqlite_entities.py`
- **Tags** — `query_tags.py`, `query_tags2.py`

### 2.6 File `.pyc` (Bytecode)

Terdapat 5 file `.pyc` di `PROJECT/scripts/__pycache__/`:
- `lmf_decoder.cpython-312.pyc` (8.8 KB)
- `mla_diff.cpython-312.pyc` (42 KB)
- `mla_query.cpython-312.pyc` (29 KB)
- `mt_decoder.cpython-312.pyc` (24 KB)

---

## 3. KLASIFIKASI FILE SCRIPT (PROJECT/scripts/)

### 3.1 Dekripsi & Decompress (16 file)
`decrypt_mt.py`, `decrypt_mt_v2.py`, `decrypt_mt_v3.py`, `decrypt_mt_v4_final.py`, `decrypt_mt_files.py`, `decrypt_mt_tea_cfb.py`, `decrypt_bapmod.py`, `decrypt_xxtea.py`, `comprehensive_decrypt.py`, `poc_decrypt.py`, `try_decrypt.py`, `try_decrypt2.py`, `try_decrypt3.py`, `try_all_ciphers.py`, `try_aes_xxtea_extensive.py`, `_decrypt_mt_final.py`

### 3.2 Static Analysis ELF/Dex (25+ file)
`find_key.py`, `find_key_functions.py`, `find_key_xref.py`, `find_xxtea_key.py`, `find_aes_funcs.py`, `find_lua_bindings.py`, `find_libagame.py`, `find_libagame2.py`, `find_libagame3.py`, `find_loader.py`, `find_vtable.py`, `find_undump.py`, `find_undump2.py`, `elf_parse_funcptr.py`, `parse_elf.py`, `parse_dynsym.py`, `check_plt.py`, `check_exports.py`, `__init__find_magic.py*`, `find_magic2.py`, `find_magic_refs.py`

### 3.3 Disassembly (30+ file)
`disasm_pipeline.py`, `disasm_getkey.py`, `disasm_getkeyv.py`, `disasm_aesdecrypt.py`, `disasm_cbc.py`, `disasm_decompress.py`, `disasm_decompressor.py`, `disasm_decryptdata.py`, `disasm_entry200.py`, `disasm_entry200_capstone.py`, `disasm_entry200_fast.py`, `disasm_keys.py`, `disasm_key_fns.py`, `disasm_loadbuffer.py`, `disasm_runroot.py`, `disasm_teacore.py`, `disasm_teadecrypt.py`, `disasm_uncompress.py`, `disasm_wrapper.py`, `disassemble_real_pipeline.py`, `manual_disasm.py`

### 3.4 Emulator (Unicorn) (12 file)
`emu_check.py`, `emu_debug.py`, `emu_decompress.py`, `emu_decompress_v4.py`, `emu_decompress_v5.py`, `emu_final.py`, `emu_fixed.py`, `emu_full.py`, `emu_minimal.py`, `emu_trace2.py`, `emu_trace3.py`, `emu_trace4.py`

### 3.5 Frida / Hook (15 file)
`frida_attach.py`, `frida_hook_getkey.js`, `frida_java_hook.py`, `frida_test_pid.py`, `hook_crypto.py`, `hook_crypto2.py`, `hook_crypto3.py`, `hook_mt_decrypt.py`, `connect_and_hook.py`, `hook_spawn.js`, `hook_strlen_key.js`, `hook_universal.js`, `spawn_and_monitor.py`, `spawn_game.py`, `quick_attach.py`

### 3.6 Analisis Hero (15+ file)
`hero_view.py`, `deep_hero_roster.py`, `extract_full_hero.py`, `find_hero_db.py`, `find_hero_across_cluster.py`, `tmp_find_hero.py`, `tmp_find_hero_cluster.py`, `tmp_find_hero_entries.py`, `tmp_gen_hero_json.py`, `tmp_hero_schema_final.py`, `merge_hero_into_v3.py`

### 3.7 Analisis Format Roo/TLV (15+ file)
`roo_parser.py`, `roo_parser_final.py`, `find_roo.py`, `find_roo_parser.py`, `tlv_analysis.py`, `schema_inference.py`, `schema_doc.py`, `classify_roo_files.py`, `format_structure_profile.py`, `structural_analysis.py`

### 3.8 Trace & Pipeline (20+ file)
`trace_pipeline.py`, `trace_pipeline2.py`, `trace_pipeline_callers.py`, `trace_universal_pipeline.py`, `trace_decoder.py`, `trace_decoder2.py`, `trace_decoder3.py`, `trace5.py`, `trace_buffer.py`, `trace_corrupt.py`, `trace_detailed.py`, `trace_func.py`, `trace_function_context.py`, `trace_isgzip.py`, `trace_magic.py`, `trace_matches.py`, `trace_ro_magic_vtable.py`, `trace_sym5.py`, `trace_vtable_dispatch.py`

### 3.9 Key Finding & XOR (10+ file)
`find_key_expansion_ptr.py`, `find_key_full_scan.py`, `find_key_xref.py`, `try_derived_keys.py`, `try_many_keys.py`, `try_filename_xor.py`, `verify_xor.py`, `search_keys_data.py`, `search_key_in_so.py`, `scan_for_keys.py`, `scan_memory_keys.js`

### 3.10 Database Query (5 file)
`find_entity_dbs.py`, `find_homogeneous_db.py`, `generate_relationship_db.py`, `read_master_db.py`, `read_global_structure.py`

### 3.11 Utility (20+ file)
`validate.py`, `cross_reference.py`, `cross_reference_analysis.py`, `cross_compare.py`, `cross_file_analysis.py`, `diff_analysis.py`, `diff_samples.py`, `zipalign.py`, `search_patterns.py`, `search_string.py`, `search_strings.py`, `synthesis.py`, `symsearch.py`

---

## 4. HUBUNGAN ANTAR KOMPONEN

```
MLA_Hook (GitHub)                    MLA Project (Lokal)
     │                                      │
     │ (DobbyHook)                          │ (Python script + Frida)
     │ libagame.so                          │
     ▼                                      ▼
┌──────────────┐                    ┌──────────────────┐
│ luaL_loadbuffer │──── LUA LOAD ──▶│ dumps/luac/      │
│ (dump bytecode) │                 │ 4904 .luac files  │
└──────────────┘                    └──────────────────┘
┌──────────────┐                    ┌──────────────────┐
│ lua_pcall      │──── TRACE ──────▶│ dumps/pbr_dump.txt│
│ (battle param) │                 │ 112508 lines      │
└──────────────┘                    └──────────────────┘
┌──────────────┐                    ┌──────────────────┐
│ lua_setfield   │──── FORCE WIN ──▶│ (in-game effect)  │
│ (result field) │                 │ auto-win + VIP 15  │
└──────────────┘                    └──────────────────┘
┌──────────────┐                    ┌──────────────────┐
│ Frida Gadget  │──── (FAILED) ────▶│ dumps/frida_config│
│ (hook.js)     │                 │ monitor.log       │
└──────────────┘                    └──────────────────┘

Project MLA (Emulator Pipeline):
  .mt file (APK) → AES-128-ECB → lmF@ decompress → Roo parse → SQLite DB

MLA_Hook (Device Pipeline):
  Game Runtime → DobbyHook → dump .luac → pull ADB → dumps/luac/
```

---

## 5. STATISTIK

| Kategori | Jumlah |
|----------|--------|
| Total file .luac di dump | 4.904 |
| Total baris pbr_dump.txt | 112.508 |
| Total script Python di PROJECT/scripts/ | ~200+ |
| Total script JavaScript (Frida) | ~8 |
| Total file C++ | 2 (`main_modified.cpp`, `main.cpp` via MLA_Hook) |
| Total file .json semantik | 8 |
| Total file sesi/log | 3 |
| Total folder asset DEC-ASSET | 12 (0..b + e) |
