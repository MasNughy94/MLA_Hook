# 05 — REKOMENDASI REFACTOR

> Analisis kode usang, duplikat, tidak terpakai, serta rekomendasi struktur proyek yang lebih rapi. **Tanpa mengubah file asli.**

---

## 1. RINGKASAN TEMUAN

### 1.1 Kondisi Saat Ini

Proyek MLA saat ini memiliki:
- **200+ file script** di satu folder (`PROJECT/scripts/`)
- **4904 file dump** di satu folder (`dumps/luac/mla_dumps/`)
- **Duplikasi script** yang tersebar (banyak variasi `decrypt_mt_v*.py`, `query_db*.py`, `trace*.py`)
- **File mentah** campur dengan file hasil olahan
- **File .pyc** (bytecode compiled) di folder scripts — tidak konsisten
- **File sementara** (tmp_*, _*, test_*) tanpa organisasi

### 1.2 Proyek Terkait: MLA_Hook

Repo MLA_Hook terpisah dari folder proyek utama. Kodenya sudah cukup modular tapi memiliki beberapa kelemahan:

| Kelemahan | Detail |
|-----------|--------|
| **Hardcoded offset** | Fallback symbol resolution menggunakan offset absolut dari `lua_pcall` — akan rusak jika versi game berubah |
| **Tidak ada error recovery** | Jika satu hook gagal, seluruh inisialisasi gagal |
| **Tidak ada konfigurasi** | Semua parameter hardcoded (force_win=true, port 19527, path dump) |
| **Frida config tidak berfungsi** | hook.js hanya stub, monitor.log menunjukkan kegagalan |
| **Tidak ada uninstall/cleanup** | Tidak ada mekanisme untuk restore hook |

---

## 2. FILE DUPLIKAT / VARIASI

### 2.1 Script Dekripsi .mt (duplikasi tinggi)

| File | Ukuran (bytes) | Kemiripan |
|------|---------------|-----------|
| `decrypt_mt.py` | 9.039 | Versi awal |
| `decrypt_mt_v2.py` | 3.298 | Variasi algoritma |
| `decrypt_mt_v3.py` | 4.117 | Variasi algoritma |
| `decrypt_mt_v4_final.py` | 5.414 | "Final" — tapi ada yang lain |
| `decrypt_mt_files.py` | 6.186 | Batch processing |
| `decrypt_mt_tea_cfb.py` | 5.847 | TEA CFB mode |
| `decrypt_xxtea.py` | 4.172 | XXTEA specific |
| `comprehensive_decrypt.py` | 3.765 | Comprehensive |
| `_decrypt_mt_all.py` | 5.223 | Underscore prefix |
| `_decrypt_mt_all2.py` | 5.369 | Underscore prefix |
| `_decrypt_mt_filename_key.py` | 5.428 | Underscore prefix |
| `_decrypt_mt_final.py` | 5.935 | Underscore prefix |

**Rekomendasi:** Hanya perlu **satu** script dekripsi final yang mendukung semua mode (AES-128-ECB, TEA-CFB, XXTEA) + CLI argument.

### 2.2 Script Query Database (9 file)

| File | Fungsi |
|------|--------|
| `query_db.py` | Query dasar |
| `query_db2.py` - `query_db6.py` | 5 variasi query |
| `query_master_entries.py` | Query master entries |
| `query_master2.py` | Variasi master |
| `query_sqlite_entities.py` | Query entities |
| `query_sqlite_schema.py` | Query schema |
| `query_tags.py` | Query tags |
| `query_tags2.py` | Variasi tags |

**Rekomendasi:** Satu script `query_db.py` dengan CLI argument untuk memilih mode query.

### 2.3 Script Trace (banyak variasi)

| File | Fokus |
|------|-------|
| `trace_pipeline.py` | Pipeline trace |
| `trace_pipeline2.py` | Variasi |
| `trace_universal_pipeline.py` | Universal |
| `trace_decoder.py` | Decoder trace |
| `trace_decoder2.py`, `trace_decoder3.py` | Variasi decoder |
| `trace5.py` | (angka) |
| `trace_buffer.py` | Buffer trace |
| `trace_corrupt.py` | Corruption trace |
| `trace_detailed.py` | Detailed trace |
| `trace_func.py` | Function trace |
| `trace_function_context.py` | Function context |
| `trace_isgzip.py` | gzip detection |
| `trace_magic.py` | Magic bytes |
| `trace_matches.py` | Pattern matches |
| `trace_ro_magic_vtable.py` | RO magic vtable |
| `trace_sym5.py` | Symbol trace |
| `trace_vtable_dispatch.py` | Vtable dispatch |

**Rekomendasi:** Satu pipeline trace modular dengan plugin system.

### 2.4 Script Emulator Unicorn (12 file)

`emu_check.py`, `emu_debug.py`, `emu_decompress.py`, `emu_decompress_v4.py`, `emu_decompress_v5.py`, `emu_final.py`, `emu_fixed.py`, `emu_full.py`, `emu_minimal.py`, `emu_trace2.py`, `emu_trace3.py`, `emu_trace4.py`

**Rekomendasi:** Satu `emu_runner.py` + modul terpisah (`emu/` folder dengan `__init__.py`, `decompress.py`, `trace.py`, dll.)

### 2.5 Script Test (banyak)

`test_3byte_hypothesis.py`, `test_all_decrypt_approaches.py`, `test_bc.py`, `test_compressors.py`, `test_first_byte.py`, `test_fixed_tree.py`, `test_full_import.py`, `test_gap_threshold.py`, `test_inner_aes.py`, `test_lit_ctx.py`, `test_query.py`, `test_query2.py`, `test_rels.py`, `test_trees.py`, `test_trees2.py`, `test_zeros.py`

**Rekomendasi:** Pindahkan ke `tests/` folder dengan pytest.

---

## 3. FILE SEMENTARA / TIDAK TERPAKAI

### 3.1 File dengan prefix `_` (underscore)

File-file ini biasanya adalah **eksperimen/sementara** yang tidak untuk produksi:

`_alt_approaches.py`, `_analyze_crypto_syms.py`, `_analyze_elf.py`, `_analyze_elf2.py`, `_analyze_hades.py`, `_analyze_mt.py`, `_battle_snapshot.py`, `_brute_iv.py`, `_check_adrp_add.py`, `_check_apk_package.py`, `_check_engine.py`, `_check_libs.py`, `_check_loaded_libs.py`, `_check_luaopen_offsets.py`, `_comprehensive_test.py`, `_crypto_analysis.py`, `_crypto_debug.py`, `_decrypt_mt_all.py`, `_decrypt_mt_all2.py`, `_decrypt_mt_filename_key.py`, `_decrypt_mt_final.py`, `_deep_check.py`, `_derive_iv.py`, `_disasm_cbc_decrypt.py`, `_disasm_entity.py`, `_disassemble_httpclient.py`, `_extract_apk_info.py`, `_final_test.py`, `_find_adrp.py`, `_find_api_endpoints.py`, `_find_battle_result_funcs.py`, `_find_functions.py`, `_find_functions2.py`, `_find_httpclient_addresses.py`, `_find_http_api_endpoints.py`, `_find_http_symbols.py`, `_find_luaopen.py`, `_find_luasocket_functions.py`, `_find_socket_send.py`, `_hook_loadlibrary.py`, `_parse_relocations.py`, `_run_test.py`, `_scan_dynsym.py`, `_search_all_adrp.py`, `_search_context.py`, `_search_data_sections.py`, `_search_game_strings.py`, `_search_strings.py`, `_smart_brute.py`, `_spawn_and_hook.py`, `_test_debug.py`, `_test_debug2.py`, `_test_read.py`, `_test_rw.py`, `_test_rw2.py`, `_test_v2.py`, `_test_v3.py`, `_test_v4.py`, `_verify_addresses.py`

**Jumlah: ~55 file**

### 3.2 File dengan prefix `tmp_`

`tmp_analyze_tags.py`, `tmp_analyze_tags2.py`, `tmp_check_catalog.py`, `tmp_check_v3.py`, `tmp_cluster_entries.py`, `tmp_find_hero.py`, `tmp_find_hero_cluster.py`, `tmp_find_hero_entries.py`, `tmp_gen_hero_json.py`, `tmp_hero_schema_final.py`

**Jumlah: 10 file**

### 3.3 File .pyc (bytecode compiled)

`__pycache__/lmf_decoder.cpython-312.pyc`, `mla_diff.cpython-312.pyc`, `mla_query.cpython-312.pyc`, `mt_decoder.cpython-312.pyc`

Sebagai cache kompilasi Python, file .pyc **tidak perlu** di-version control. Ini artifact runtime.

---

## 4. MASALAH STRUKTUR

### 4.1 Flat Folder Problem

Semua 200+ script ada di satu folder `PROJECT/scripts/`. Ini menyebabkan:
- **Sulit navigasi** — perlu scroll panjang untuk menemukan file
- **Naming collision risk** — banyak nama mirip (trace_pipeline, trace_pipeline2, trace_pipeline_callers)
- **Tidak ada hierarki** — script dekripsi, analisis, emulator, Frida, utility campur aduk

### 4.2 Dump Folder Flat

4904 file .luac di satu folder `dumps/luac/mla_dumps/` akan menyebabkan:
- **Performance issue** — file system lambat dengan ribuan file dalam satu folder
- **Sulit dicari** — perlu grep/scrolling

### 4.3 Konvensi Penamaan Tidak Konsisten

| Masalah | Contoh |
|---------|--------|
| Campur snake_case dan camelCase | `quick_attach.py` vs `hook_spawn.js` |
| Angka tanpa arti | `trace5.py`, `emu_trace2.py` |
| "Final" tapi tidak final | `decrypt_mt_v4_final.py` — lalu masih ada `_decrypt_mt_final.py` |
| Prefix underscore tidak standar | 55 file dengan prefix `_` — apakah private? archive? |

---

## 5. REKOMENDASI STRUKTUR BARU

### 5.1 Struktur Folder yang Diusulkan

```
MLA/
├── .github/                       # (TIDAK BERUBAH)
├── data/                          # (TIDAK BERUBAH)
├── dumps/                         # (REFACTOR)
│   ├── luac/                      # Semua bytecode dump
│   │   ├── mt/                    # File hashed: {awal_hash}/{hash}.mt.luac
│   │   ├── require/               # require "..." -> require__path_.luac
│   │   ├── return_/               # return statement -> return__N_.luac
│   │   └── lib/                   # Library (LuaSocket, dll)
│   ├── pbr/                       # Battle parameter dumps
│   │   ├── pbr_dump.txt           # File log utama
│   │   └── sessions/              # Per-session dump
│   ├── frida/                     # Frida config & logs
│   │   ├── config/                # frida_config*.json
│   │   ├── scripts/               # hook.js, dll
│   │   └── logs/                  # monitor.log, dll
│   └── debug/                     # Debug logs
│       └── mla_debug.txt
├── PROJECT/
│   ├── scripts/                   # (REFACTOR - subfolders)
│   │   ├── decrypt/               # Script dekripsi (1 file final)
│   │   ├── analyze/               # Analisis ELF, format, struktur
│   │   ├── disasm/                # Disassembly pipeline
│   │   ├── emu/                   # Unicorn emulator (modular)
│   │   ├── frida/                 # Frida hooks & scripts
│   │   ├── hooks/                 # MLA_Hook code & variants
│   │   ├── trace/                 # Trace pipeline (modular)
│   │   ├── query/                 # Database query tools
│   │   ├── hero/                  # Hero analysis
│   │   ├── format/                # Roo/TLV parser
│   │   ├── key/                   # Key finding & crypto
│   │   ├── utils/                 # Utility functions
│   │   │   ├── __init__.py
│   │   │   ├── logger.py          # Logging utility
│   │   │   └── file_utils.py      # File I/O helpers
│   │   └── tests/                 # Unit tests (pytest)
│   │       ├── test_decrypt.py
│   │       ├── test_parser.py
│   │       └── test_emu.py
│   ├── analysis/                  # (TIDAK BERUBAH)
│   ├── cache/                     # (TIDAK BERUBAH)
│   ├── decrypted/                 # (TIDAK BERUBAH)
│   ├── docs/                      # (TIDAK BERUBAH)
│   ├── input/                     # (TIDAK BERUBAH)
│   ├── logs/                      # (TIDAK BERUBAH)
│   ├── parsed/                    # (TIDAK BERUBAH)
│   ├── reports/                   # (TIDAK BERUBAH)
│   ├── research/                  # (TIDAK BERUBAH)
│   ├── semantic/                  # (TIDAK BERUBAH)
│   └── SESSION/                   # (TIDAK BERUBAH)
├── sources/                       # (TIDAK BERUBAH)
├── docs/                          # Dokumentasi terpusat (baru)
│   ├── 01_STRUKTUR_PROJECT.md
│   ├── 02_ANALISIS_HOOK.md
│   ├── 03_ALUR_HOOK.md
│   ├── 04_DAFTAR_FUNGSI_GAME.md
│   └── 05_REKOMENDASI_REFACTOR.md
├── external/                      # External repos terintegrasi (baru)
│   └── MLA_Hook/                  # Git submodule ke MasNughy94/MLA_Hook
│       ├── module/
│       │   ├── src/
│       │   ├── include/
│       │   └── CMakeLists.txt
│       └── GUIDE.md
├── config/                        # Konfigurasi terpusat (baru)
│   ├── paths.json                 # Path ke ADB, NDK, SDK
│   ├── hook_config.json           # Konfigurasi hook (target lib, port, dll)
│   └── decrypt_config.json        # Konfigurasi dekripsi (mode, key)
├── requirements.txt               # Python dependencies
└── README.md                      # Dokumentasi proyek utama
```

### 5.2 Saran untuk MLA_Hook Refactor

```
MLA_Hook/
├── module/
│   ├── src/
│   │   ├── main.cpp               # Entry point (minimal)
│   │   ├── hook_loadbuffer.cpp    # luaL_loadbuffer hook
│   │   ├── hook_pcall.cpp         # lua_pcall hook
│   │   ├── hook_setfield.cpp      # lua_setfield hook
│   │   ├── lua_api.cpp            # Symbol resolution
│   │   ├── lua_inject.cpp         # Lua mod script injection
│   │   ├── output_tcp.cpp         # TCP sender
│   │   ├── output_file.cpp        # File dumper
│   │   ├── output_log.cpp         # logcat logger
│   │   └── utils.cpp              # Utility functions
│   ├── include/
│   │   ├── hooking.h
│   │   ├── lua_api.h
│   │   ├── output.h
│   │   └── config.h               # Konfigurasi (ganti hardcoded)
│   ├── config/
│   │   └── mla_hook.json          # Runtime config file
│   └── CMakeLists.txt
└── scripts/                       # Build & deploy scripts
    ├── build.ps1
    ├── build.sh
    └── deploy.py                  # ADB push + inject
```

**Perbaikan teknis yang direkomendasikan untuk MLA_Hook:**
1. **Ganti hardcoded offset** dengan pattern matching / signature scanning
2. **Tambahkan config file** JSON untuk parameter runtime
3. **Tambahkan graceful degradation** — jika satu hook gagal, hook lain tetap jalan
4. **Fix Frida gadget** — lengkapi hook.js dengan hook yang sebenarnya
5. **Tambahkan mekanisme cleanup** — restore hook saat modul di-unload
6. **Gunakan `#define`** untuk path, port, dan parameter lainnya

---

## 6. PRIORITAS REFACTOR

| Prioritas | Area | Alasan |
|-----------|------|--------|
| 🔴 **HIGH** | Pisahkan 200+ script ke subfolder | Navigasi & maintainability |
| 🔴 **HIGH** | Archive 55 file `_` + 10 file `tmp_` | Mengurangi kebingungan |
| 🟡 **MEDIUM** | Gabungkan 12+ varian decrypt script | Satu titik kebenaran |
| 🟡 **MEDIUM** | Gabungkan 9+ varian query script | Satu titik kebenaran |
| 🟡 **MEDIUM** | Organisasi dumps/luac/ ke subfolder | Filesystem performance |
| 🟢 **LOW** | Hapus .pyc dari version control | Artifact runtime |
| 🟢 **LOW** | Integrasi MLA_Hook sebagai submodule | Satu source of truth |
| 🟢 **LOW** | Buat config file JSON terpusat | Mudah dikonfigurasi |
| 🟢 **LOW** | Unit test untuk script utama | Regression prevention |

---

## 7. CATATAN PENTING

1. **Jangan hapus file asli** — selalu archive atau rename
2. **Simpan history** — jika file memiliki nilai historis (perjalanan reverse engineering), dokumentasikan di SESSION/
3. **Dokumentasi pipeline** — setiap subfolder harus punya README singkat
4. **Integrasi MLA_Hook** — gunakan git submodule agar sinkron dengan repo upstream
5. **File dump tidak perlu di-refactor** — hanya re-organisasi folder untuk performa
