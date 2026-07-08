================================================================================
                                   README
                      PROYEK REVERSE ENGINEERING MLA
          Mobile Legends Adventure - Analisis File .mt (Moonton)
================================================================================

                                     2026-07-07

================================================================================
1. RINGKASAN PROYEK
================================================================================

Tujuan:
  Membongkar dan memahami format file .mt (Moonton) milik game Mobile Legends
  Adventure (MLA). Pipeline utama: decrypt (.mt) -> decompress -> parse (Roo) ->
  SQLite database. Proyek ini mencakup reverse engineering native library (ARM64),
  dekripsi AES-128-ECB, dekompresi lmF@, parsing format Roo, dan analisis
  database game (221,602 entity).

Gambaran Umum:
  - Emulator pipeline: 100% working (key AES diketahui)
  - Device APK pipeline: ~80% (format sama, key berbeda/belum ditemukan)
  - Tools: Python scripts, Frida hooks, disassembly, emulasi Unicorn
  - Output: SQLite database, JSON analysis, dokumentasi pipeline

================================================================================
2. PENGELOMPOKAN FOLDER BERDASARKAN FUNGSI
================================================================================

Kategori: DECRYPTION / REVERSE ENGINEERING / ANALYSIS SCRIPTS
  PROJECT/scripts/            -> 466 file Python untuk semua tahap RE

Kategori: NATIVE LIBRARY
  sources/MLADVENTURE2/lib/  -> .so libraries dari APK (ARM64)

Kategori: SOURCE CODE (decompiled APK)
  sources/MLADVENTURE2/       -> Hasil decompile APK (smali, dex, res, assets)
  sources/PROJECT MLA/       -> Project IDA Pro (Ghidra?)

Kategori: TOOLS
  sources/apktool.jar         -> APK decompiler
  sources/libfrida-gadget.so  -> Frida gadget untuk hooking

Kategori: ASSET (game data)
  data/decrypted_output/      -> ~7370 file .mt hasil decrypt (RAW/XML)
  data/DEC-ASSET/             -> Aset hasil decompress (14 file .mt)
  data/e/                     -> 2 file .mt spesifik
  data/mt_dump/               -> Sample .mt + hasil setiap tahap pipeline
  PROJECT/decrypted/dec_batch/ -> ~7258 file .mt hasil decrypt batch
  PROJECT/emulator_mt/        -> File .mt dari emulator (4 file + .so)

Kategori: DATABASE
  PROJECT/cache/mla_database.db -> SQLite hasil parsing (221,602 entity)

Kategori: ANALYSIS OUTPUT
  PROJECT/analysis/           -> 11 file JSON hasil analisis
  PROJECT/semantic/           -> 8 file JSON/MD model semantic database
  PROJECT/reports/            -> Diff reports antar versi (v1, v2, v6)
  PROJECT/research/           -> Riset runtime enumeration

Kategori: DOCUMENTATION
  PROJECT/docs/               -> 15 file dokumentasi teknis (.md)
  PROJECT/SESSION/            -> Log sesi reverse engineering
  PROJECT/RESUME OpenCode/    -> Laporan eksekutif

Kategori: CI / CONFIGURATION
  .github/workflows/build.yml -> GitHub Actions build
  .gitignore                  -> 91 aturan ignore
  .gitmodules                 -> Submodule Dobby (hooking library)

Kategori: TEMPORARY / CACHE
  PROJECT/scripts/__pycache__/ -> Python bytecode cache
  PROJECT/from_termux/__pycache__/ -> Python bytecode cache

Kategori: EMPTY / CADANGAN
  PROJECT/parsed/             -> Kosong
  PROJECT/input/              -> Kosong
  PROJECT/logs/               -> Kosong

================================================================================
3. STRUKTUR FOLDER LENGKAP
================================================================================

ROOT: C:\Users\ADMIN SERVICE\Videos\MLA
.htaccess-like config files:
  .gitignore              Konfigurasi Git ignore (91 aturan)
  .gitmodules             Submodule Dobby (https://github.com/jmpews/Dobby.git)
  .github/workflows/      CI build workflow (build.yml)

--- ROOT FILES: QUERY SCRIPTS ---
query_db.py ~ query_db6.py         Query data dari SQLite database hasil parsing
query_master_entries.py             Query entri master database
query_master2.py                    Query master versi lanjutan
query_sqlite_entities.py            Query entity dari SQLite
query_sqlite_schema.py              Melihat skema tabel SQLite
query_tags.py, query_tags2.py       Query tag data game
query_sqlite entities.py            (duplikat nama dengan query_sqlite_entities.py?)
  Fungsi:  Akses dan query hasil parsing .mt ke database SQLite
  Manfaat: Verifikasi data dan eksplorasi isi database tanpa parsing ulang
  Wajib:   Tidak, hanya utility query
  Hasil Build: Tidak
  Hasil Decompile: Tidak
  Backup:   Tidak
  Temporary: Tidak

--- FOLDER: data/ ---
Fungsi:    Menyimpan data game mentah, baik yang terenkripsi (.mt) maupun
           hasil dekripsi/dekompresi di berbagai tahap pipeline
Hubungan:  Input dari sources/MLADVENTURE2/assets/, output ke PROJECT/scripts/
Wajib:     Ya, sumber data utama
Hasil Build: Sebagian (decrypted_output adalah hasil decrypt)
Hasil Decompile: Tidak
Backup:     data/mt_dump/ bisa dianggap backup sample

Subfolder:
  data/DEC-ASSET/
    Fungsi: Hasil decompress aset game (14 file .mt didekompres)
    Isi:    Folder 0-9, a, b, e berisi .dec + .txt; _decompile_log.txt
    Manfaat: Contoh hasil akhir decompress untuk verifikasi pipeline
    Hubungan: Output dari script di PROJECT/scripts/
    Wajib:   Tidak, hasil proses
    Hasil Build: Ya (hasil decompress)
    Temporary:   Bisa dianggap intermediate output

  data/decrypted_output/
    Fungsi: Output dekripsi .mt (~7370 file)
    Isi:    File RAW/XML dengan pola:
            {hash}_{format}.{tipe}
            - UNKNOWN_raw (raw setelah AES decrypt)
            - lmF@_uncompressed_f5a193d5_hdr16 (setelah range decode)
            - XML_* (hasil parse XML)
    Manfaat: Melihat hasil decrypt semua file .mt
    Hubungan: Output script decrypt di PROJECT/scripts/
    Wajib:   Tidak, hasil proses
    Hasil Build: Ya (hasil dekripsi)
    Temporary:   Bisa di-reproduce dari file .mt asli

  data/e/
    Fungsi: 2 file .mt spesifik (mungkin sample)
    Isi:    ec6dc2b91ccdeb3b47bce19b3b48fb5a.mt
            ef38b62e54c15222c2d076cb9de82fa2.mt
    Manfaat: File uji coba
    Wajib:   Tidak

  data/mt_dump/
    Fungsi: Sample file .mt lengkap dengan hasil setiap tahap pipeline
    Isi:    sample.mt (original encrypted)
            sample.mt.dec (setelah AES decrypt)
            sample.dec (??)
            sample.mt.dec_md5 (hash)
            sample.mt.dec_raw (raw)
            sample.mt.lua (hasil akhir decompress -> lua?)
            assets/ (asset game - mirror dari APK)
    Manfaat: Referensi visual pipeline step-by-step
    Wajib:   Tidak, dokumentasi
    Backup:   Ya, ini backup sample

--- FOLDER: sources/ ---
Fungsi:    Menyimpan sumber APK original, hasil decompile, dan tools
Hubungan: Input ke data/ (file .mt dari assets APK), input ke PROJECT/scripts/
Wajib:     Ya, sumber utama reverse engineering
Hasil Build: Tidak
Hasil Decompile: sources/MLADVENTURE2/ adalah hasil decompile

Subfolder:
  sources/MLADVENTURE.apk
    Fungsi: File APK original game
    Manfaat: Bahan baku utama RE
    Wajib:   Ya

  sources/libagame.so
    Fungsi: Native library utama game (diekstrak dari APK)
    Manfaat: Target RE utama (berisi fungsi decrypt, crypto, dll)
    Wajib:   Ya

  sources/libfrida-gadget.so
    Fungsi: Library Frida Gadget untuk hooking
    Manfaat: Instrumentasi runtime game
    Wajib:   Tidak, tool

  sources/apktool.jar
    Fungsi: Tool decompile APK
    Manfaat: Membongkar APK menjadi smali + resources
    Wajib:   Tidak, tool

  sources/disassembly_output.txt
    Fungsi: Output disassembly libagame.so
    Manfaat: Referensi analisis
    Wajib:   Tidak

  sources/logcat.txt
    Fungsi: Log Android dari game runtime
    Manfaat: Debug runtime
    Wajib:   Tidak

  sources/lua_offsets.h
    Fungsi: Definisi offset struct Lua
    Manfaat: Memahami struktur data Lua di memory
    Wajib:   Tidak

  sources/MLADVENTURE2/
    Fungsi: Hasil decompile APK (apktool)
    Isi:    AndroidManifest.xml, classes.dex, classes2.dex,
            lib/arm64-v8a/ (8 .so libraries), assets/ (game data),
            res/, META-INF/, kotlin/, okhttp3/, dll.
      lib/arm64-v8a/ berisi:
        libagame.so       -> Library game utama (core)
        libhades.so       -> Library Hades (engine?)
        libBugly.so       -> Bugly crash reporting (Tencent)
        libcrashlytics*.so -> Firebase Crashlytics
        libdatastore_shared_counter.so -> Google DataStore
      assets/ berisi:
        Folder 0-9, a-f (file .mt terenkripsi)
        app_config.json, google-services.json
        LuaCheckFile.bin, config.bin
        resList.lua, resSizeList.lua
        audio/, fonts/, shader/, level/, dll.
    Manfaat: Semua bahan RE: source smali, native lib, asset .mt
    Wajib:   Ya
    Hasil Decompile: Ya, dari apktool

  sources/PROJECT MLA/
    Fungsi: Project file IDA Pro / Ghidra untuk analisis binary
    Isi:    MLA PROJECT.gpr, MLA PROJECT.lock, MLA PROJECT.rep/
    Manfaat: Project analisis disassembly
    Wajib:   Tidak

--- FOLDER: PROJECT/ ---
Fungsi:    Workspace utama RE - berisi semua skrip, analisis, output
Hubungan: Pusat dari seluruh proyek
Wajib:     Ya
Hasil Build: Sebagian (cache, decrypted)
Hasil Decompile: Tidak

Subfolder:
  PROJECT/scripts/
    Fungsi: INTI PROYEK - 466 file Python untuk semua aspek RE
    Isi:    Berikut subkategori:
      a. DECRYPTION:
         decrypt_mt.py, decrypt_mt_v2/3/4_final.py
         decrypt_xxtea.py, decrypt_bapmod.py
         decrypt_mt_tea_cfb.py, decrypt_mt_files.py
         comprehensive_decrypt.py, poc_decrypt.py
      b. DISASSEMBLY:
         disasm.py, disasm_entry200.py, disasm_cbc.py
         disasm_keys.py, disasm_pipeline.py, disasm_uncompress.py
         disasm_teacore.py, disasm_aesdecrypt.py
         disassemble_real_pipeline.py
      c. EMULATION (Unicorn):
         emu_decompress.py, emu_decompress_v4/v5.py
         emu_check.py, emu_debug.py, emu_final.py, emu_full.py
         emu_trace_all.py, emu_trace2/3/4.py
         unicorn_trace.py
      d. FRIDA HOOKING:
         frida_attach.py, frida_java_hook.py
         hook_crypto.py, hook_crypto2/3.py, hook_mt_decrypt.py
         hook_spawn.js, hook_strlen_key.js, hook_universal.js
         spawn_game.py, spawn_and_monitor.py, connect_and_hook.py
      e. BINARY ANALYSIS:
         analyze_so.py, analyze_arm64.py, analyze_binary.py
         find_xxtea_*.py, find_key*.py, find_libagame*.py
         scan_dynsym.py, scan_rodata.py, scan_all_memory.py
         parse_dynsym.py, parse_elf.py, elf_parse_funcptr.py
      f. FORMAT PARSING (.mt / Roo / lmF@):
         lmf_decoder.py, mt_decoder.py, roo_parser.py
         roo_parser_final.py, analyze_lmF.py, analyze_mt.py
         analyze_format.py, analyze_pipeline.py~6.py
         analyze_cluster*.py, search_lmF@.py
      g. DATABASE ANALYSIS:
         analyze_hero_db.py, analyze_entity_types.py
         build_erd.py, build_file_catalog.py, build_mla_db.py
         semantic_reconstruction.py, semantic_v2/v3.py
         schema_inference.py, schema_doc.py
         generate_relationship_db.py
      h. TESTING / DEBUG:
         test_*.py, check_*.py, debug_*.py, tmp_*.py
         try_*.py, verify_*.py, validate.py
      i. UTILITY:
         batch_analyze.py, batch_decompile_mt.py
         cross_reference.py, all_pipelines.py
         final_classify.py, patch_bypass.py
    Manfaat: Semua kode analisis - jantung proyek
    Wajib:   Ya
    Hasil Build: Tidak
    __pycache__/ -> Temporary (Python bytecode)

  PROJECT/analysis/
    Fungsi: Hasil analisis dalam format JSON
    Isi:
      semantic_analysis.json  -> Analisis semantic entity (21rb baris)
      cluster_report.json     -> Laporan klaster file
      file_catalog.json       -> Katalog semua file
      final_classification.json -> Klasifikasi akhir
      tag_database.json       -> Database tag
      corpus_summary.json     -> Ringkasan korpus
      hero_db_schema_analysis.json -> Skema database hero
      roo_file_catalog.json   -> Katalog file Roo
      extract.ps1, lookup_entries.ps1 -> Script PowerShell utility
    Manfaat: Output analisis langsung pakai
    Wajib:   Tidak (bisa di-reproduce)
    Hasil Build: Ya
    Temporary:   Hasil proses

  PROJECT/semantic/
    Fungsi: Model relasi database game
    Isi:
      entity_relationships.json -> Relasi antar entity
      entity_schemas.json       -> Skema entity
      foreign_keys.json         -> Kunci asing
      primary_keys.json         -> Kunci utama
      hero_db_schema.json/.md   -> Skema DB hero
      reference_graph.json      -> Graph referensi
      semantic_db_v3.json       -> Database semantic v3
    Manfaat: Dokumentasi struktur database game
    Wajib:   Tidak
    Hasil Build: Ya (dari semantic_reconstruction.py)

  PROJECT/docs/
    Fungsi: Dokumentasi teknis
    Isi:
      PIPELINE.md, PIPELINE_VERIFIED.md  -> Pipeline decrypt
      ROO_FORMAT_SPEC.md                 -> Spesifikasi format Roo
      DECRYPTDATA_SPEC.md                -> Spesifikasi decrypt
      DATABASE_ARCHITECTURE.md           -> Arsitektur DB
      ENTITY_RELATIONSHIPS.md            -> Relasi entity
      HERO_DATABASE.md                   -> Database hero
      STARTUP_SEQUENCE.md, STARTUP_TIMELINE.md -> Startup game
      GAP_ANALYSIS.md, INIT_GRAPH.md     -> Analisis gap & init
      session.md                         -> Catatan sesi
      SEASON_SUMMARY.txt, VERIFIED.md    -> Ringkasan
    Manfaat: Dokumentasi lengkap hasil RE
    Wajib:   Tidak
    Hasil Build: Tidak

  PROJECT/reports/
    Fungsi: Laporan perbandingan antar versi
    Isi:    diff_v1_v2.*, diff_v1_v6.* (JSON + TXT)
    Manfaat: Melacak perubahan data antar versi game
    Wajib:   Tidak
    Hasil Build: Ya (dari diff tool)

  PROJECT/research/
    Fungsi: Skrip riset enumerasi runtime
    Isi:
      enumerate_game.py, enumerate_game_v2.py
      enumerate_libagame.js, enumerate_with_dlopen.py
      find_game_procs.py, mla_enumeration.json
      session_progress_2026-07-01.md
    Manfaat: Dokumentasi riset runtime game
    Wajib:   Tidak

  PROJECT/cache/
    Fungsi: Cache database SQLite
    Isi:    mla_database.db (SQLite, 221,602 entity)
    Manfaat: Data game siap query tanpa parsing ulang
    Wajib:   Tidak
    Hasil Build: Ya
    Temporary:   Bisa di-rebuild

  PROJECT/decrypted/dec_batch/
    Fungsi: Hasil decrypt batch semua file .mt
    Isi:    ~7258 file .mt.dec (hasil AES decrypt)
    Manfaat: Data intermediate hasil decrypt
    Wajib:   Tidak
    Hasil Build: Ya
    Temporary:   Bisa di-reproduce

  PROJECT/emulator_mt/
    Fungsi: File .mt dari emulator Android (MEmu/BlueStacks)
    Isi:
      base.apk, libagame.so, libhades.so
      e42da2e203724755f8607e7e3b81a0c1.mt
      e4cf63c72b429b41d5edaea92b119c51.mt
      e9f3b8900afa5a2838f0e356b74e30a9.mt
    Manfaat: File .mt dari emulator untuk testing pipeline
    Wajib:   Tidak
    Backup:   Bisa dianggap backup API emulator

  PROJECT/from_termux/
    Fungsi: Skrip dan tools yang dikembangkan/dijalankan dari Termux (Android)
    Isi:
      from_termux/frida/
        frida_dump_decoder.js, frida_trace_bits.js    -> Frida scripts
      from_termux/scripts/
        decode_full.py, extract_mt.py, lmf_decompress.py
        lmf_fix.py, mt_tool.py, mt_tool_v2.py
        roo_parser.py, test_decompress_v4/v6/v9/v12.py
      from_termux/output/
        *_info.json                    -> Output info
      from_termux/test_vectors/
        *.mt.lmf, *.mt.lmf.decompressed, *.mt.luac -> Vektor test
      from_termux/__pycache__/        -> Python bytecode cache (Temporary)
    Manfaat: Tools alternatif dari lingkungan Android
    Wajib:   Tidak

  PROJECT/SESSION/
    Fungsi: Log harian sesi reverse engineering
    Isi:
      SESSION_UTAMA.md              -> Log sesi utama (479 baris, komprehensif)
      SESSION_2026-07-01.txt        -> Log per tanggal
      file_continuing*.txt          -> Catatan kelanjutan
    Manfaat: Catatan progress RE harian
    Wajib:   Tidak
    Hasil Build: Tidak

  PROJECT/RESUME OpenCode/
    Fungsi: Laporan eksekutif untuk OpenCode AI
    Isi:    REPORT.md (358 baris - ringkasan lengkap proyek)
    Manfaat: Dokumentasi untuk AI/kolaborator
    Wajib:   Tidak

  PROJECT/input/  -> KOSONG
    Fungsi: Cadangan untuk input file
    Wajib:   Tidak
    Temporary: Ya (kosong)

  PROJECT/logs/   -> KOSONG
    Fungsi: Cadangan untuk log
    Wajib:   Tidak
    Temporary: Ya (kosong)

  PROJECT/parsed/ -> KOSONG
    Fungsi: Cadangan untuk output parsing
    Wajib:   Tidak
    Temporary: Ya (kosong)

--- KONFIGURASI GIT ---
.gitignore
  Fungsi: Mengatur file apa saja yang tidak di-track Git (91 aturan)
  Isi:    Aturan untuk .so, .apk, hasil decrypt, cache, experiment scripts, dll
  Manfaat: Mencegah file besar/hasil build masuk ke repo

.gitmodules
  Fungsi: Mendefinisikan submodule Git
  Isi:    Dobby (https://github.com/jmpews/Dobby.git)
  Manfaat: Library hooking lintas platform

.github/workflows/build.yml
  Fungsi: CI build GitHub Actions
  Manfaat: Build otomatis
  Wajib:   Tidak

================================================================================
4. HUBUNGAN ANTAR FOLDER (DATA FLOW)
================================================================================

sources/MLADVENTURE.apk
    |
    v
sources/MLADVENTURE2/  (apktool decompile)
    |
    |-- lib/arm64-v8a/*.so  -->  PROJECT/scripts/ (scan, disasm, find_xxtea, dll)
    |-- assets/0-9/*.mt    -->  data/decrypted_output/ (AES decrypt)
    |                              |
    |                              v
    |                         PROJECT/decrypted/dec_batch/ (.mt.dec)
    |                              |
    |                              v
    |                         data/decrypted_output/ (lmF@ decompress)
    |                              |
    |                              v
    |                         PROJECT/scripts/ (roo_parser.py -> parse Roo)
    |                              |
    |                              v
    |                         PROJECT/cache/mla_database.db (SQLite)
    |                              |
    |                              v
    |                         PROJECT/analysis/ (JSON analysis)
    |                         PROJECT/semantic/ (semantic model)
    |
    |-- assets/ -->  data/DEC-ASSET/ (decompress langsung)
    |            -->  data/e/ (sample .mt)
    |            -->  data/mt_dump/ (sample pipeline)

PROJECT/scripts/  <--->  PROJECT/analysis/  (script -> output)
PROJECT/scripts/  <--->  PROJECT/semantic/  (script -> model)
PROJECT/scripts/  <--->  PROJECT/docs/      (analisis -> dokumentasi)
PROJECT/scripts/  <--->  PROJECT/reports/   (diff -> laporan)
PROJECT/scripts/  <--->  PROJECT/emulator_mt/ (testing)

PROJECT/SESSION/  -->  Dokumentasi progress
PROJECT/RESUME OpenCode/ --> Ringkasan untuk kolaborator

================================================================================
5. FILE PENTING
================================================================================

FILE WAJIB (inti proyek):
  sources/MLADVENTURE.apk          -> APK original
  sources/MLADVENTURE2/assets/     -> Data game .mt (input utama)
  sources/MLADVENTURE2/lib/arm64-v8a/libagame.so -> Native library utama
  PROJECT/scripts/                 -> Semua skrip analisis

FILE OUTPUT PENTING:
  PROJECT/cache/mla_database.db    -> Database hasil parsing
  PROJECT/analysis/semantic_analysis.json -> Analisis terlengkap
  PROJECT/semantic/semantic_db_v3.json    -> Model semantic DB

FILE DOKUMENTASI PENTING:
  PROJECT/docs/PIPELINE.md         -> Dokumentasi pipeline
  PROJECT/docs/ROO_FORMAT_SPEC.md  -> Spesifikasi format Roo
  PROJECT/SESSION/SESSION_UTAMA.md -> Log sesi lengkap
  PROJECT/RESUME OpenCode/REPORT.md -> Laporan eksekutif

FILE KEMUNGKINAN TIDAK DIGUNAKAN:
  PROJECT/scripts/tmp_*.py         -> File temporary eksperimen (13 file)
  PROJECT/scripts/_*.py            -> 46 file dengan prefix _ (alternate approach)
  PROJECT/input/                   -> Kosong
  PROJECT/logs/                    -> Kosong
  PROJECT/parsed/                  -> Kosong
  PROJECT/scripts/__pycache__/     -> Cache Python (auto-generated)
  PROJECT/from_termux/__pycache__/ -> Cache Python (auto-generated)
  sources/disassembly_output.txt   -> Mungkin sudah outdated
  sources/lua_offsets.h            -> Referensi offset, mungkin tidak digunakan
                                     langsung oleh script

================================================================================
6. REKOMENDASI STRUKTUR YANG LEBIH RAPI
================================================================================

CATATAN: Rekomendasi ini hanya saran. JANGAN memindahkan/mengubah apapun.
         Jika suatu saat ingin merestruktur, berikut saran organisasi:

Rekomendasi 1: Pisahkan script berdasarkan fungsi
  PROJECT/scripts/ terlalu besar (466 file). Usulan sub-folder:
    scripts/decrypt/       -> Script dekripsi
    scripts/disasm/        -> Script disassembly
    scripts/emu/           -> Script emulasi Unicorn
    scripts/frida/         -> Script Frida hooking
    scripts/parse/         -> Script parsing format
    scripts/analyze/       -> Script analisis database
    scripts/test/          -> Script testing/debug
    scripts/experiment/    -> _*.py dan tmp_*.py (alternate/temporary)

Rekomendasi 2: Pisahkan output berdasarkan tipe
  PROJECT/analysis/        -> Tetap seperti ini
  PROJECT/semantic/        -> Tetap seperti ini
  PROJECT/reports/         -> Tetap seperti ini
  PROJECT/cache/           -> Tetap seperti ini

Rekomendasi 3: Gabungkan folder output dekripsi
  data/decrypted_output/   + PROJECT/decrypted/dec_batch/
  -> Usulan: satukan di data/decrypted/ saja

Rekomendasi 4: Pindahkan tools ke folder tools/
  sources/apktool.jar, sources/libfrida-gadget.so
  -> Usulan: tools/apktool.jar, tools/frida/

Rekomendasi 5: Bersihkan folder kosong
  PROJECT/input/, PROJECT/logs/, PROJECT/parsed/
  -> Hapus jika tidak diperlukan (atau biarkan dengan .gitkeep)

Rekomendasi 6: Satukan dokumentasi
  PROJECT/docs/ + PROJECT/SESSION/ + PROJECT/RESUME OpenCode/
  -> Usulan: docs/ (untuk dokumentasi final), logs/ (untuk session log)

Rekomendasi 7: Pisahkan source APK dan hasil reverse engineering
  sources/ -> simpan APK original dan tools
  Buat folder baru: decompiled/ atau build/ untuk MLADVENTURE2/

Rekomendasi 8: Kelompokkan experiment scripts
  PROJECT/scripts/ memiliki banyak file prefiks _ (46 file) dan tmp_ (13 file).
  Ini adalah experiment/alternate approach yang bisa dipisahkan ke
  scripts/experiments/ atau scripts/archive/.

================================================================================
7. INVENTARIS LENGKAP
================================================================================

Total folder dengan subfolder: 30+
Total file: ~7500+ (termasuk ~7370 file decrypt output dan ~7258 file dec_batch)
Total skrip Python: ~500+
Total dokumentasi (.md/.txt): ~20+
Total database: 1 SQLite (221rb entity)
Total native library: 8 .so (ARM64)

================================================================================
Akhir README
================================================================================
