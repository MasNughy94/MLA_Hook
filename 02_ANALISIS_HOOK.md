# 02 — ANALISIS HOOK MLA

> Analisis mendalam arsitektur, mekanisme, dan komponen **MLA_Hook** (dari repo `MasNughy94/MLA_Hook`) serta hubungannya dengan hasil dump di project lokal.

---

## 1. ARSITEKTUR MLA_Hook

### 1.1 Stack Teknologi

| Komponen | Detail |
|----------|--------|
| **Framework Hook** | [Dobby](https://github.com/jmpews/Dobby) — lightweight hook library untuk ARM64/ARM |
| **Target Library** | `libagame.so` — library utama game Moonton (berisi Lua VM + game logic) |
| **Bahasa** | C++17 + C11 |
| **Build System** | CMake 3.18+ dengan Android NDK r27c |
| **Target ABI** | `arm64-v8a` (Android 64-bit) |
| **Target API** | Android 24 (Android 7.0) |
| **Logging** | logcat (ANDROID_LOG_INFO), file sdcard, TCP socket |

### 1.2 Struktur File Repository

```
MLA_Hook/
├── .github/workflows/build.yml     # GitHub Actions CI (Ubuntu)
├── .gitignore
├── GUIDE.md                         # Panduan build portable
├── build_android.ps1                # Build script Windows PowerShell
└── module/
    ├── CMakeLists.txt               # Build config CMake
    ├── download_prebuilt.ps1        # Download Dobby prebuilt (Windows)
    ├── download_prebuilt.sh         # Download Dobby prebuilt (Linux)
    ├── include/
    │   └── hooking.h                # Header: log macros + namespace
    ├── src/
    │   └── main.cpp                 # ** KODE UTAMA HOOK ** (1674 baris)
    ├── Dobby/include/
    │   └── dobby.h                  # Header Dobby API
    └── prebuilt/arm64-v8a/
        ├── libDobby.a               # Dobby static library
        └── libDobby.so              # Dobby shared library
```

### 1.3 Ukuran & Kompleksitas

| Metrik | Nilai |
|--------|-------|
| Baris kode main.cpp | ~1.674 baris |
| Jumlah fungsi hook | 3 (luaL_loadbuffer, lua_pcall, lua_setfield) |
| Jumlah fungsi helper | ~12 (dump_script, dump_lua_to_file, tcp_send, execute_lua_string, dll) |
| Jumlah fungsi Lua yang didefinisikan | 24 typedef (Lua 5.1 API) |
| Jumlah field WIN yang dicari | 13 |
| Jumlah field FORMATION yang dicari | 17 |
| Jumlah nama battle yang dipatch | 18 |
| Jumlah VIP function yang dipatch | 10 |
| Jumlah modul global yang di-scan | 12 |

---

## 2. MEKANISME HOOK

### 2.1 Initialization (`mla::initialize()`)

1. **Buka `libagame.so`** via `dlopen("libagame.so", RTLD_NOW)`
2. **Resolve simbol Lua API** — 24 fungsi Lua di-cari via `dlsym()` dari `libagame.so` dan `RTLD_DEFAULT`
3. **Fallback offset** — beberapa simbol (pushvalue, getinfo, pushcclosure, tonumber, tostring) punya fallback berbasis offset dari `lua_pcall` (hardcoded address — **brittle!**)
4. **Pasang 3 DobbyHook** — `lua_pcall`, `luaL_loadbuffer`, `lua_setfield`
5. **Tulis debug** ke `/sdcard/.../mla_debug.txt`
6. **Buat directory dump** `/sdcard/.../mla_dumps/`

### 2.2 Lua Symbol Resolution Detail

```cpp
void *pcall_addr = dlsym(g_libagame, "lua_pcall");
void *lb_addr = dlsym(g_libagame, "luaL_loadbuffer");
void *sf_addr = dlsym(g_libagame, "lua_setfield");
```

Untuk simbol yang tidak ditemukan langsung, digunakan **offset-based addressing**:
```cpp
lua.pushvalue = (lua_pushvalue_t)((uintptr_t)_base + 0x006681b4 - 0x006693a8);
```
Ini mengasumsikan base address `lua_pcall` + offset tetap — **sangat rentan terhadap perubahan versi game**.

### 2.3 Re-entrancy Guard

Dua variabel `volatile int` digunakan sebagai **spinlock** untuk mencegah infinite loop:
- `g_in_loadbuffer` — melindungi `luaL_loadbuffer_hook`
- `g_in_pcall` — melindungi `lua_pcall_hook`

Mekanisme: `__sync_lock_test_and_set()` + `__sync_lock_release()` (GCC atomic builtins).

---

## 3. HOOK DETAIL

### 3.1 Hook #1: `luaL_loadbuffer_hook`

**Tujuan:** Mencegat semua pemuatan skrip Lua oleh game.

**Alur:**
1. Track lua_State unik (maks 16 via `g_seen_lua_states`)
2. Cek re-entrancy guard (skip jika `g_in_loadbuffer` aktif)
3. Skip khusus untuk "UpdateAllService"
4. Panggil `g_orig_luaL_loadbuffer()` asli
5. Jika sukses (ret == 0):
   - **Dump bytecode** ke sdcard via `dump_lua_to_file()` → `/sdcard/.../mla_dumps/<name>.luac`
   - **Kirim TCP** via `tcp_send()` ke localhost:19527 dengan format `[PBR] LUA_LOAD name=... size=...`
   - **Tulis file** `pbr_dump.txt` di sdcard

**Yang di-dump:** SEMUA skrip Lua yang berhasil di-load — termasuk file `.mt`, string `require`, `return`, dan kode inline.

**Rate limiter debug:** log setiap 500 panggilan.

### 3.2 Hook #2: `lua_pcall_hook`

**Tujuan:** Mencegat pemanggilan fungsi Lua, terutama `playBattleReport`.

**Alur:**
1. Track lua_State
2. Cek re-entrancy
3. Jika fungsi memiliki nama yang mengandung "playBattleReport" → panggil `dump_battle_param()`
4. Log fungsi yang mengandung kata: battle, Battle, result, Result, fight, Fight, simulate, win, Win
5. Hitung total pcall (via `g_pcall_count`)

**Fungsi `dump_battle_param()`:**
- Baca parameter posisional
- Ekstrak: `type`, `m_iSelectHeroId`, `stAttackerSide`
- Iterasi `vArrange` array untuk setiap hero: `heroId`, `posIndex`, `iArrangeRow`, `iArrangePos`
- Format output: `[PBR]` prefix → TCP + file

**Rate limiter:** log setiap 50 panggilan.

### 3.3 Hook #3: `lua_setfield_hook`

**Tujuan:** Dua fungsi sekaligus.

**Fungsi A — FORCE WIN:**
- Saat field di-set dengan nama yang cocok dengan `WIN_FIELDS[]`, push integer `1` sebagai gantinya
- Ini membuat game selalu mendeteksi kemenangan dalam pertempuran

```cpp
static const char *WIN_FIELDS[] = {
    "result", "isWin", "win", "fightResult",
    "battleResult", "battle_result", "is_win",
    "victory", "isVictory", "Result", "IsWin",
    "success", "isSuccess", nullptr
};
```

**Fungsi B — LOG FORMATION:**
- Saat field di-set dengan nama yang cocok dengan `FORMATION_FIELDS[]`, log tipe nilainya
- Membantu reverse engineer struktur data formasi battle

```cpp
static const char *FORMATION_FIELDS[] = {
    "slot", "Slot", "SLOT", "position", "Position",
    "formation", "Formation", "FORMATION",
    "lineup", "Lineup", "LINEUP", "deploy", "Deploy",
    "team", "Team", "TEAM", nullptr
};
```

**Fungsi C — LOG ALL UNIQUE KEYS:**
- Semua nama field unik yang pernah di-setfield dicatat (maks 32)
- Ini membantu menemukan field-field penting yang digunakan game

---

## 4. INJECTED LUA MOD SCRIPT

Selain hook C++, MLA_Hook juga **menyuntikkan script Lua** ke runtime game melalui `execute_lua_string()`.

### 4.1 MOD_LUA_SCRIPT — Fitur

| Fitur | Deskripsi |
|-------|-----------|
| **MLA_AUTO_WIN** | Mencari fungsi battle result di global table dan memaksa argumen `true` |
| **MLA_FORCE_VIP** | Mencari fungsi VIP (isVip, getVipLevel, dll) dan mengembalikan `15` |
| **MLA_DUMP_FORMATION** | Scan global & modul tabel untuk field formasi dan log strukturnya |
| **mla_log()** | Fungsi native C yang diregistrasi ke Lua sebagai `_G.mla_log` |

### 4.2 Nama Fungsi Battle yang Dipatch

```lua
BATTLE_NAMES = {
    'showBattleResult', 'onBattleEnd', 'onFightEnd',
    'battleEnd', 'BattleEnd', 'onBattleFinish',
    'resultView', 'showResult', 'onStageResult',
    'setResult', 'SetResult', 'finishBattle',
    'onFinishFight', 'getBattleResult', 'recordBattle',
    'onResult', 'Result', 'battleCallback',
}
```

### 4.3 Modul Global yang di-scan

```lua
MODULES = { 'app', 'game', 'cc', 'fighter',
            'Battle', 'Fight', 'Stage', 'Scene',
            'g_Battle', 'g_battle', 'Game' }
```

---

## 5. MEKANISME OUTPUT

### 5.1 Triple Output System

| Metode | Destinasi | Format | Latency |
|--------|-----------|--------|---------|
| **logcat** | Android log | `[MLA_Hook]` / `[MLA_DBG]` / `[PBR]` | Real-time |
| **File sdcard** | `/sdcard/.../mla_dumps/*.luac` | Bytecode dump | Batch |
| **TCP Socket** | localhost:19527 | `[PBR] ...` line | Real-time |
| **File append** | `/sdcard/.../pbr_dump.txt` | `[PBR] ...` line | Append |
| **File debug** | `/sdcard/.../mla_debug.txt` | Debug init log | Append |

### 5.2 Deduplikasi File Dump

Fungsi `dump_lua_to_file()` sudah memiliki deduplikasi:
- Gunakan `stat()` untuk cek file yang sudah ada dengan _ukuran sama_ — skip jika ada
- Gunakan `pthread_mutex_lock` untuk thread safety
- Sanitasi nama file (ganti karakter ilegal dengan `_`)

---

## 6. ANALISIS FRIDA CONFIG (dumps/frida_config/)

### 6.1 File Konfigurasi

| File | Path hook.js | Tipe |
|------|-------------|------|
| `frida_config.json` | `/storage/emulated/0/MLADVENTURE_DUMP/hook.js` | File lokal |
| `frida_config2.json` | `/data/data/com.moonton.mobilehero/files/frida/hook.js` | Internal app |
| `frida_config3.json` | `/data/local/tmp/hook.js` | tmp directory |
| `listen_config.json` | — (listen mode) | TCP listen |

### 6.2 hook.js

```javascript
throw "SCRIPT_IS_ALIVE_AND_RUNNING";
```

Hanya stub — script tidak melakukan hook apa pun. Ini placeholder / test script untuk memverifikasi Frida gadget berfungsi.

### 6.3 monitor.log

**Status: GAGAL.** Log menunjukkan:
- Game diluncurkan
- 1 file dump terdeteksi
- 60 detik monitoring: **"NO DUMP FILES OBTAINED"**
- Kemungkinan: game crash, integrity check, atau Frida gadget tidak terinisialisasi

---

## 7. TIPE HOOK BERDASARKAN LAPISAN

| Lapisan | Metode Hook | Status |
|---------|-------------|--------|
| **Lua (C API)** | DobbyHook → `luaL_loadbuffer`, `lua_pcall`, `lua_setfield` di `libagame.so` | ✅ Berfungsi |
| **Lua (Script)** | Inject script via `luaL_loadstring` + `lua_pcall` → patch global functions | ✅ Berfungsi |
| **Native Library (.so)** | DobbyHook framework → hook fungsi C di `libagame.so` | ✅ Berfungsi |
| **IL2CPP** | Tidak ada hook IL2CPP | ❌ Tidak diterapkan |
| **Unity Engine** | Tidak ada hook Unity langsung | ❌ Tidak diterapkan |
| **Frida Gadget** | Config file siap, hook.js hanya stub | ❌ Gagal inisialisasi |

**Kesimpulan:** MLA_Hook bekerja secara **kombinasi native + Lua** dengan DobbyHook sebagai fondasi. Frida disiapkan tapi tidak berfungsi.

---

## 8. REUSABLE CODE PATTERNS

| Pattern | Lokasi | Reusable untuk |
|---------|--------|----------------|
| **DobbyHook wrapper** | `DobbyHook(target, replacement, &orig)` | Setiap hook fungsi native |
| **Re-entrancy guard** | `__sync_lock_test_and_set` + `__sync_lock_release` | Mencegah infinite loop hook |
| **TCP sender** | `tcp_send()` + `PBR_TCP` macro | Real-time data streaming |
| **File dumper** | `dump_lua_to_file()` + mutex | Thread-safe file I/O |
| **Rate-limited logging** | `dbg_log_rate(counter, interval, ...)` | Debug tanpa spam logcat |
| **Lua API function table** | `struct lua { ... }` + `dlsym` resolvers | Akses Lua API dari native |
| **Fallback offset resolver** | Base address + hardcoded offset | Jika dlsym gagal (tapi brittle!) |
| **Lua mod injector** | `execute_lua_string()` + native C closure | Inject kode Lua dari C |
