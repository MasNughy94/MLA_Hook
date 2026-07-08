# 04 — DAFTAR FUNGSI GAME YANG DI-HOOK / DIANALISIS

> Dokumentasi fungsi-fungsi game Mobile Legends Adventure yang berhasil diidentifikasi melalui hook MLA_Hook dan hasil dump.

---

## 1. FUNGSI LUA API (C) — Target DobbyHook

Fungsi-fungsi ini adalah **API Lua native** yang di-hook di `libagame.so` oleh Dobby.

| # | Fungsi | Tipe Hook | Nama Simbol | Tujuan Analisis |
|---|--------|-----------|-------------|-----------------|
| 1 | `luaL_loadbuffer` | DobbyHook (intercept) | `luaL_loadbuffer` | Mencegat semua pemuatan skrip Lua → dump bytecode |
| 2 | `lua_pcall` | DobbyHook (intercept) | `lua_pcall` | Mencegat pemanggilan fungsi → dump battle params |
| 3 | `lua_setfield` | DobbyHook (override) | `lua_setfield` | Override field hasil battle + log field formasi |

**Library target:** `libagame.so` — library utama game yang berisi Lua VM 5.1.

---

## 2. FUNGSI LUA API (C) — Resolved via dlsym

Fungsi-fungsi ini tidak di-hook tapi di-resolve dari `libagame.so` untuk digunakan oleh hook.

| # | Fungsi | Critical | Digunakan Untuk |
|---|--------|----------|-----------------|
| 1 | `lua_settop` | ✅ YA | Manajemen stack Lua |
| 2 | `lua_gettop` | ✅ YA | Mendapatkan ukuran stack |
| 3 | `lua_pushstring` | ✅ YA | Push string ke stack |
| 4 | `luaL_loadstring` | ✅ YA | Kompilasi kode Lua (untuk inject mod) |
| 5 | `lua_pcall` | ✅ YA | Eksekusi kode Lua |
| 6 | `lua_pushinteger` | ❌ Tidak | Push integer (untuk force win) |
| 7 | `lua_pushboolean` | ❌ Tidak | Push boolean |
| 8 | `lua_getfield` | ❌ Tidak | Baca field tabel |
| 9 | `lua_setfield` | ❌ Tidak | Tulis field tabel |
| 10 | `lua_tostring` | ❌ Tidak | Konversi value ke string |
| 11 | `lua_gettable` | ❌ Tidak | Baca tabel via key |
| 12 | `lua_settable` | ❌ Tidak | Tulis tabel via key |
| 13 | `lua_next` | ❌ Tidak | Iterasi tabel |
| 14 | `lua_pushnil` | ❌ Tidak | Push nil |
| 15 | `lua_type` | ❌ Tidak | Cek tipe value |
| 16 | `lua_getmetatable` | ❌ Tidak | Baca metatable |
| 17 | `lua_rawgeti` | ❌ Tidak | Baca array index |
| 18 | `lua_rawseti` | ❌ Tidak | Tulis array index |
| 19 | `lua_pushvalue` | ❌ Tidak | Copy value stack |
| 20 | `lua_getinfo` | ❌ Tidak | Debug info fungsi |
| 21 | `lua_pushcclosure` | ❌ Tidak | Buat C closure |
| 22 | `lua_tonumber` | ❌ Tidak | Konversi ke number |
| 23 | `lua_toboolean` | ❌ Tidak | Konversi ke boolean |
| 24 | `lua_tonumber` (fallback) | ❌ Tidak | Cadangan via offset |
| 25 | `lua_tostring` (fallback) | ❌ Tidak | Cadangan via offset |

---

## 3. FUNGSI BATTLE — Target Auto-Win

Fungsi-fungsi ini adalah **fungsi Lua game** yang diidentifikasi dan di-patch oleh injected script untuk auto-win.

### 3.1 Dari MOD_LUA_SCRIPT (BATTLE_NAMES)

| # | Nama Fungsi | Kemungkinan Kegunaan | Status Analisis |
|---|-------------|---------------------|-----------------|
| 1 | `showBattleResult` | Menampilkan hasil battle ke UI | Terpatch (force win) |
| 2 | `onBattleEnd` | Callback saat battle selesai | Terpatch (force win) |
| 3 | `onFightEnd` | Callback saat fight selesai | Terpatch (force win) |
| 4 | `battleEnd` | Event battle selesai | Terpatch (force win) |
| 5 | `BattleEnd` | Variasi kapital | Terpatch (force win) |
| 6 | `onBattleFinish` | Callback battle selesai | Terpatch (force win) |
| 7 | `resultView` | Tampilkan layar hasil | Terpatch (force win) |
| 8 | `showResult` | Tampilkan hasil | Terpatch (force win) |
| 9 | `onStageResult` | Hasil stage (PvE) | Terpatch (force win) |
| 10 | `setResult` | Set hasil pertempuran | Terpatch (force win) |
| 11 | `SetResult` | Variasi kapital | Terpatch (force win) |
| 12 | `finishBattle` | Finalisasi battle | Terpatch (force win) |
| 13 | `onFinishFight` | Finalisasi fight | Terpatch (force win) |
| 14 | `getBattleResult` | Ambil hasil battle | Terpatch (force win) |
| 15 | `recordBattle` | Rekam data battle | Terpatch (force win) |
| 16 | `onResult` | Callback hasil | Terpatch (force win) |
| 17 | `Result` | Fungsi hasil (generik) | Terpatch (force win) |
| 18 | `battleCallback` | Callback battle | Terpatch (force win) |

**Mekanisme patch:** Argumen pertama (`...`) di-override jadi `true`:
```lua
return orig(self, true, ...)  -- force win = true
```

### 3.2 Dari lua_pcall_hook (Battle Detection via getinfo)

Fungsi-fungsi yang namanya mengandung kata kunci tertentu di-log saat dipanggil:

| # | Kata Kunci | Dicari di Nama Fungsi | Tujuan |
|---|-----------|----------------------|--------|
| 1 | `battle` | `strstr(name, "battle")` | Deteksi battle |
| 2 | `Battle` | `strstr(name, "Battle")` | Deteksi battle |
| 3 | `result` | `strstr(name, "result")` | Deteksi result |
| 4 | `Result` | `strstr(name, "Result")` | Deteksi result |
| 5 | `fight` | `strstr(name, "fight")` | Deteksi fight |
| 6 | `Fight` | `strstr(name, "Fight")` | Deteksi fight |
| 7 | `simulate` | `strstr(name, "simulate")` | Deteksi simulasi |
| 8 | `Simulate` | `strstr(name, "Simulate")` | Deteksi simulasi |
| 9 | `win` | `strstr(name, "win")` | Deteksi win |
| 10 | `Win` | `strstr(name, "Win")` | Deteksi win |

---

## 4. FUNGSI VIP — Target Force Level 15

Fungsi-fungsi ini dipatch untuk selalu mengembalikan VIP level 15.

| # | Nama Fungsi | Tujuan Asli | Patched Return |
|---|-------------|-------------|----------------|
| 1 | `isVip` | Cek apakah player VIP | `true` (level 15) |
| 2 | `IsVip` | Variasi kapital | `true` (level 15) |
| 3 | `getVipLevel` | Ambil level VIP | `15` |
| 4 | `getVIPLevel` | Ambil level VIP (kapital) | `15` |
| 5 | `GetVipLevel` | Variasi kapital | `15` |
| 6 | `GetVIPLevel` | Variasi kapital | `15` |
| 7 | `checkVip` | Validasi VIP | `true` |
| 8 | `isVipValid` | Cek apakah VIP masih valid | `true` |
| 9 | `getPlayerVip` | Ambil data VIP player | `15` |

---

## 5. FUNGSI FORMATION — Target Dumping

Field-field yang di-log oleh `lua_setfield_hook` saat di-set ke tabel Lua.

| # | Field Name | Tipe Value (dari log) | Kemungkinan Arti |
|---|-----------|----------------------|------------------|
| 1 | `slot` | number / table | Slot hero di formasi |
| 2 | `position` | number / table | Posisi hero |
| 3 | `formation` | table / string | Data formasi |
| 4 | `lineup` | table | Lineup tim |
| 5 | `deploy` | function / table | Fungsi deploy hero |
| 6 | `team` | table | Tim hero |
| 7 | `Slot` | (kapital) | Variasi penamaan |
| 8 | `SLOT` | (kapital) | Variasi penamaan |
| 9 | `Position` | (kapital) | Variasi penamaan |
| 10 | `Formation` | (kapital) | Variasi penamaan |
| 11 | `FORMATION` | (kapital) | Variasi penamaan |
| 12 | `Lineup` | (kapital) | Variasi penamaan |
| 13 | `LINEUP` | (kapital) | Variasi penamaan |
| 14 | `Deploy` | (kapital) | Variasi penamaan |
| 15 | `Team` | (kapital) | Variasi penamaan |
| 16 | `TEAM` | (kapital) | Variasi penamaan |

---

## 6. FUNGSI BATTLE PARAM — Target Dump (playBattleReport)

Field-field yang diekstrak dari parameter `playBattleReport`.

| # | Field Path | Tipe | Deskripsi |
|---|-----------|------|-----------|
| 1 | `type` | string (LUA_TSTRING) | Tipe battle |
| 2 | `m_iSelectHeroId` | number (LUA_TNUMBER) | ID hero yang dipilih |
| 3 | `stAttackerSide` | table (LUA_TTABLE) | Data tim penyerang |
| 4 | `stAttackerSide.nBorrowedHeroID` | number | ID hero pinjaman |
| 5 | `stAttackerSide.vArrange` | table (array) | Array formasi hero |
| 6 | `vArrange[i].heroId` | number | ID hero di slot i |
| 7 | `vArrange[i].posIndex` | number | Index posisi |
| 8 | `vArrange[i].iArrangeRow` | number | Baris formasi |
| 9 | `vArrange[i].iArrangePos` | number | Kolom/posisi dalam baris |

---

## 7. MODUL GLOBAL GAME — Target Scanning

Modul-modul global Lua yang di-scan oleh injected script untuk mencari fungsi battle & VIP.

| # | Nama Modul | Kemungkinan Isi |
|---|-----------|-----------------|
| 1 | `app` | Aplikasi utama |
| 2 | `game` | Logic game inti |
| 3 | `cc` | Cocos2d-x binding |
| 4 | `fighter` | Data fighter/hero |
| 5 | `Battle` | Battle system |
| 6 | `Fight` | Fight system |
| 7 | `Stage` | Stage/PvE |
| 8 | `Scene` | Scene management |
| 9 | `g_Battle` | Global battle singleton |
| 10 | `g_battle` | Global battle singleton (lowercase) |
| 11 | `Game` | Game controller |
| 12 | `_G` | Global environment (root) |

---

## 8. FILE DUMP — Bukti Eksekusi Hook

### 8.1 File .luac (4904 file)

**Pola penamaan** yang teridentifikasi:

| Pola | Contoh | Jumlah | Arti |
|------|--------|--------|------|
| `{hex}/{hash}.mt.luac` | `0_00d9dec2caa8b5b8389e2fde9227152c.mt.luac` | ~2083 | File .mt hashed (path: `{hex_awal}/{hash}.mt`) |
| `return__{name}_.luac` | `return__10053_.luac` | ~1671 | Kode `return` statement (anonim) |
| `----------__...` | `----------__--_URI_parsing__compos.luac` | ~9 | LuaSocket/mime library modules |
| `require__{path}_.luac` | `require__lua_main_.luac` | ~2 | `require "lua/main"` calls |
| `resInfo___...` | `resInfo___...` | ~4 | Resource info calls |

**LuaSocket modules teridentifikasi:**
- URI parsing
- SMTP/FTP support
- MIME support
- LuaSocket helper
- LTN12 filters
- HTTP 1.1 client
- FTP support
- Canonic header field

### 8.2 pbr_dump.txt (112.508 baris)

**Pola data:**

| Prefix | Jumlah | Arti |
|--------|--------|------|
| `[PBR] LUA_LOAD name={path} size={bytes}` | ~112.500+ | Setiap load buffer |
| `[PBR] === PARAM DUMP ===` | Beberapa | Battle param start marker |
| `[PBR] type=...` | Per battle | Tipe battle |
| `[PBR] m_iSelectHeroId=...` | Per battle | Hero terpilih |
| `[PBR] [N] heroId=... posIndex=...` | Per hero | Data formasi hero |

**Path pattern di pbr_dump.txt:**
- `{hex}/{hash}.mt` — file .mt hashed (sama dengan dump .luac)
- `require "lua/service/..."` — require path
- `require "lua/main"` — entry point
- `return` — return statements

### 8.3 mla_debug.txt (5 baris)

```
MLA Hook v2 initializing...  (×5)
```

Terjadi 5 kali inisialisasi — menandakan:
- Game me-restart atau memuat ulang library
- Atau hook terpicu multiple times dari konstruktor `__attribute__((constructor))`

---

## 9. FIELD-FIELD BARU YANG TERIDENTIFIKASI

Dari hook `lua_setfield`, semua nama field unik yang di-set oleh game dicatat (maks 32 field pertama). Field-field ini memberikan gambaran tentang struktur data game:

| No | Field Terdeteksi | Kemungkinan Fungsi |
|----|-----------------|-------------------|
| 1 | `result` | Hasil battle/action |
| 2 | `isWin` | Flag kemenangan |
| 3 | `win` | Flag win |
| 4 | `slot` | Slot formasi |
| 5 | `position` | Posisi dalam formasi |
| 6 | `team` | Tim |
| 7 | `lineup` | Susunan tim |
| 8 | `formation` | Formasi |
| 9 | `deploy` | Deploy hero |
| (dan seterusnya hingga 32 field) | | |

---

## 10. RINGKASAN FUNGSI GAME YANG SUDAH DIANALISIS

| Fitur Game | Metode Analisis | Status |
|-----------|----------------|--------|
| **Battle Result** | lua_setfield hook (13 field) | ✅ Teridentifikasi |
| **Battle Parameter** | lua_pcall + dump_battle_param | ✅ Teridentifikasi (heroId, pos, dll) |
| **Battle Functions** | Lua mod inject + patch (18 fungsi) | ✅ Teridentifikasi |
| **VIP System** | Lua mod inject + patch (10 fungsi) | ✅ Teridentifikasi |
| **Formation System** | lua_setfield log + Lua scan (17 field) | ✅ Teridentifikasi |
| **Script Loading** | luaL_loadbuffer dump (4904 file) | ✅ Full dump |
| **LuaSocket** | Dump file .luac (9 modul) | ✅ Teridentifikasi |
| **Asset Loading** | PBR log .mt paths | ✅ Pola path hashed |
| **Frida Gadget** | monitor.log | ❌ Gagal inisialisasi |
