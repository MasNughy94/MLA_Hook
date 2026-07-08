# 03 — ALUR HOOK MLA

> Dokumentasi alur kerja hook mulai dari proses **inject** hingga **hook dijalankan**, termasuk diagram alir dan interaksi antar komponen.

---

## 1. DIAGRAM ALUR TINGKAT TINGGI

```
                        ┌─────────────────────────┐
                        │     MLA_Hook (.so)       │
                        │  libmla_hook.so (Dobby)  │
                        └───────────┬─────────────┘
                                    │ dlopen("libagame.so")
                                    ▼
               ┌─────────────────────────────────────┐
               │        libagame.so (Game)            │
               │  ┌───────────────────────────────┐   │
               │  │  Lua VM 5.1 (Cocos2d-x)       │   │
               │  │  luaL_loadbuffer ◄──HOOK──┐   │   │
               │  │  lua_pcall        ◄──HOOK──┤   │   │
               │  │  lua_setfield     ◄──HOOK──┤   │   │
               │  └───────────────────────────────┘   │
               │                                       │
               │  ┌───────────────────────────────┐   │
               │  │  Game Logic (Lua Script)       │   │
               │  │  - Battle system               │   │
               │  │  - VIP system                  │   │
               │  │  - Formation system            │   │
               │  │  - Result handling             │   │
               │  └───────────────────────────────┘   │
               └─────────────────────────────────────┘
                              │
                              ▼
               ┌─────────────────────────────────────┐
               │         Output System                 │
               │  ┌─────────────────────────────┐     │
               │  │  sdcard: mla_dumps/*.luac    │     │
               │  │  sdcard: pbr_dump.txt        │     │
               │  │  sdcard: mla_debug.txt       │     │
               │  │  TCP: localhost:19527        │     │
               │  │  logcat: MLA_Hook / MLA_DBG  │     │
               │  └─────────────────────────────┘     │
               └─────────────────────────────────────┘
```

---

## 2. ALUR INISIALISASI (BOOT)

### Step-by-step inisialisasi:

```
[Game Start]
    │
    ▼
[SO Load: libmla_hook.so]
    │
    ▼
[__attribute__((constructor)) → on_load()]
    │
    ▼
[mla::initialize()]
    │
    ├─ 1. WRITE_DEBUG("MLA Hook v2 initializing...")
    │      → file: mla_debug.txt (append)
    │
    ├─ 2. ensure_dump_dir()
    │      → mkdir /sdcard/.../mla_dumps/
    │      → test write /sdcard/.../mla_dumps/.write_test
    │
    ├─ 3. dlopen("libagame.so", RTLD_NOW)
    │      → Jika gagal: return false (hook gagal total)
    │      → Jika sukses: simpan handle di g_libagame
    │
    ├─ 4. Symbol Resolution (dlsym)
    │   ├─ lua_settop, lua_gettop     → WAJIB
    │   ├─ lua_pushstring             → WAJIB
    │   ├─ luaL_loadstring            → WAJIB
    │   ├─ lua_pcall                  → WAJIB
    │   ├─ lua_pushinteger            → (opsional)
    │   ├─ lua_getfield, lua_setfield → (opsional)
    │   ├─ lua_tostring               → (opsional)
    │   ├─ lua_pushcclosure           → (opsional, fallback offset)
    │   ├─ lua_pushvalue              → (opsional, fallback offset)
    │   ├─ lua_getinfo                → (opsional, fallback offset)
    │   ├─ lua_tonumber               → (opsional, fallback offset)
    │   └─ lua_type, lua_next, dll   → (opsional)
    │
    ├─ 5. Critical symbol check
    │   → Jika lua_settop/lua_pushstring/luaL_loadstring/lua_pcall/lua_gettop NULL:
    │     dlclose + return false
    │
    ├─ 6. DobbyHook #1: lua_pcall
    │   → target: dlsym(g_libagame, "lua_pcall")
    │   → replacement: lua_pcall_hook
    │   → trampoline: &g_orig_lua_pcall
    │
    ├─ 7. DobbyHook #2: luaL_loadbuffer
    │   → target: dlsym(g_libagame, "luaL_loadbuffer")
    │   → replacement: luaL_loadbuffer_hook
    │   → trampoline: &g_orig_luaL_loadbuffer
    │   → Jika gagal: dlclose + return false
    │
    ├─ 8. DobbyHook #3: lua_setfield
    │   → target: dlsym(g_libagame, "lua_setfield")
    │   → replacement: lua_setfield_hook
    │   → trampoline: &g_orig_lua_setfield
    │
    └─ 9. LOGI("MLA Hook v2 initialized")
```

---

## 3. ALUR HOOK `luaL_loadbuffer` (Dump Script)

```
[Game memuat file .mt / script Lua]
    │
    ▼
[luaL_loadbuffer(L, buff, sz, name)]
    │
    ├─ track_lua_state(L)  ← catat pointer unik
    │
    ├─ Cek re-entrancy: g_in_loadbuffer
    │   └─ Jika sudah di dalam hook → panggil original langsung
    │
    ├─ Cek nama == "UpdateAllService"
    │   └─ Jika ya → skip + panggil original
    │
    ├─ LOGI("load: %s (%zu bytes)")  ← logcat
    │
    ├─ panggil g_orig_luaL_loadbuffer(L, buff, sz, name)
    │
    ├─ Cek return value
    │   ├─ Jika ret == 0 (SUKSES):
    │   │   ├─ Cek nama dimulai "if not MLA_MOD" atau "do local _" → skip dump
    │   │   ├─ dump_lua_to_file(name, buff, sz)     → .luac ke sdcard
    │   │   ├─ PBR_TCP("LUA_LOAD name=%s size=%zu") → TCP + pbr_dump.txt
    │   │   └─ LOGI("[LUA_DUMP] Saving: %s (%zu bytes)")
    │   │
    │   └─ Jika ret != 0 (GAGAL):
    │       └─ LOGW("loadbuffer FAIL(%d): %s (%zu bytes)")
    │
    └─ Release re-entrancy guard
    └─ return ret
```

### Output Format di pbr_dump.txt:
```
[PBR] LUA_LOAD name=8/8c7fdcf2f27e51d81e7616a0b5abbf29.mt size=2565
[PBR] LUA_LOAD name=require "lua/main" size=18
[PBR] LUA_LOAD name=return  size=7
```

---

## 4. ALUR HOOK `lua_pcall` (Battle Param Dump)

```
[Game memanggil fungsi Lua]
    │
    ▼
[lua_pcall(L, nargs, nresults, errfunc)]
    │
    ├─ track_lua_state(L)
    │
    ├─ Cek re-entrancy
    │
    ├─ Increment g_pcall_count
    │
    ├─ Jika lua.getinfo tersedia:
    │   ├─ Ambil fungsi dari stack (index: -(nargs+1))
    │   ├─ lua_getinfo(L, ">n", &ar)
    │   ├─ Cek nama fungsi:
    │   │   ├─ "playBattleReport" → dump_battle_param(L, nargs)
    │   │   │   └─ Output ke TCP + pbr_dump.txt:
    │   │   │       [PBR] === PARAM DUMP ===
    │   │   │       [PBR] type=xxx
    │   │   │       [PBR] m_iSelectHeroId=xxx
    │   │   │       [PBR] nBorrowedHeroID=xxx
    │   │   │       [PBR]   [1] heroId=xxx posIndex=xxx arrange=(x,x)
    │   │   │       [PBR] === PARAM DUMP END ===
    │   │   │
    │   │   ├─ battle/Battle/result/Result/fight/Fight/simulate/win/Win
    │   │   │   → LOGI("[BATTLE] %s(nargs=%d)")
    │   │   │
    │   │   └─ Setiap 10000 pcall:
    │   │       LOGI("[CALL] pcall %d: %s")
    │   │
    ├─ Release re-entrancy
    │
    └─ return g_orig_lua_pcall(L, nargs, nresults, errfunc)
```

---

## 5. ALUR HOOK `lua_setfield` (Force Win + Formation Log)

```
[Game meng-set field tabel Lua]
    │
    ▼
[lua_setfield(L, idx, k)]
    │
    ├─ Rate-limited debug: log setiap 50 panggilan
    │
    ├─ Log semua field UNIK (maks 32):
    │   → [SETFIELD_KEY] result
    │   → [SETFIELD_KEY] isWin
    │   → [SETFIELD_KEY] slot
    │   → dst.
    │
    ├─ FORCE WIN (jika g_force_win=true):
    │   FOR each WIN_FIELDS[i]:
    │     if strcmp(k, WIN_FIELDS[i]) == 0:
    │       lua.pushinteger(L, 1)
    │       g_orig_lua_setfield(L, idx, k)
    │       return   ← SKIP original value!
    │
    ├─ LOG FORMATION (jika g_log_formation=true):
    │   FOR each FORMATION_FIELDS[i]:
    │     if strcmp(k, FORMATION_FIELDS[i]) == 0:
    │       log type value → [FORMATION] slot = [number]
    │
    └─ g_orig_lua_setfield(L, idx, k)  ← panggil original
```

### Daftar Field yang Di-override:

| Field WIN | Field FORMATION |
|-----------|-----------------|
| result | slot, Slot, SLOT |
| isWin | position, Position |
| win | formation, Formation, FORMATION |
| fightResult | lineup, Lineup, LINEUP |
| battleResult | deploy, Deploy |
| battle_result | team, Team, TEAM |
| is_win | |
| victory, isVictory | |
| Result, IsWin | |
| success, isSuccess | |

---

## 6. ALUR INJECT LUA MOD SCRIPT

```
[Setelah hook terpasang, saat luaL_loadbuffer pertama sukses]
    │
    ▼
[execute_lua_string(L, MOD_LUA_SCRIPT)]
    │
    ├─ 1. lua_pushcclosure(L, native_log_func, 0)
    │      → Buat fungsi C "mla_log" bisa dipanggil dari Lua
    │
    ├─ 2. lua_setfield(L, LUA_GLOBALSINDEX, "mla_log")
    │      → Registrasi sebagai _G.mla_log
    │
    ├─ 3. luaL_loadstring(L, MOD_LUA_SCRIPT)
    │      → Kompilasi script Lua
    │
    ├─ 4. lua_pcall(L, 0, 0, 0)
    │      → Eksekusi script
    │      → Jika error: log + cleanup stack
    │
    └─ Script melakukan:
        ├─ Set flag MLA_AUTO_WIN = true
        ├─ Set flag MLA_FORCE_VIP = true
        ├─ Set flag MLA_DUMP_FORMATION = true
        ├─ Patch 18 fungsi battle (override arg result jadi true)
        ├─ Scan 12 modul global untuk patch
        ├─ Patch 10 fungsi VIP (return 15)
        └─ Scan formation keywords di _G dan modul
```

---

## 7. ALUR OUTPUT TCP REAL-TIME

```
[Dump event terjadi]
    │
    ▼
[PBR_TCP("LUA_LOAD name=%s size=%zu", ...)]
    │
    ├─ 1. Format string → "[PBR] LUA_LOAD name=... size=..."
    │
    ├─ 2. LOGI("%s", _buf) → logcat
    │
    ├─ 3. tcp_send(_buf)   → kirim ke 127.0.0.1:19527
    │   ├─ socket(AF_INET, SOCK_STREAM, 0)
    │   ├─ connect(127.0.0.1:19527)
    │   ├─ send(msg + "\n")
    │   └─ close(socket)
    │
    └─ 4. file_write(".../pbr_dump.txt", _buf) → append ke file
```

### Port 19527
TCP listener di localhost:19527 memungkinkan **PC host** menerima data real-time melalui **ADB forward**:
```
adb forward tcp:19527 tcp:19527
nc localhost 19527
```

---

## 8. ALUR FRIDA (GAGAL)

```
[monitor.log menunjukkan:]
    │
    ├─ Initial files in dump dir: 0
    ├─ Kill existing game instance
    ├─ Start logcat monitor
    ├─ Launch com.moonton.mobilehero
    ├─ [+0s] NEW DUMP! Total: 1 files (+1)
    ├─ Timeout reached (60 seconds)
    └─ FINAL SUMMARY: NO DUMP FILES OBTAINED

Possible issues (dari log):
  1. Game crashed on startup (black screen)
  2. Frida-gadget not initialized (config issue)
  3. Game integrity check detected modification
  4. No .mt files were loaded during the monitoring period
```

Frida config sudah disiapkan (4 file konfigurasi) tapi hook.js hanya stub. Alur Frida tidak berhasil karena:
1. Frida gadget mungkin tidak ter-inject ke APK
2. Atau game mendeteksi Frida dan crash
3. Atau konfigurasi path tidak sesuai

---

## 9. TIMELINE EKSEKUSI

```
t=0ms     Game start → libmla_hook.so dimuat
t=1ms     on_load() → mla::initialize()
t=5ms     dlopen("libagame.so")
t=10ms    Symbol resolution (24 fungsi)
t=15ms    DobbyHook × 3 (lua_pcall, luaL_loadbuffer, lua_setfield)
t=20ms    Game Lua VM inisialisasi
t=25ms    Lua load first script → luaL_loadbuffer hook aktif
t=26ms    execute_lua_string() → inject mod script
t=30ms    Lua mod script aktif (auto-win, force VIP, formation scan)
t=50ms+   Game running → setiap load → dump .luac
                    → setiap pcall → trace battle
                    → setiap setfield → force win
```

---

## 10. DEPENDENCY GRAPH

```
libmla_hook.so
    ├── libDobby.a (static)       ← Dobby hook framework
    ├── libagame.so (runtime)     ← Target hook
    │   ├── lua_pcall             ← Intercept function call
    │   ├── luaL_loadbuffer       ← Intercept script load
    │   └── lua_setfield          ← Intercept field assignment
    ├── liblog.so (Android NDK)   ← logcat output
    └── libdl.so (Android)        ← dlopen/dlsym
```
