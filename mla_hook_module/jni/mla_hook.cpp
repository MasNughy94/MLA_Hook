#include "hooking.h"
#include "dobby.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>

namespace mla {

//=============================================================================
// Lua API type definitions (Lua 5.1, as used by Cocos2d-x)
//=============================================================================
typedef struct lua_State lua_State;

typedef int   (*luaL_loadbuffer_t)(lua_State *, const char *, size_t, const char *);
typedef int   (*luaL_loadstring_t)(lua_State *, const char *);
typedef int   (*lua_pcall_t)(lua_State *, int, int, int);
typedef void  (*lua_settop_t)(lua_State *, int);
typedef int   (*lua_gettop_t)(lua_State *);
typedef void  (*lua_pushstring_t)(lua_State *, const char *);
typedef void  (*lua_pushinteger_t)(lua_State *, int);
typedef void  (*lua_pushboolean_t)(lua_State *, int);
typedef void  (*lua_getfield_t)(lua_State *, int, const char *);
typedef void  (*lua_setfield_t)(lua_State *, int, const char *);
typedef const char* (*lua_tostring_t)(lua_State *, int);
typedef void  (*lua_gettable_t)(lua_State *, int);
typedef void  (*lua_settable_t)(lua_State *, int);
typedef int   (*lua_next_t)(lua_State *, int);
typedef void  (*lua_pushnil_t)(lua_State *);
typedef int   (*lua_type_t)(lua_State *, int);
typedef int   (*lua_getmetatable_t)(lua_State *, int);
typedef void  (*lua_rawgeti_t)(lua_State *, int, int);
typedef void  (*lua_rawseti_t)(lua_State *, int, int);

//=============================================================================
// Gloabl state
//=============================================================================
static void *g_libagame = nullptr;
static luaL_loadbuffer_t g_orig_luaL_loadbuffer = nullptr;
static lua_pcall_t g_orig_lua_pcall = nullptr;

// Resolved Lua API functions
static struct {
    lua_settop_t        settop;
    lua_gettop_t        gettop;
    lua_pushstring_t    pushstring;
    lua_pushinteger_t   pushinteger;
    lua_pushboolean_t   pushboolean;
    lua_getfield_t      getfield;
    lua_setfield_t      setfield;
    lua_tostring_t      tostring;
    luaL_loadstring_t   loadstring;
    lua_pcall_t         pcall;
    lua_gettable_t      gettable;
    lua_settable_t      settable;
    lua_next_t          next;
    lua_pushnil_t       pushnil;
    lua_type_t          type;
    lua_getmetatable_t  getmetatable;
    lua_rawgeti_t       rawgeti;
    lua_rawseti_t       rawseti;
} lua;

// Injected Lua mod script — overrides hero selection, fuse, idle reward, tower
// All class names are globals registered by MLA's module system
static const char MOD_LUA_SCRIPT[] =
    "if not MLA_MOD then MLA_MOD=true\n"

    // === ORIGINAL: HeroSelectHelper + CommonArrangeHelper overrides ===
    "local h=HeroSelectHelper\n"
    "if h then\n"
    "h.isHeroSelectedEnough=function()return true end\n"
    "h.isHeroSelectedOverLimit=function()return nil end\n"
    "h.hasAlreadySameHero=function()return nil end\n"
    "h.hasArrangeFullTips=function()return nil end\n"
    "end\n"
    "local c=CommonArrangeHelper\n"
    "if c then\n"
    "c.hasAlreadySameHero=function()return nil end\n"
    "c.isHeroSelectedOverLimit=function()return nil end\n"
    "c.isHeroNotOwned=function()return nil end\n"
    "c.isNotOwnedHeroSelected=function()return nil end\n"
    "end\n"

    // === NEW FEATURE 1: DOUBLE IDLE REWARD ===
    "local ih=IdleHelper\n"
    "if ih then\n"
    "ih.getDropActionGoldRandom=function()return 999999 end\n"
    "ih.getDropActionHeroExpRandom=function()return 99999 end\n"
    "ih.getDropActionTeamExpRandom=function()return 99999 end\n"
    "ih.hasReward=function()return true end\n"
    "ih.isRewardTimeFull=function()return true end\n"
    "ih.getIdleMaxTime=function()return 86400 end\n"
    "end\n"

    // === NEW FEATURE 2: FUSION BYPASS (any hero as material) ===
    "local hc=HeroComposeMainPanel\n"
    "if hc then\n"
    "hc.canAddToMaterial=function()return true end\n"
    "hc.isMaterialFull=function()return false end\n"
    "hc.checkMaterialFull=function()return false end\n"
    "end\n"

    // === NEW FEATURE 3: DOUBLE TOWER REWARD ===
    "local tc=CrystalTowerDreamMainPanel\n"
    "if tc and tc.getReward then\n"
    "local gr=tc.getReward\n"
    "tc.getReward=function(s,...)\n"
    "local r=gr(s,...)\n"
    "if type(r)=='table'then\n"
    "for _,v in pairs(r)do\n"
    "if type(v)=='table'and v.amount then v.amount=v.amount*2\n"
    "elseif type(v)=='table'and v.count then v.count=v.count*2 end\n"
    "end end\n"
    "return r end\n"
    "end\n"

    "end\n";

//=============================================================================
// Dump first N bytes of a buffer to logcat
//=============================================================================
static void dump_script(const char *name, const char *buff, size_t sz) {
    if (!buff || sz == 0) return;
    size_t dump = sz > 1024 ? 1024 : sz;
    char line[512];
    for (size_t i = 0; i < dump; i += 64) {
        int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "[%.4zx] ", i);
        for (size_t j = 0; j < 64 && i + j < dump; j++) {
            pos += snprintf(line + pos, sizeof(line) - pos, "%02x",
                           (unsigned char)buff[i + j]);
            if ((j + 1) % 16 == 0) pos += snprintf(line + pos, sizeof(line) - pos, " ");
        }
        pos += snprintf(line + pos, sizeof(line) - pos, "  |");
        for (size_t j = 0; j < 64 && i + j < dump; j++) {
            unsigned char c = buff[i + j];
            pos += snprintf(line + pos, sizeof(line) - pos, "%c",
                           c >= 32 && c <= 126 ? c : '.');
        }
        pos += snprintf(line + pos, sizeof(line) - pos, "|");
        LOGI("  %s", line);
    }
    if (sz > dump) LOGI("  ... (%zu bytes total)", sz);
}

//=============================================================================
// Execute a Lua string on the given state
//=============================================================================
static void execute_lua_string(lua_State *L, const char *code) {
    if (!L || !code) return;

    if (lua.loadstring(L, code) != 0) {
        lua.settop(L, lua.gettop(L) - 1);
        return;
    }
    if (lua.pcall(L, 0, 0, 0) != 0) {
        const char *err = lua.tostring(L, -1);
        if (err) LOGW("Lua mod error: %s", err);
        lua.settop(L, lua.gettop(L) - 1);
    }
}

//=============================================================================
// Shared state
//=============================================================================
static int g_pcall_count = 0;
static bool g_mod_injected = true;       // always ready to inject (pcall hook will trigger)
static bool g_mod_injected_pcall = false; // set true after MOD script was actually executed

//=============================================================================
// Hook: lua_pcall — inject mod (fallback if not already injected by loadbuffer)
//=============================================================================
static int lua_pcall_hook(lua_State *L, int nargs, int nresults, int errfunc) {
    g_pcall_count++;

    // If mod already injected by loadbuffer hook, skip
    if (g_mod_injected_pcall) {
        return g_orig_lua_pcall(L, nargs, nresults, errfunc);
    }

    // Flag ready for injection at pcall #50 (much earlier than old #500!)
    if (g_mod_injected && g_pcall_count > 50) {
        g_mod_injected_pcall = true;
        LOGI("[MLA_MOD] Injecting MOD_LUA_SCRIPT at pcall #%d", g_pcall_count);
        execute_lua_string(L, MOD_LUA_SCRIPT);
    }

    // Retry once more at #500 in case the first attempt was too early
    if (!g_mod_injected_pcall && g_pcall_count > 500) {
        g_mod_injected_pcall = true;
        LOGI("[MLA_MOD] Injecting MOD_LUA_SCRIPT (retry) at pcall #%d", g_pcall_count);
        execute_lua_string(L, MOD_LUA_SCRIPT);
    }

    return g_orig_lua_pcall(L, nargs, nresults, errfunc);
}

//=============================================================================
//=============================================================================
// Bytecode patching: replace "isHeroNotOwned" with "getHeroSelected" in buffer
// Both are 14 chars, no size field change needed
//=============================================================================
#define PATCH_FROM "isHeroNotOwned"
#define PATCH_TO   "getHeroSelected"
#define PATCH_LEN  14

// Simple buffer search (no memmem dependency)
static const char* memfind(const char *haystack, size_t hlen, const char *needle, size_t nlen) {
    if (nlen == 0) return haystack;
    if (hlen < nlen) return nullptr;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (memcmp(haystack + i, needle, nlen) == 0) return haystack + i;
    }
    return nullptr;
}

// Scan buffer for "isHeroNotOwned" and patch to "getHeroSelected"
// Returns: number of patches applied, -1 if no patch needed
static int patch_bytecode(const char **out_buf, const char *in_buf, size_t sz) {
    if (!memfind(in_buf, sz, PATCH_FROM, PATCH_LEN)) return -1;

    char *patched = (char *)malloc(sz);
    if (!patched) return -1;
    memcpy(patched, in_buf, sz);

    int patched_count = 0;
    size_t pos = 0;
    while (pos + PATCH_LEN <= sz) {
        if (memcmp(patched + pos, PATCH_FROM, PATCH_LEN) == 0) {
            // Verify Lua string constant entry: type(1) + size(4) + content
            // type byte at pos-5 must be 4 (string), size at pos-4 must be 15 (14+null)
            if (pos >= 5) {
                uint32_t str_size;
                memcpy(&str_size, patched + pos - 4, sizeof(uint32_t));
                if (str_size == PATCH_LEN + 1 && (uint8_t)patched[pos - 5] == 4) {
                    memcpy(patched + pos, PATCH_TO, PATCH_LEN);
                    patched_count++;
                    pos += PATCH_LEN;
                    continue;
                }
            }
        }
        pos++;
    }

    if (patched_count == 0) {
        free(patched);
        return -1;
    }

    LOGI("[MLA_PATCH] Patched %d occurrence(s) of '%s' -> '%s' in [%zu bytes]",
         patched_count, PATCH_FROM, PATCH_TO, sz);
    *out_buf = patched;
    return patched_count;
}

//=============================================================================
// Hook: luaL_loadbuffer — patch bytecode + inject mod early
//=============================================================================
static int g_load_count = 0;

static int luaL_loadbuffer_hook(lua_State *L, const char *buff, size_t sz,
                                 const char *name) {
    g_load_count++;

    // Skip reflection/self scripts
    if (name && strstr(name, "UpdateAllService")) {
        return g_orig_luaL_loadbuffer(L, buff, sz, name);
    }

    // STEP 1: Patch bytecode — replace "isHeroNotOwned" -> "getHeroSelected"
    const char *patched_buf = nullptr;
    int patch_result = patch_bytecode(&patched_buf, buff, sz);
    const char *load_buf = (patch_result >= 0) ? patched_buf : buff;

    // STEP 2: Early mod injection — inject when we see key helper scripts
    if (!g_mod_injected && name) {
        const char *basename = name;
        const char *slash = strrchr(name, '/');
        if (slash) basename = slash + 1;

        // Trigger injection when any hero/formation/resonance/idle/tower script is loaded
        const char *EARLY_TRIGGERS[] = {
            "HeroSelectHelper", "CommonArrangeHelper",
            "PowerResonanceHelper", "Resonance",
            "IdleHelper", "IdleMoudle",
            "HeroComposeMainPanel", "HeroCompose",
            "CrystalTowerDream", "CrystalTower",
            "formation", "Formation", "hero", "Hero",
            "lineup", "Lineup", "arrange", "Arrange",
            "slot", "Slot", nullptr
        };
        for (int i = 0; EARLY_TRIGGERS[i]; i++) {
            if (strstr(basename, EARLY_TRIGGERS[i])) {
                g_mod_injected = true;
                LOGI("[MLA_MOD] Early inject at '%s' (load #%d)", basename, g_load_count);
                break;
            }
        }
    }

    // STEP 3: Call original loader with potentially patched buffer
    // Inject MOD_LUA_SCRIPT immediately after loading a matching script
    int ret = g_orig_luaL_loadbuffer(L, load_buf, sz, name);

    // Clean up patched buffer copy
    if (patch_result >= 0) free((void *)patched_buf);

    // STEP 4: If ret==0 and we flagged early inject, execute MOD now
    if (ret == 0 && g_mod_injected && !g_mod_injected_pcall) {
        LOGI("[MLA_MOD] Injecting MOD_LUA_SCRIPT at load #%d", g_load_count);
        execute_lua_string(L, MOD_LUA_SCRIPT);
        g_mod_injected_pcall = true;
    }

    // KEYWORD ANALYSIS: dump script content when it contains target keywords
    if (ret == 0 && buff && sz > 0) {
        const char *KEYWORDS[] = {
            "babel", "Babel", "tower", "Tower",
            "fuse", "Fuse", "idle", "Idle",
            "reward", "Reward", "getReward", "showReward",
            "getDropActionGold", "getDropActionHero",
            "claimIdleReward", "canAddToMaterial",
            "isMaterialFull", "onClickCompose",
            "exchangeHybridPiece", "getTowerTblData",
            nullptr
        };
        for (int ki = 0; KEYWORDS[ki]; ki++) {
            if (memfind(buff, sz, KEYWORDS[ki], strlen(KEYWORDS[ki]))) {
                LOGI("[ANALYZE] === Script contains '%s' at load #%d (%s, %zu bytes) ===",
                     KEYWORDS[ki], g_load_count, name ? name : "?", sz);
                dump_script(KEYWORDS[ki], buff, sz);
                break;
            }
        }
    }

    // Reduced logging to avoid spam
    if (ret == 0 && name && g_load_count < 100 && (g_load_count % 20 == 0)) {
        LOGI("load: %s (%zu bytes)", name, sz);
    }
    return ret;
}

//=============================================================================
// Initialize
//=============================================================================
bool initialize() {
    LOGI("MLA Hook v2 initializing...");

    g_libagame = dlopen("libagame.so", RTLD_NOLOAD);
    if (!g_libagame) {
        g_libagame = dlopen("libagame.so", RTLD_NOW);
    }
    if (!g_libagame) {
        LOGE("Failed to open libagame.so: %s", dlerror());
        return false;
    }
    LOGI("libagame.so handle: %p", g_libagame);

    lua.settop      = (lua_settop_t)     dlsym(g_libagame, "lua_settop");
    lua.gettop      = (lua_gettop_t)     dlsym(g_libagame, "lua_gettop");
    lua.pushstring  = (lua_pushstring_t) dlsym(g_libagame, "lua_pushstring");
    lua.pushinteger = (lua_pushinteger_t)dlsym(g_libagame, "lua_pushinteger");
    lua.pushboolean = (lua_pushboolean_t)dlsym(g_libagame, "lua_pushboolean");
    lua.getfield    = (lua_getfield_t)   dlsym(g_libagame, "lua_getfield");
    lua.setfield    = (lua_setfield_t)   dlsym(g_libagame, "lua_setfield");
    lua.tostring    = (lua_tostring_t)   dlsym(g_libagame, "lua_tostring");
    lua.loadstring  = (luaL_loadstring_t)dlsym(g_libagame, "luaL_loadstring");
    lua.pcall       = (lua_pcall_t)      dlsym(g_libagame, "lua_pcall");
    lua.gettable    = (lua_gettable_t)   dlsym(g_libagame, "lua_gettable");
    lua.settable    = (lua_settable_t)   dlsym(g_libagame, "lua_settable");
    lua.next        = (lua_next_t)       dlsym(g_libagame, "lua_next");
    lua.pushnil     = (lua_pushnil_t)    dlsym(g_libagame, "lua_pushnil");
    lua.type        = (lua_type_t)       dlsym(g_libagame, "lua_type");
    lua.getmetatable = (lua_getmetatable_t)dlsym(g_libagame, "lua_getmetatable");
    lua.rawgeti     = (lua_rawgeti_t)    dlsym(g_libagame, "lua_rawgeti");
    lua.rawseti     = (lua_rawseti_t)    dlsym(g_libagame, "lua_rawseti");

    if (!lua.settop || !lua.pushstring || !lua.loadstring || !lua.pcall) {
        LOGE("Failed to resolve Lua API functions");
        dlclose(g_libagame);
        return false;
    }
    LOGI("Lua API functions resolved");

    void *pcall = dlsym(g_libagame, "lua_pcall");
    if (pcall) {
        int ret = DobbyHook(pcall,
                            (dobby_dummy_func_t)lua_pcall_hook,
                            (dobby_dummy_func_t *)&g_orig_lua_pcall);
        if (ret == 0) {
            LOGI("lua_pcall hooked at %p", pcall);
        } else {
            LOGW("lua_pcall DobbyHook failed: ret=%d", ret);
        }
    } else {
        LOGW("Cannot find lua_pcall (dlsym returned null)");
    }

    void *loadbuffer = dlsym(g_libagame, "luaL_loadbuffer");
    if (!loadbuffer) {
        LOGE("Cannot find luaL_loadbuffer");
        dlclose(g_libagame);
        return false;
    }
    LOGI("luaL_loadbuffer at %p", loadbuffer);

    if (DobbyHook(loadbuffer,
                  (dobby_dummy_func_t)luaL_loadbuffer_hook,
                  (dobby_dummy_func_t *)&g_orig_luaL_loadbuffer) != 0) {
        LOGE("Failed to hook luaL_loadbuffer");
    } else {
        LOGI("luaL_loadbuffer hooked successfully");
    }

    LOGI("MLA Hook v2 initialized");
    return true;
}

void cleanup() {
    LOGI("MLA Hook v2 cleanup");
    if (g_libagame) {
        dlclose(g_libagame);
        g_libagame = nullptr;
    }
}

} // namespace mla

__attribute__((constructor))
static void on_load() {
    mla::initialize();
}

__attribute__((destructor))
static void on_unload() {
    mla::cleanup();
}
