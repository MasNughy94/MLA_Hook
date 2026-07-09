#include "hooking.h"
#include "dobby.h"

#include <cstring>
#include <cstdio>
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

// Injected Lua mod script — overrides HeroSelectHelper/CommonArrangeHelper
// to allow duplicate heroes, bypass count checks, and auto-fill strongest hero
static const char MOD_LUA_SCRIPT[] =
    "if not MLA_MOD then MLA_MOD=true\n"
    "local prh=PowerResonanceHelper\n"
    "if prh and prh.checkAuraCondition then prh.checkAuraCondition=function()return true end end\n"
    "local h=HeroSelectHelper\n"
    "if h then\n"
    "h.isHeroSelectedEnough=function()return true end\n"
    "h.isHeroSelectedOverLimit=function()return false end\n"
    "h.hasAlreadySameHero=function()return false end\n"
    "h.hasArrangeFullTips=function()return false end\n"
    "end\n"
    "local c=CommonArrangeHelper\n"
    "if c then\n"
    "c.hasAlreadySameHero=function()return false end\n"
    "c.isHeroSelectedOverLimit=function()return false end\n"
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
// Hook: lua_pcall — inject mod once when Lua environment is stable
//=============================================================================
static int g_pcall_count = 0;
static bool g_mod_injected = false;

static int lua_pcall_hook(lua_State *L, int nargs, int nresults, int errfunc) {
    g_pcall_count++;

    // Inject MOD_LUA_SCRIPT once at pcall #500 (sets up MLA_MOD flag)
    if (!g_mod_injected && g_pcall_count > 500) {
        g_mod_injected = true;
        LOGI("[MLA_MOD] Injecting MOD_LUA_SCRIPT at pcall #%d", g_pcall_count);
        execute_lua_string(L, MOD_LUA_SCRIPT);
    }

    // Retry helper patching every 100 pcalls after #500 until both are patched
    if (g_mod_injected && g_pcall_count > 500 && g_pcall_count % 100 == 0) {
        execute_lua_string(L, MOD_LUA_SCRIPT);
    }

    return g_orig_lua_pcall(L, nargs, nresults, errfunc);
}

//=============================================================================
// Hook: luaL_loadbuffer — dump scripts matching formation/slot/lineup keywords
//=============================================================================
static int luaL_loadbuffer_hook(lua_State *L, const char *buff, size_t sz,
                                 const char *name) {
    if (name && strstr(name, "UpdateAllService")) {
        return g_orig_luaL_loadbuffer(L, buff, sz, name);
    }

    const char *n = name ? name : "?";
    if (sz > 0 && sz < 256) {
        LOGI("load: %s (%zu bytes)", n, sz);
    } else {
        LOGI("load: [%zu bytes]", sz);
    }

    int ret = g_orig_luaL_loadbuffer(L, buff, sz, name);

    if (ret == 0) {
        if (name) {
            if (strncmp(name, "if not MLA_MOD", 14) == 0) return ret;
            if (strncmp(name, "do local _", 10) == 0) return ret;
        }

        // Formation/lineup/slot keywords for dumping
        const char *FORMATION_KEYWORDS[] = {
            "formation", "Formation", "FORMATION",
            "lineup", "Lineup", "LINEUP",
            "slot", "Slot", "SLOT",
            "deploy", "Deploy", "DEPLOY",
            "position", "Position",
            "team", "Team", "TEAM",
            "battle", "Battle", "BATTLE",
            "result", "Result",
            "fight", "Fight",
            "arena", "Arena",
            "pvp", "Pvp", "PVP",
            "campaign", "Campaign",
            nullptr
        };

        const char *basename = name;
        const char *slash = strrchr(name, '/');
        if (slash) basename = slash + 1;

        bool dump = false;
        for (int i = 0; FORMATION_KEYWORDS[i]; i++) {
            if (strstr(basename, FORMATION_KEYWORDS[i])) {
                dump = true;
                LOGI("=== FORMATION MATCH: %s (%zu bytes) ===", name, sz);
                break;
            }
        }

        if (dump) {
            dump_script(name, buff, sz);
            return ret;
        }

        // Unnamed large scripts
        if (!name || name[0] == '\0') {
            if (sz > 1024) {
                size_t dump = sz > 512 ? 512 : sz;
                LOGI("=== Unnamed script (%zu bytes) - first %zu bytes ===", sz, dump);
                char line[1024];
                for (size_t i = 0; i < dump; i += 128) {
                    size_t remain = dump - i;
                    size_t copy = remain > 127 ? 127 : remain;
                    memcpy(line, buff + i, copy);
                    line[copy] = '\0';
                    for (size_t j = 0; j < copy; j++) {
                        if (line[j] < 32 && line[j] != '\n' && line[j] != '\t') line[j] = '.';
                    }
                    LOGI("  %s", line);
                }
            }
            return ret;
        }

        // Also dump battle/result/fight/vip scripts (original behavior)
        if (strstr(basename, "battle") || strstr(basename, "Battle") ||
            strstr(basename, "result") || strstr(basename, "Result") ||
            strstr(basename, "fight") || strstr(basename, "Fight") ||
            strstr(basename, "vip") || strstr(basename, "Vip") || strstr(basename, "VIP") ||
            strstr(basename, "shop") || strstr(basename, "Shop") ||
            strstr(basename, "gacha") || strstr(basename, "Gacha") ||
            strstr(basename, "gashapon") || strstr(basename, "Gashapon")) {
            LOGI("=== Dumping %s (%zu bytes) ===", name, sz);
            dump_script(name, buff, sz);
        }

        if (strstr(basename, "main") || strstr(basename, "init") || strstr(basename, "App") ||
            strstr(basename, "start") || strstr(basename, "boot") || strstr(basename, "login")) {
            LOGI("Found startup script: %s", name);
        }

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
        if (DobbyHook(pcall,
                      (dobby_dummy_func_t)lua_pcall_hook,
                      (dobby_dummy_func_t *)&g_orig_lua_pcall) == 0) {
            LOGI("lua_pcall hooked");
        }
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
