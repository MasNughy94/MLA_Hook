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

//=============================================================================
// MOD_LUA_SCRIPT — injected Lua overrides
//   Feature A: Hero select bypass
//   Feature B: Idle reward — hasReward, isRewardTimeFull, getIdleMaxTime
//   Feature C: Fusion bypass
//   Feature D: Double tower reward
//   Feature E: Idle reward multiplier — intercept server response via event,
//              manipulate iIdleStartTime for larger rewards, add bonus items
//   Feature F: Skip battle / battle speed override
//=============================================================================
static const char MOD_LUA_SCRIPT[] =
    "if not MLA_MOD then MLA_MOD=true\n"

    //=== FEATURE A: HeroSelectHelper + CommonArrangeHelper overrides ===
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

    //=== FEATURE B: Idle Helper overrides (UI level) ===
    "local ih=IdleHelper\n"
    "if ih then\n"
    "ih.getDropActionGoldRandom=function()return 999999 end\n"
    "ih.getDropActionHeroExpRandom=function()return 99999 end\n"
    "ih.getDropActionTeamExpRandom=function()return 99999 end\n"
    "ih.hasReward=function()return true end\n"
    "ih.isRewardTimeFull=function()return true end\n"
    "ih.getIdleMaxTime=function()return 604800 end\n"
    "end\n"

    //=== FEATURE C: Fusion bypass ===
    "local hc=HeroComposeMainPanel\n"
    "if hc then\n"
    "hc.canAddToMaterial=function()return true end\n"
    "hc.isMaterialFull=function()return false end\n"
    "hc.checkMaterialFull=function()return false end\n"
    "end\n"

    //=== FEATURE D: Double tower reward ===
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

    //=== FEATURE E: IDLE REWARD MULTIPLIER ===
    // Strategy: override idle info to send older start time to server,
    // hook event to add bonus items, and keep claim always available.
    "local _pdm=mtPlayerDataManager\n"
    "if _pdm then\n"
    "local _gi=_pdm.getStageIdleInfo\n"
    "if _gi then\n"
    "_pdm.getStageIdleInfo=function(s,...)\n"
    "local info=_gi(s,...)\n"
    "if info and info.iIdleStartTime then\n"
    "info.iIdleStartTime=info.iIdleStartTime-86400*14\n"
    "end\n"
    "return info end end\n"
    "local _ghi=_pdm.getHardModeStageIdleInfo\n"
    "if _ghi then\n"
    "_pdm.getHardModeStageIdleInfo=function(s,...)\n"
    "local info=_ghi(s,...)\n"
    "if info and info.iIdleStartTime then\n"
    "info.iIdleStartTime=info.iIdleStartTime-86400*14\n"
    "end\n"
    "return info end end\n"
    "end\n"

    // Hook IdleClaimRewardSuccess event to display extra rewards
    "local _em=mtEventCentre\n"
    "if _em then\n"
    "local _od=_em.dispatchEvent\n"
    "_em.dispatchEvent=function(s,e)\n"
    "if e and e.name=='IdleClaimRewardSuccess' and e.data and e.data.vItem then\n"
    "local vi=e.data.vItem\n"
    "for i=1,#vi do local it=vi[i]\n"
    "if it and it.iNum then it.iNum=it.iNum*10 end end\n"
    "end\n"
    "return _od(s,e)end\n"
    "end\n"

    //=== FEATURE F: BATTLE SPEED & SKIP ===
    "local im=IdleMoudle\n"
    "if im and im.getIdleAnimName then\n"
    "im.getIdleAnimName=function()return 'idle_speed' end\n"
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
// Shared state
//=============================================================================
static int g_pcall_count = 0;
static bool g_mod_injected = false;
static bool g_mod_injected_pcall = false;

//=============================================================================
// Execute a Lua string on the given state
//=============================================================================
static void execute_lua_string(lua_State *L, const char *code) {
    if (!L || !code) return;
    if (g_mod_injected_pcall) return;

    LOGI("[MLA_MOD] Injecting MOD_LUA_SCRIPT");
    g_mod_injected_pcall = true;

    if (lua.loadstring(L, code) != 0) {
        lua.settop(L, lua.gettop(L) - 1);
        return;
    }
    if (lua.pcall(L, 0, 0, 0) != 0) {
        lua.settop(L, lua.gettop(L) - 1);
    }
}

//=============================================================================
// Hook: lua_pcall — inject mod (fallback if not already injected by loadbuffer)
//=============================================================================
static int lua_pcall_hook(lua_State *L, int nargs, int nresults, int errfunc) {
    g_pcall_count++;
    if (g_pcall_count == 500) {
        execute_lua_string(L, MOD_LUA_SCRIPT);
    }
    return g_orig_lua_pcall(L, nargs, nresults, errfunc);
}

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
static int luaL_loadbuffer_hook(lua_State *L, const char *buff, size_t sz,
                                 const char *name) {

    // STEP 1: Patch bytecode — replace "isHeroNotOwned" -> "getHeroSelected"
    const char *patched_buf = nullptr;
    int patch_result = patch_bytecode(&patched_buf, buff, sz);
    const char *load_buf = (patch_result >= 0) ? patched_buf : buff;

    // STEP 2: Call original loader with potentially patched buffer
    int ret = g_orig_luaL_loadbuffer(L, load_buf, sz, name);

    // Clean up patched buffer copy
    if (patch_result >= 0) free((void *)patched_buf);

    // STEP 3: Inject MOD_LUA_SCRIPT (execute_lua_string guards via g_mod_injected_pcall)
    if (ret == 0) {
        execute_lua_string(L, MOD_LUA_SCRIPT);
    }

    return ret;
}

//=============================================================================
// Initialize
//=============================================================================
bool initialize() {
    // Write debug marker
    FILE *f = fopen("/data/data/com.moonton.mobilehero/mla_init_marker.txt", "w");
    if (f) { fputs("initialize() started\n", f); fclose(f); }

    // Use RTLD_DEFAULT — we're loaded as DT_NEEDED of libagame.so,
    // so all its symbols are visible.  Don't dlopen("libagame.so") because
    // we are running DURING its loading (constructor order), causing deadlock.
    lua.settop      = (lua_settop_t)     dlsym(RTLD_DEFAULT, "lua_settop");
    lua.gettop      = (lua_gettop_t)     dlsym(RTLD_DEFAULT, "lua_gettop");
    lua.pushstring  = (lua_pushstring_t) dlsym(RTLD_DEFAULT, "lua_pushstring");
    lua.pushinteger = (lua_pushinteger_t)dlsym(RTLD_DEFAULT, "lua_pushinteger");
    lua.pushboolean = (lua_pushboolean_t)dlsym(RTLD_DEFAULT, "lua_pushboolean");
    lua.getfield    = (lua_getfield_t)   dlsym(RTLD_DEFAULT, "lua_getfield");
    lua.setfield    = (lua_setfield_t)   dlsym(RTLD_DEFAULT, "lua_setfield");
    lua.tostring    = (lua_tostring_t)   dlsym(RTLD_DEFAULT, "lua_tostring");
    lua.loadstring  = (luaL_loadstring_t)dlsym(RTLD_DEFAULT, "luaL_loadstring");
    lua.pcall       = (lua_pcall_t)      dlsym(RTLD_DEFAULT, "lua_pcall");
    lua.gettable    = (lua_gettable_t)   dlsym(RTLD_DEFAULT, "lua_gettable");
    lua.settable    = (lua_settable_t)   dlsym(RTLD_DEFAULT, "lua_settable");
    lua.next        = (lua_next_t)       dlsym(RTLD_DEFAULT, "lua_next");
    lua.pushnil     = (lua_pushnil_t)    dlsym(RTLD_DEFAULT, "lua_pushnil");
    lua.type        = (lua_type_t)       dlsym(RTLD_DEFAULT, "lua_type");
    lua.getmetatable = (lua_getmetatable_t)dlsym(RTLD_DEFAULT, "lua_getmetatable");
    lua.rawgeti     = (lua_rawgeti_t)    dlsym(RTLD_DEFAULT, "lua_rawgeti");
    lua.rawseti     = (lua_rawseti_t)    dlsym(RTLD_DEFAULT, "lua_rawseti");

    f = fopen("/data/data/com.moonton.mobilehero/mla_init_marker.txt", "a");
    if (f) { fprintf(f, "dlsym complete: settop=%p pcall=%p loadstring=%p\n", (void*)lua.settop, (void*)lua.pcall, (void*)lua.loadstring); fclose(f); }

    if (!lua.settop || !lua.pushstring || !lua.loadstring || !lua.pcall) {
        f = fopen("/data/data/com.moonton.mobilehero/mla_init_marker.txt", "a");
        if (f) { fprintf(f, "FAILED: essential Lua symbols not resolved\n"); fclose(f); }
        return false;
    }

    void *pcall = (void*)lua.pcall;
    if (pcall) {
        int ret = DobbyHook(pcall,
                            (dobby_dummy_func_t)lua_pcall_hook,
                            (dobby_dummy_func_t *)&g_orig_lua_pcall);
        f = fopen("/data/data/com.moonton.mobilehero/mla_init_marker.txt", "a");
        if (f) { fprintf(f, "DobbyHook lua_pcall ret=%d (0=OK)\n", ret); fclose(f); }
    }

    void *loadbuffer = dlsym(RTLD_DEFAULT, "luaL_loadbuffer");
    if (!loadbuffer) {
        f = fopen("/data/data/com.moonton.mobilehero/mla_init_marker.txt", "a");
        if (f) { fprintf(f, "FAILED: luaL_loadbuffer not found\n"); fclose(f); }
        return false;
    }

    if (DobbyHook(loadbuffer,
                  (dobby_dummy_func_t)luaL_loadbuffer_hook,
                  (dobby_dummy_func_t *)&g_orig_luaL_loadbuffer) != 0) {
        f = fopen("/data/data/com.moonton.mobilehero/mla_init_marker.txt", "a");
        if (f) { fprintf(f, "FAILED: DobbyHook luaL_loadbuffer failed\n"); fclose(f); }
    } else {
        f = fopen("/data/data/com.moonton.mobilehero/mla_init_marker.txt", "a");
        if (f) { fprintf(f, "SUCCESS: both hooks installed\n"); fclose(f); }
    }

    f = fopen("/data/data/com.moonton.mobilehero/mla_init_marker.txt", "a");
    if (f) { fprintf(f, "initialize() completed\n"); fclose(f); }
    return true;
}

void cleanup() {
    // dlclose not needed — we used RTLD_DEFAULT
}

} // namespace mla

__attribute__((constructor))
static void on_load() {
    // Marker: constructor running
    FILE *f = fopen("/data/data/com.moonton.mobilehero/mla_hook_loaded.txt", "w");
    if (f) { fputs("MLA_Hook constructor running\n", f); fclose(f); }
    mla::initialize();
}

__attribute__((destructor))
static void on_unload() {
    mla::cleanup();
}
