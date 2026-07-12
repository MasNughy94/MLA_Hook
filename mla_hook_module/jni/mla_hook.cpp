#include "hooking.h"
#include "dobby.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>

namespace mla {

//=============================================================================
// Deferred initialization support
//=============================================================================
#include <pthread.h>
#include <unistd.h>

static volatile bool g_inited = false;

// Forward declaration
bool initialize();

static void* deferred_init_thread(void*) {
    // Wait for libagame.so to finish loading
    sleep(3);

    FILE *f = fopen("/data/data/com.moonton.mobilehero/mla_deferred.txt", "w");
    if (f) { fprintf(f, "deferred init starting, pid=%d\n", getpid()); fclose(f); }

    bool ok = mla::initialize();

    f = fopen("/data/data/com.moonton.mobilehero/mla_deferred.txt", "a");
    if (f) { fprintf(f, "deferred init result: %d\n", ok); fclose(f); }

    g_inited = true;
    return nullptr;
}

static void start_deferred_init() {
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, deferred_init_thread, nullptr);
    pthread_attr_destroy(&attr);
}

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

    //=== FEATURE A: Unlock all heroes + skins ===
    "local hh=HeroHelper\n"
    "if hh and hh.isHeroOwned then\n"
    "hh.isHeroOwned=function()return true end\n"
    "end\n"
    "if hh and hh.getHero then\n"
    "local _gh=hh.getHero\n"
    "hh.getHero=function(s,i)\n"
    "local h=_gh(s,i)\n"
    "if not h and i then\n"
    "h={iHeroId=i,iStar=10,iLevel=250,iBreakLevel=15,\n"
    "iRank=8,iSkinId=0,iEvolutionStage=5,iStep=3,\n"
    "iSkillLevel=1,iPotential=100,isUnlock=true}\n"
    "end\n"
    "return h end\n"
    "end\n"
    "local sd=SkillDisplayHelper\n"
    "if sd and sd.hasSkin then\n"
    "sd.hasSkin=function()return true end\n"
    "end\n"
    "local bm=BattleManager\n"
    "if bm and bm.hasSkin then\n"
    "bm.hasSkin=function()return true end\n"
    "end\n"
    "local fa=FirstChargeActivity\n"
    "if fa and fa.hasHero then\n"
    "fa.hasHero=function()return true end\n"
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
// Shared state
//=============================================================================
static int g_pcall_count = 0;
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
    if (g_pcall_count == 3000 || g_pcall_count % 50000 == 0) {
        g_mod_injected_pcall = false;
        execute_lua_string(L, MOD_LUA_SCRIPT);
    }
    return g_orig_lua_pcall(L, nargs, nresults, errfunc);
}

//=============================================================================
// Hook: luaL_loadbuffer — call original loader (no bytecode patching)
//=============================================================================
static int luaL_loadbuffer_hook(lua_State *L, const char *buff, size_t sz,
                                 const char *name) {
    return g_orig_luaL_loadbuffer(L, buff, sz, name);
}

//=============================================================================
// Initialize
//=============================================================================
bool initialize() {
    g_libagame = dlopen("libagame.so", RTLD_NOW);
    if (!g_libagame) return false;

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

    if (!lua.settop || !lua.pushstring || !lua.loadstring || !lua.pcall)
        return false;

    void *pcall = dlsym(g_libagame, "lua_pcall");
    DobbyHook(pcall, (dobby_dummy_func_t)lua_pcall_hook,
              (dobby_dummy_func_t *)&g_orig_lua_pcall);

    void *loadbuffer = dlsym(g_libagame, "luaL_loadbuffer");
    if (loadbuffer)
        DobbyHook(loadbuffer, (dobby_dummy_func_t)luaL_loadbuffer_hook,
                  (dobby_dummy_func_t *)&g_orig_luaL_loadbuffer);

    return true;
}

void cleanup() {
    // dlclose not needed — we used RTLD_DEFAULT
}

} // namespace mla

__attribute__((constructor))
static void on_load() {
    FILE *f = fopen("/data/data/com.moonton.mobilehero/mla_hook_loaded.txt", "w");
    if (f) { fputs("MLA_Hook constructor running - deferring init\n", f); fclose(f); }
    mla::start_deferred_init();
}

__attribute__((destructor))
static void on_unload() {
    mla::cleanup();
}
