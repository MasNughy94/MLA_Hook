/*
 * mla_hook.c  -  DobbyHook-based Lua function interception for MLA
 *
 * Hooks lua_getfield (hero stat maxing) and lua_rawgeti (hero roster replacement)
 * using static offsets from libagame.so + DobbyGetLibraryBase.
 *
 * Build: NDK arm64-v8a, link Dobby as a submodule.
 * Target: Cocos2d-x Lua (not Unity/IL2CPP).
 */

#include "mla_offsets.h"
#include "dobby.h"

#include <string.h>
#include <stdint.h>
#include <inttypes.h>

/* ===================================================================
 *  Lua type / struct forward decls
 * =================================================================== */
typedef struct lua_State lua_State;

/* ===================================================================
 *  Lua C API function-pointer typedefs
 * =================================================================== */
typedef int           (*lua_gettop_t)(lua_State *);
typedef void          (*lua_settop_t)(lua_State *, int);
typedef int           (*lua_type_t)(lua_State *, int);
typedef const char   *(*lua_tolstring_t)(lua_State *, int, size_t *);
typedef int           (*lua_tointeger_t)(lua_State *, int);
typedef void          (*lua_pushnil_t)(lua_State *);
typedef void          (*lua_pushinteger_t)(lua_State *, int);
typedef void          (*lua_pushnumber_t)(lua_State *, double);
typedef void          (*lua_pushstring_t)(lua_State *, const char *);
typedef void          (*lua_pushvalue_t)(lua_State *, int);
typedef void          (*lua_getfield_t)(lua_State *, int, const char *);
typedef void          (*lua_rawget_t)(lua_State *, int);
typedef void          (*lua_rawgeti_t)(lua_State *, int, int);
typedef void          (*lua_setfield_t)(lua_State *, int, const char *);
typedef int           (*lua_pcall_t)(lua_State *, int, int, int);

/* ===================================================================
 *  Runtime-resolved function pointers (set once in mla_init)
 * =================================================================== */
static lua_gettop_t      real_lua_gettop      = NULL;
static lua_settop_t      real_lua_settop      = NULL;
static lua_type_t        real_lua_type        = NULL;
static lua_tolstring_t   real_lua_tolstring   = NULL;
static lua_tointeger_t   real_lua_tointeger   = NULL;
static lua_pushnil_t     real_lua_pushnil     = NULL;
static lua_pushinteger_t real_lua_pushinteger = NULL;
static lua_pushstring_t  real_lua_pushstring  = NULL;
static lua_pushvalue_t   real_lua_pushvalue   = NULL;
static lua_getfield_t    orig_lua_getfield    = NULL;
static lua_getfield_t    real_lua_getfield    = NULL;
static lua_rawget_t      real_lua_rawget      = NULL;
static lua_rawgeti_t     orig_lua_rawgeti     = NULL;
static lua_rawgeti_t     real_lua_rawgeti     = NULL;
static lua_setfield_t    real_lua_setfield    = NULL;
static lua_pcall_t       orig_lua_pcall       = NULL;
static lua_pcall_t       real_lua_pcall       = NULL;

/* ===================================================================
 *  Naming convention heuristics
 *
 *  Because .mt Lua sources are encrypted, we guess common Cocos2d-x /
 *  Lua naming patterns.  Adjust these arrays after testing.
 * =================================================================== */

/* ---- Fields whose reads we override with a static max value ---- */
typedef struct {
    const char *name;
    int64_t     max_value;
    int         battle_only;   /* 1 = only override during battle */
} FieldOverride;

static FieldOverride g_overrides[] = {
    /* rarity – database tag 0x06, observed max 96 */
    { "rarity",       96,      0 },
    { "Rarity",       96,      0 },
    { "m_rarity",     96,      0 },
    /* star quality – tag 0x07, observed max 95 */
    { "starQuality",  95,      0 },
    { "StarQuality",  95,      0 },
    { "star",         95,      0 },
    { "Star",         95,      0 },
    /* hero class – tag 0x04 */
    { "class",        19,      0 },
    { "Class",        19,      0 },
    { "m_class",      19,      0 },
    /* combat stats – overridden only during battle */
    { "hp",           999999,  1 },
    { "Hp",           999999,  1 },
    { "m_hp",         999999,  1 },
    { "atk",          999999,  1 },
    { "Atk",          999999,  1 },
    { "m_atk",        999999,  1 },
    { "def",          999999,  1 },
    { "Def",          999999,  1 },
    { "m_def",        999999,  1 },
};
static const int g_num_overrides = sizeof(g_overrides) / sizeof(g_overrides[0]);

/* ---- Field names that identify a table as "hero" ---- */
static const char *g_hero_id_fields[] = {
    "heroId", "HeroId", "HeroID", "id", "Id", "ID", "m_id", "m_ID"
};
static const int g_num_hero_id_fields =
    sizeof(g_hero_id_fields) / sizeof(g_hero_id_fields[0]);

/* ===================================================================
 *  Battle context tracking
 *
 *  We use a simple atomic counter: it is incremented when lua_pcall is
 *  called with a known "battle start" function and decremented when the
 *  function returns.  This works because Lua is single-threaded per
 *  state, but the hook may be called from multiple Lua states.
 * =================================================================== */
/* For simplicity, we treat any lua_pcall of a Lua function whose
 * upvalue or name contains "battle" as a battle context.  In practice
 * you may need to tune the matcher after looking at actual .roo names. */
static volatile int g_battle_depth = 0;

static int is_battle_function(lua_State *L) {
    /* peek the function at stack index 1 (first argument, before args) */
    if (real_lua_type(L, 1) == LUA_TFUNCTION) {
        /* push its name if available */
        /* lua_getinfo(L, ">n", &ar) would need debug lib -- skip for now */
        return 0; /* not detected via simple heuristic */
    }
    return 0;
}

/* ------------------------------------------------------------------ */

/* Resolve every Lua API function pointer from the base address. */
static void resolve_lua_api(addr_t base) {
#define RESOLVE(name, off) \
    real_##name = (name##_t)(base + off)

    RESOLVE(lua_gettop,      OFF_LUA_GETTOP);
    RESOLVE(lua_settop,      OFF_LUA_SETTOP);
    RESOLVE(lua_type,        OFF_LUA_TYPE);
    RESOLVE(lua_tolstring,   OFF_LUA_TOLSTRING);
    RESOLVE(lua_tointeger,   OFF_LUA_TOINTEGER);
    RESOLVE(lua_pushnil,     OFF_LUA_PUSHNIL);
    RESOLVE(lua_pushinteger, OFF_LUA_PUSHINTEGER);
    RESOLVE(lua_pushnumber,  OFF_LUA_PUSHNUMBER);
    RESOLVE(lua_pushstring,  OFF_LUA_PUSHSTRING);
    RESOLVE(lua_pushvalue,   OFF_LUA_PUSHVALUE);
    RESOLVE(lua_getfield,    OFF_LUA_GETFIELD);
    RESOLVE(lua_rawget,      OFF_LUA_RAWGET);
    RESOLVE(lua_rawgeti,     OFF_LUA_RAWGETI);
    RESOLVE(lua_setfield,    OFF_LUA_SETFIELD);
    RESOLVE(lua_pcall,       OFF_LUA_PCALL);

#undef RESOLVE
}

/* ------------------------------------------------------------------ */
/*  Helper: check whether the table at absolute stack index `abs_idx`
 *  looks like a hero table (it has a numeric "heroId"-style field).
 *  Saves / restores the Lua stack.                                   */
static int table_is_hero(lua_State *L, int abs_idx) {
    int top    = real_lua_gettop(L);
    int result = 0;

    /* Must be a table */
    if (real_lua_type(L, abs_idx) != LUA_TTABLE)
        goto done;

    /* Try each possible hero-ID field name */
    for (int i = 0; i < g_num_hero_id_fields; i++) {
        real_lua_pushstring(L, g_hero_id_fields[i]);
        real_lua_rawget(L, abs_idx);   /* pops key, pushes value */
        int t = real_lua_type(L, -1);
        if (t == LUA_TNUMBER) {
            int64_t vid = real_lua_tointeger(L, -1);
            if (vid > 0 && vid < 10000) {
                result = 1;
                real_lua_settop(L, top);
                return result;
            }
        }
        real_lua_settop(L, top);       /* pop the value, try next */
    }

done:
    real_lua_settop(L, top);
    return result;
}

/* ------------------------------------------------------------------ */
/*  Match key against g_overrides; return index or -1.                */
static int match_override(const char *key) {
    if (!key) return -1;
    for (int i = 0; i < g_num_overrides; i++) {
        if (strcmp(key, g_overrides[i].name) == 0)
            return i;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Hooked lua_getfield
 *
 *  Intercepted call:
 *      lua_getfield(L, idx, "rarity")
 *
 *  Strategy:
 *    1. Call original so metamethods / __index fire normally.
 *    2. If the field is a target AND the table is a hero, replace
 *       the top-of-stack with the configured max value.
 * ------------------------------------------------------------------ */
static void hooked_lua_getfield(lua_State *L, int idx, const char *key) {
    int oi = match_override(key);

    /* Convert idx to absolute (stable after original pushes result). */
    int abs_idx = idx > 0 ? idx : real_lua_gettop(L) + idx + 1;

    /* Always call the original first — handles __index, proxies, etc. */
    orig_lua_getfield(L, idx, key);

    if (oi < 0) return;  /* not a field we care about */

    /* Battle-only fields – skip unless inside battle context. */
    if (g_overrides[oi].battle_only && g_battle_depth == 0)
        return;

    /* Verify source table is a hero. */
    if (!table_is_hero(L, abs_idx))
        return;

    /* Replace the value on top with our max. */
    real_lua_settop(L, real_lua_gettop(L) - 1);
    real_lua_pushinteger(L, (int)g_overrides[oi].max_value);
}

/* ------------------------------------------------------------------ */
/*  Hooked lua_rawgeti  (stub – for roster/team replacement)
 *
 *  Intended use: when the roster array is accessed (e.g. team[1]),
 *  replace the returned hero ID with the strongest known hero ID.
 *
 *  Implementation deferred until we can observe the actual roster
 *  access pattern from decrypted .roo / memory tracing.
 * ------------------------------------------------------------------ */
static void hooked_lua_rawgeti(lua_State *L, int idx, int n) {
    /* pass-through for now */
    orig_lua_rawgeti(L, idx, n);
}

/* ------------------------------------------------------------------ */
/*  Hooked lua_pcall  (battle-context tracking)
 *
 *  When a Lua function is called, we (optionally) detect battle
 *  entry / exit by name-matching.  For now it is a no-op placeholder.
 * ------------------------------------------------------------------ */
static int hooked_lua_pcall(lua_State *L, int nargs, int nresults, int errfunc) {
    return orig_lua_pcall(L, nargs, nresults, errfunc);
}

/* ===================================================================
 *  Public entry point – called from JNI_OnLoad or via constructor
 * =================================================================== */
int mla_hook_init(void) {
    /* 1. Resolve libagame.so base address (Dobby-style). */
    void *base_ptr = DobbyGetLibraryBase("libagame.so");
    if (!base_ptr) return -1;
    addr_t base = (addr_t)base_ptr;

    /* 2. Resolve all Lua function pointers. */
    resolve_lua_api(base);

    /* 3. Install Dobby hooks. */
    int ret;

    ret = DobbyHook((void *)(base + OFF_LUA_GETFIELD),
                    (void *)hooked_lua_getfield,
                    (void **)&orig_lua_getfield);
    if (ret != 0) return -2;

    ret = DobbyHook((void *)(base + OFF_LUA_RAWGETI),
                    (void *)hooked_lua_rawgeti,
                    (void **)&orig_lua_rawgeti);
    if (ret != 0) return -3;

    ret = DobbyHook((void *)(base + OFF_LUA_PCALL),
                    (void *)hooked_lua_pcall,
                    (void **)&orig_lua_pcall);
    if (ret != 0) return -4;

    return 0; /* success */
}
