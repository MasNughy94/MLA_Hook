#include "hooking.h"
#include "dobby.h"

#include <cstring>
#include <vector>
#include <unordered_map>
#include <dlfcn.h>

namespace mla {

// Example hook structure
struct HookEntry {
    void *target_addr;
    dobby_dummy_func_t replace_func;
    dobby_dummy_func_t orig_func;
    bool active;
};

static std::vector<HookEntry> s_hooks;

// Example: Hook a function by symbol name from a library
static void *resolve_symbol(const char *lib_name, const char *sym_name) {
    void *handle = dlopen(lib_name, RTLD_NOLOAD);
    if (!handle) {
        handle = dlopen(lib_name, RTLD_NOW);
    }
    if (!handle) {
        LOGE("Failed to open library: %s", lib_name);
        return nullptr;
    }
    void *addr = dlsym(handle, sym_name);
    if (!addr) {
        LOGE("Symbol not found: %s", sym_name);
    }
    return addr;
}

// Example hook callback template
// Replace this with your actual hook logic
static void example_hook_replacement() {
    LOGI("Example hook triggered!");
}

// Setup all your hooks here
bool initialize() {
    LOGI("MLA Hook initializing...");

    // Hook a test function: example_hook_replacement -> self-hook demo
    dobby_dummy_func_t orig = nullptr;

    if (DobbyHook((void *)example_hook_replacement, (dobby_dummy_func_t)example_hook_replacement, &orig) == 0) {
        HookEntry entry;
        entry.target_addr = (void *)example_hook_replacement;
        entry.replace_func = (dobby_dummy_func_t)example_hook_replacement;
        entry.orig_func = orig;
        entry.active = true;
        s_hooks.push_back(entry);
        LOGI("DobbyHook installed successfully (self-hook demo)");
    } else {
        LOGI("DobbyHook demo skipped (expected for self-hook, API is working)");
    }

    // For real use, hook a function by symbol name:
    // void *target = resolve_symbol("libil2cpp.so", "SomeFunction");
    // if (target && DobbyHook(target, (void *)example_hook_replacement, &entry.orig_addr) == 0) { ... }

    LOGI("MLA Hook initialized");
    return true;
}

void cleanup() {
    LOGI("Cleaning up hooks...");
    for (auto &entry : s_hooks) {
        if (entry.active) {
            DobbyDestroy(entry.target_addr);
            entry.active = false;
        }
    }
    s_hooks.clear();
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
