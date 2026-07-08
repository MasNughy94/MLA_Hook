/*
 * enumerate_libagame.js v2
 * Enumerates libagame.so: modules, exports, symbols, function search
 * Output: console + /data/local/tmp/mla_enum.json
 */

var PKG = "com.moonton.mobilehero";
var OUT_FILE = "/data/local/tmp/mla_enum.json";

var result = {
    metadata: { pid: null, pkg: PKG, timestamp: Date.now() },
    modules: [],
    libagame: null,
    exports: [],
    symbols: [],
    interesting_funcs: [],
    search_results: {}
};

var SEARCH_PATTERNS = [
    "fopen", "fread", "fseek", "fclose", "fgetc",
    "AAsset", "Asset", "asset",
    "AES", "aes", "cipher", "decrypt", "crypto",
    "mt_", "_mt", "MT_", "uncompress", "decompress",
    "load", "LoadFile", "ReadFile",
    "LZMA", "lzma", "range", "decoder",
    "strstr", "strcmp",
    "memcpy", "memset", "buffer",
    "Unity", "il2cpp",
];

function log(msg) {
    console.log("[ENUM] " + msg);
}

// ─── Enumerate modules ─────────────────────────────────────────────────────────
function enumerateModules() {
    try {
        var mods = Process.enumerateModules();
        log("Modules found: " + mods.length);
        mods.forEach(function(m) {
            result.modules.push({
                name: String(m.name),
                base: m.base.toString(),
                size: Number(m.size),
                path: String(m.path)
            });
        });
    } catch (e) {
        log("enumerateModules error: " + e);
    }
}

// ─── Get libagame.so ──────────────────────────────────────────────────────────
function getLibagame() {
    try {
        var lib = Process.findModuleByName("libagame.so");
        if (!lib) {
            log("ERROR: libagame.so not found!");
            return null;
        }
        result.libagame = {
            name: String(lib.name),
            base: lib.base.toString(),
            size: Number(lib.size),
            end: lib.base.add(lib.size).toString()
        };
        log("libagame.so: " + lib.base + " size=" + lib.size);
        return lib;
    } catch (e) {
        log("getLibagame error: " + e);
        return null;
    }
}

// ─── Enumerate exports ─────────────────────────────────────────────────────────
function enumerateExports(lib) {
    try {
        if (typeof lib.enumerateExports !== "function") {
            log("enumerateExports not a function, skipping");
            return;
        }
        var exp = lib.enumerateExports();
        log("Exports: " + exp.length);
        exp.forEach(function(e) {
            result.exports.push({
                name: String(e.name),
                address: e.address.toString(),
                type: String(e.type)
            });
        });
    } catch (e) {
        log("enumerateExports error: " + e);
    }
}

// ─── Enumerate symbols ─────────────────────────────────────────────────────────
function enumerateSymbols(lib) {
    try {
        if (typeof lib.enumerateSymbols !== "function") {
            log("enumerateSymbols not a function, skipping");
            return;
        }
        var syms = lib.enumerateSymbols();
        log("Symbols: " + syms.length);
        syms.forEach(function(s) {
            result.symbols.push({
                name: String(s.name),
                address: s.address.toString(),
                type: String(s.type)
            });
        });
    } catch (e) {
        log("enumerateSymbols error: " + e);
    }
}

// ─── Search interesting functions ───────────────────────────────────────────────
function searchInteresting() {
    var all = result.exports.concat(result.symbols);
    var found = {};
    SEARCH_PATTERNS.forEach(function(pat) { found[pat] = []; });

    all.forEach(function(item) {
        var name = item.name || "";
        var lower = name.toLowerCase();
        SEARCH_PATTERNS.forEach(function(pat) {
            if (lower.indexOf(pat.toLowerCase()) !== -1) {
                found[pat].push(item);
            }
        });
    });

    result.search_results = found;
    var seen = {};
    all.forEach(function(item) {
        var n = item.name || "";
        if (!seen[n]) {
            SEARCH_PATTERNS.forEach(function(pat) {
                if (n.toLowerCase().indexOf(pat.toLowerCase()) !== -1) {
                    seen[n] = true;
                    result.interesting_funcs.push(item);
                }
            });
        }
    });

    log("Total interesting funcs: " + result.interesting_funcs.length);

    // Print results to console
    SEARCH_PATTERNS.forEach(function(pat) {
        var items = found[pat];
        if (items && items.length > 0) {
            console.log("");
            console.log("[" + pat + "] (" + items.length + "):");
            items.slice(0, 30).forEach(function(item) {
                console.log("  " + item.address + " | " + item.name);
            });
        }
    });
}

// ─── Write results ─────────────────────────────────────────────────────────────
function writeResults() {
    try {
        var fn = new File(OUT_FILE, "w");
        fn.write(JSON.stringify(result, null, 2));
        fn.close();
        log("Written: " + OUT_FILE);
        console.log("");
        console.log("=== DONE ===");
        console.log("Modules: " + result.modules.length);
        console.log("Exports: " + result.exports.length);
        console.log("Symbols: " + result.symbols.length);
        console.log("Interesting: " + result.interesting_funcs.length);
    } catch (e) {
        console.error("Write error: " + e);
    }
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────
log("Starting enumeration...");

result.metadata.pid = Process.id;
log("My PID: " + Process.id);

enumerateModules();

var lib = getLibagame();
if (lib) {
    enumerateExports(lib);
    enumerateSymbols(lib);
    searchInteresting();
    writeResults();
} else {
    log("libagame.so not found!");
    console.log(JSON.stringify(result));
}
