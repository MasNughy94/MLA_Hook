#!/usr/bin/env python3
"""
enumerate_game_v2.py - Frida 17 API: enumerate libagame.so with correct API
API pattern:
  Process.getModuleByName(name) -> module
  module.getExportByName(name) -> NativePointer
  module.enumerateExports() -> exports[]
  module.enumerateSymbols() -> symbols[]
  Interceptor.attach(ptr, callbacks)
"""
import frida, time, json, sys

OUT_FILE = r"C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\research\mla_enumeration.json"

# Frida 17 JS - no 'use strict' to avoid potential issues
JS = """
var result = {
    pid: null,
    libagame: null,
    modules: [],
    exports: [],
    symbols: [],
    interesting: [],
    dlopen_calls: [],
    script_error: null
};

var PATTERNS = [
    'fopen','fread','fseek','fclose',
    'AAsset','asset',
    'AES','aes','cipher','decrypt','crypto',
    'mt_','_mt','MT_','uncompress','decompress',
    'load','LoadFile','ReadFile','LZMA','lzma','range','decoder',
    'memcpy','memset','buffer',
    'strstr','strcmp','strncmp',
    'Unity','il2cpp'
];

try {
    result.pid = Process.id;
    console.log('[START] PID=' + result.pid);

    // Enumerate all modules
    var mods = Process.enumerateModules();
    mods.forEach(function(m) {
        result.modules.push({name: m.name, base: m.base.toString(), size: m.size});
    });
    console.log('[MODULES] ' + result.modules.length + ' total');

    // Show game-related
    result.modules.forEach(function(m) {
        var n = m.name.toLowerCase();
        if (n.indexOf('game') !== -1 || n.indexOf('moonton') !== -1 || n.indexOf('unity') !== -1 || n.indexOf('il2cpp') !== -1 || n.indexOf('legends') !== -1) {
            console.log('[GAME-MODULE] ' + m.name + ' @ ' + m.base + ' sz=' + m.size);
        }
    });

    // libagame.so
    var lib = Process.getModuleByName('libagame.so');
    if (lib) {
        console.log('[libagame.so] FOUND @ ' + lib.base + ' sz=' + lib.size);
        result.libagame = {
            name: lib.name,
            base: lib.base.toString(),
            size: lib.size,
            end: lib.base.add(lib.size).toString()
        };

        // Hook dlopen to catch future loads
        var libdl = Process.getModuleByName('libdl.so');
        var dlopen_fn = null;
        if (libdl) {
            dlopen_fn = libdl.getExportByName('dlopen');
        }
        if (dlopen_fn) {
            Interceptor.attach(dlopen_fn, {
                onEnter: function(args) {
                    try {
                        var path = args[0].readCString();
                        if (path) {
                            var n = path.toLowerCase();
                            if (n.indexOf('game') !== -1 || n.indexOf('moonton') !== -1) {
                                console.log('[dlopen] ' + path);
                            }
                            result.dlopen_calls.push(path);
                        }
                    } catch(e) {}
                }
            });
            console.log('[dlopen] hooked');
        }

        // Enumerate exports
        var exp = lib.enumerateExports();
        exp.forEach(function(e) {
            result.exports.push({name: e.name, address: e.address.toString(), type: e.type});
        });
        console.log('[EXPORTS] ' + exp.length);

        // Enumerate symbols
        var syms = lib.enumerateSymbols();
        syms.forEach(function(s) {
            result.symbols.push({name: s.name, address: s.address.toString(), type: s.type});
        });
        console.log('[SYMBOLS] ' + syms.length);

        // Search interesting
        var all = result.exports.concat(result.symbols);
        var seen = {};
        all.forEach(function(item) {
            var n = item.name || '';
            PATTERNS.forEach(function(pat) {
                if (n.toLowerCase().indexOf(pat.toLowerCase()) !== -1 && !seen[n]) {
                    seen[n] = true;
                    result.interesting.push(item);
                    console.log('[' + pat + '] ' + item.address + ' | ' + item.name);
                }
            });
        });
        console.log('[INTERESTING] ' + result.interesting.length);
    } else {
        console.log('[libagame.so] NOT FOUND');
        // Check if it's in a different process
        console.log('[INFO] Searching in module list...');
        result.modules.forEach(function(m) {
            var n = m.name.toLowerCase();
            if (n.indexOf('agame') !== -1 || n.indexOf('moonton') !== -1) {
                console.log('[POSSIBLE] ' + m.name + ' @ ' + m.base);
            }
        });
    }

    console.log('[DONE]');
} catch(e) {
    result.script_error = String(e);
    console.log('[JS-ERROR] ' + e + ' at ' + (e.stack || '').split('\\n')[0]);
}

send(JSON.stringify(result));
"""

def on_message(msg, data):
    payload = msg.get('payload')
    if isinstance(payload, str):
        try:
            result = json.loads(payload)
            with open(OUT_FILE, 'w') as f:
                json.dump(result, f, indent=2)
            print('[PY] Written:', OUT_FILE)
            print('[PY] Modules:', len(result.get('modules', [])))
            print('[PY] libagame:', result.get('libagame') is not None)
            lib = result.get('libagame')
            if lib:
                print(f"  Base: {lib['base']}  Size: {lib['size']}")
                print(f"  Exports: {len(result.get('exports', []))}")
                print(f"  Symbols: {len(result.get('symbols', []))}")
                print(f"  Interesting: {len(result.get('interesting', []))}")
            for item in result.get('interesting', []):
                print(f"  {item['address']} | {item['name']}")
            if result.get('script_error'):
                print('[PY] JS Error:', result['script_error'])
        except Exception as e:
            print('[PY] Parse error:', e)
            print('[PY] Raw:', payload[:200])
    else:
        print('[PY] msg:', payload)

print('[PY] Connecting...')
mgr = frida.get_device_manager()
device = mgr.add_remote_device('127.0.0.1')
print('[PY] Device:', device)
print('[PY] Attaching to PID 4703...')
session = device.attach(4703)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('[PY] Script loaded. Waiting...')

for i in range(40):
    time.sleep(0.5)
    if session.is_detached:
        print('[PY] Detached at', i * 0.5, 's')
        break
    try:
        with open(OUT_FILE) as f:
            data = json.load(f)
            if data.get('modules'):
                print('[PY] File ready at', (i+1)*0.5, 's')
                break
    except:
        pass
else:
    print('[PY] Timeout')

session.detach()
