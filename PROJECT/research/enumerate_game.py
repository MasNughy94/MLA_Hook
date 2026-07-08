#!/usr/bin/env python3
"""
enumerate_game.py - Attach to ML: Adventure, enumerate libagame.so
"""
import frida, json, sys, time

OUT_FILE = r"C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\research\mla_enumeration.json"

JS = """
'use strict';
var result = {pid:null,libagame:null,modules:[],exports:[],symbols:[],interesting:[],dlopen_calls:[]};

// Hook dlopen to catch game library loading
var real_dlopen = Module.getExportByName(null, 'dlopen');
Interceptor.attach(real_dlopen, {
    onEnter: function(args) { this.libpath = args[0].readCString(); },
    onLeave: function(retval) {
        if (this.libpath) {
            var n = this.libpath.toLowerCase();
            if (n.indexOf('game') !== -1 || n.indexOf('moonton') !== -1) {
                console.log('[dlopen] ' + this.libpath + ' -> ' + retval);
                result.dlopen_calls.push(this.libpath);
            }
        }
    }
});

function doEnumerate() {
    result.pid = Process.id;
    console.log('[MAIN] PID: ' + result.pid);

    Process.enumerateModules().forEach(function(m) {
        var n = m.name.toLowerCase();
        result.modules.push({name:m.name, base:m.base.toString(), size:m.size, path:m.path});
        if (n.indexOf('game') !== -1 || n.indexOf('moonton') !== -1 || n.indexOf('unity') !== -1 || n.indexOf('il2cpp') !== -1) {
            console.log('[GAME MODULE] ' + m.name + ' @ ' + m.base);
        }
    });
    console.log('[MAIN] Total modules: ' + result.modules.length);

    var lib = Process.findModuleByName('libagame.so');
    if (lib) {
        console.log('[libagame.so] FOUND @ ' + lib.base + ' sz=' + lib.size);
        result.libagame = {name:lib.name, base:lib.base.toString(), size:lib.size, end:lib.base.add(lib.size).toString()};

        try {
            var exp = lib.enumerateExports();
            exp.forEach(function(e){ result.exports.push({name:e.name, address:e.address.toString(), type:e.type}); });
            console.log('[exports] ' + exp.length);
        } catch(e) { console.log('[ERR exp] ' + e); }

        try {
            var syms = lib.enumerateSymbols();
            syms.forEach(function(s){ result.symbols.push({name:s.name, address:s.address.toString(), type:s.type}); });
            console.log('[syms] ' + syms.length);
        } catch(e) { console.log('[ERR sym] ' + e); }

        var PATTERNS = ['fopen','fread','fseek','fclose','AAsset','asset','AES','aes','cipher','decrypt','crypto',
            'mt_','_mt','MT_','uncompress','decompress','load','LoadFile','ReadFile','LZMA','lzma','range','decoder',
            'memcpy','memset','buffer','strstr','strcmp','strncmp','Unity','il2cpp'];
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
        console.log('[interesting] ' + result.interesting.length);
    } else {
        console.log('[libagame.so] NOT FOUND');
        result.modules.forEach(function(m) {
            var n = m.name.toLowerCase();
            if (n.indexOf('game') !== -1 || n.indexOf('moonton') !== -1 || n.indexOf('unity') !== -1) {
                console.log('[POSSIBLE] ' + m.name + ' @ ' + m.base + ' sz=' + m.size);
            }
        });
    }

    console.log('[DONE]');
    send(JSON.stringify(result));
}

doEnumerate();
"""

def on_message(msg, data):
    if msg.get('type') == 'send':
        try:
            result = json.loads(msg['payload'])
            with open(OUT_FILE, 'w') as f:
                json.dump(result, f, indent=2)
            print('[PY] Saved to', OUT_FILE)
            print('[PY] Modules:', len(result.get('modules', [])))
            print('[PY] libagame found:', result.get('libagame') is not None)
            lib = result.get('libagame')
            if lib:
                print(f"  Base: {lib['base']}  Size: {lib['size']}")
                print(f"  Exports: {len(result.get('exports', []))}")
                print(f"  Symbols: {len(result.get('symbols', []))}")
                print(f"  Interesting: {len(result.get('interesting', []))}")
            print('[PY] dlopen calls:', len(result.get('dlopen_calls', [])))
            for c in result.get('dlopen_calls', [])[:20]:
                print('  ', c)
        except Exception as e:
            print('[PY] Parse error:', e)
    elif msg.get('type') == 'error':
        print('[JS ERROR]', msg.get('message', '?'))

print('[PY] Connecting to frida-server via remote device...')
mgr = frida.get_device_manager()
device = mgr.add_remote_device('127.0.0.1')
print('[PY] Device:', device)

print('[PY] Device:', device)
print('[PY] Attaching to PID 4703...')
session = device.attach(4703)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('[PY] Script loaded.')

# Wait for completion
for i in range(40):
    time.sleep(0.5)
    if session.is_detached:
        print('[PY] Session detached')
        break
    try:
        with open(OUT_FILE) as f:
            data = json.load(f)
            if data.get('modules'):
                break
    except:
        pass
else:
    print('[PY] Timeout')

session.detach()
print('[PY] Done.')
