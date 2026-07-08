#!/usr/bin/env python3
"""
enumerate_with_dlopen.py - Hook dlopen to catch libagame.so loading
"""
import frida, time, json

OUT_FILE = r"C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\research\mla_modules.json"

JS = """
'use strict';
var result = {modules:[], dlopen_calls:[], error:null, script_error:null};
try {
    Process.enumerateModules().forEach(function(m) {
        result.modules.push({name:m.name, base:m.base.toString(), size:m.size});
    });
    console.log('[START] PID=' + Process.id + ' modules=' + result.modules.length);

    var dlopen = Module.getExportByName(null, 'dlopen');
    console.log('[dlopen addr] ' + dlopen);

    Interceptor.attach(dlopen, {
        onEnter: function(args) {
            try {
                this.path = args[0].readCString();
            } catch(e) { this.path = null; }
        },
        onLeave: function(retval) {
            if (this.path) {
                var n = this.path.toLowerCase();
                if (n.indexOf('game') !== -1 || n.indexOf('agame') !== -1 || n.indexOf('moonton') !== -1) {
                    console.log('[GAME-SO] ' + this.path + ' -> ' + retval);
                }
                result.dlopen_calls.push(this.path);
            }
        }
    });
    console.log('[dlopen] hooked');
    send({type:'modules', count: result.modules.length, modules: result.modules});
} catch(e) {
    result.script_error = String(e);
    console.log('[JS-ERROR] ' + e);
    send({type:'error', error: String(e)});
}
"""

def on_message(msg, data):
    payload = msg.get('payload', {})
    if isinstance(payload, dict):
        t = payload.get('type', '')
        if t == 'modules':
            print('[PY] Received module list:', payload.get('count'), 'modules')
            with open(OUT_FILE, 'w') as f:
                json.dump(payload, f, indent=2)
            print('[PY] Written to', OUT_FILE)
            # Show game-related modules
            for m in payload.get('modules', []):
                n = m['name'].lower()
                if any(x in n for x in ['game', 'moonton', 'unity', 'il2cpp', 'legends', 'hero']):
                    print('  GAME?:', m['name'], '@', m['base'], 'sz=', m['size'])
        elif t == 'error':
            print('[PY] JS Error:', payload.get('error'))
        else:
            print('[PY] msg:', payload)
    else:
        print('[PY] raw:', payload)

print('[PY] Connecting...')
mgr = frida.get_device_manager()
device = mgr.add_remote_device('127.0.0.1')
print('[PY] Device:', device)
print('[PY] Attaching to PID 4703...')
session = device.attach(4703)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
print('[PY] Script loaded. Waiting 10s for dlopen events...')
time.sleep(10)
session.detach()
print('[PY] Done.')

# Print results
try:
    with open(OUT_FILE) as f:
        data = json.load(f)
    print('\n=== MODULES ===')
    for m in data.get('modules', []):
        n = m['name'].lower()
        if any(x in n for x in ['game', 'moonton', 'unity', 'il2cpp', 'legends', 'hero']):
            print('GAME:', m['name'], '@', m['base'], 'sz=', m['size'])
except Exception as e:
    print('[PY] Error reading results:', e)
