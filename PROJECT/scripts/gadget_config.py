"""
Create a frida-gadget config file and rebuild APK with built-in script.
This makes the gadget auto-load a hook script without needing external connection.
"""
import os, sys, struct, shutil, zipfile

# The gadget config as JSON, frida-gadget reads it from libfrida-gadget.config.so
# Actually the config is stored as a raw asset or embedded resource.
# The format: libfrida-gadget.config.so should contain the JSON config.

config = {
    "interaction": {
        "type": "script",
        "on_change": "reload"
    },
    "script": r"""
console.log('[+] Auto-loaded gadget script!');

Java.perform(function() {
    console.log('[+] Java hook ready');
    
    // CCCrypto Java class
    try {
        var CCCrypto = Java.use('com.moonton.mobilehero.plug.game.CCCrypto');
        if (CCCrypto) {
            console.log('[+] Found CCCrypto');
            
            // Hook aes_decrypt
            var aesDec = CCCrypto.aes_decrypt.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
            aesDec.implementation = function(key, data, iv) {
                console.log('[AES] key=' + key);
                console.log('[AES] iv=' + iv);
                console.log('[AES] data.len=' + data.length);
                var result = this.aes_decrypt(key, data, iv);
                console.log('[AES] result.len=' + (result ? result.length : 0));
                return result;
            };
        }
    } catch(e) {
        console.log('[!] CCCrypto error: ' + e);
    }
    
    // Hook System.loadLibrary
    try {
        var System = Java.use('java.lang.System');
        System.loadLibrary.implementation = function(name) {
            console.log('[loadLibrary] ' + name);
            return this.loadLibrary(name);
        };
    } catch(e) {}
});

// Native hooks in libagame.so
var mod = Process.findModuleByName('libagame.so');
if (mod) {
    console.log('[+] libagame.so at ' + mod.base);
    
    // Hook getKey
    try {
        Interceptor.attach(mod.base.add(0xCEC678), {
            onEnter: function(args) {
                console.log('[getKey] called');
            },
            onLeave: function(retval) {
                console.log('[getKey] returns');
            }
        });
    } catch(e) {
        console.log('[!] getKey hook failed: ' + e);
    }
}
""",
    "version": 1
}

import json
config_json = json.dumps(config, indent=2)
print(f"Config JSON ({len(config_json)} bytes):")
print(config_json[:500])
