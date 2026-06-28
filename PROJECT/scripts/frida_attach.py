#!/usr/bin/env python3
"""Attach frida to running game and hook crypto functions"""
import frida, time, sys

jscode = """
var mod = "libagame.so";
var base = Module.findBaseAddress(mod);
console.log("[+] " + mod + " @ " + base);

var OFFSETS = {
    getkey: 0x43B33C,
    oi_decrypt2: 0x43AE3C,
    encrypt_decrypt: 0x43B43C,
    tea_dec_ecb: 0x43AA80,
    setKey: 0xCECA74,
    setKey2: 0xCECB5C,
    getKey: 0xCEC678,
    aesDecrypt: 0xCEDFE4,
    aesEncrypt: 0xCED7A8,
    uncompress: 0xCECD24,
};

function readStr(ptr) {
    try {
        var p = ptr.readPointer();
        var len = ptr.add(8).readPointer().toInt32();
        if (len > 0 && len < 0x100000) return p.readUtf8String(len);
        return null;
    } catch(e) { return null; }
}

function hook(off, name, cb) {
    var addr = base.add(off);
    console.log("[*] Hooking " + name + " @ " + addr);
    try { Interceptor.attach(addr, cb); }
    catch(e) { console.log("[-] " + name + ": " + e.message); }
}

hook(OFFSETS.setKey, "setKey(str)", {
    onEnter: function(args) {
        var key = readStr(args[0]);
        if (key) console.log("\n[setKey] " + key);
    }
});

hook(OFFSETS.setKey2, "setKey2(str)", {
    onEnter: function(args) {
        var key = readStr(args[0]);
        if (key) console.log("\n[setKey2] " + key);
    }
});

hook(OFFSETS.getKey, "getKey()", {
    onLeave: function(ret) {
        var key = readStr(ret);
        if (key) console.log("\n[getKey] => " + key);
    }
});

hook(OFFSETS.aesDecrypt, "aes_decrypt", {
    onEnter: function(args) {
        var key = readStr(args[0]);
        var data = readStr(args[1]);
        if (key) console.log("\n[aes_decrypt] key=" + key.substring(0,32));
        if (data) console.log("  data(" + data.length + "): " + data.substring(0,48));
    },
    onLeave: function(ret) {
        var out = readStr(ret);
        if (out && out.length > 0) {
            console.log("[aes_decrypt] output(" + out.length + "): " + out.substring(0,48));
            if (out.charCodeAt(0) == 0x6c && out.charCodeAt(1) == 0x6d) {
                console.log("  *** lmF@ MAGIC! ***");
            }
        }
    }
});

hook(OFFSETS.uncompress, "uncompressData", {
    onEnter: function(args) {
        var len = args[1].toInt32();
        if (len > 0 && len < 0x100000) {
            var data = args[0].readByteArray(len);
            var arr = new Uint8Array(data);
            var magic = String.fromCharCode(arr[0], arr[1], arr[2], arr[3]);
            if (magic == "lmF@" || magic == "Antm" || arr[0] == 0x78) {
                console.log("\n[uncompressData] len=" + len + " magic=" + magic);
                console.log("  hex: " + hexdump(data, {offset:0, length:Math.min(len, 48)}));
            }
        }
    }
});

hook(OFFSETS.getkey, "getkey", {
    onEnter: function(args) {
        try {
            var hex = args[0].readCString();
            console.log("\n[getkey] hex=\"" + hex + "\"");
        } catch(e) {}
    }
});

console.log("[*] Script loaded!");
"""

def on_msg(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    elif msg['type'] == 'error':
        print(f"[!] Error: {msg}")

if len(sys.argv) > 1:
    pid = int(sys.argv[1])
else:
    print("Usage: python frida_attach.py <PID>")
    print("Finding game PID via adb...")
    import subprocess
    result = subprocess.run(
        ["C:\\Users\\NGEONG\\Videos\\MLA\\platform-tools\\adb.exe",
         "-s", "192.168.1.7:5555", "shell", "pidof com.moonton.mobilehero"],
        capture_output=True, text=True)
    pid = int(result.stdout.strip())
    print(f"Game PID: {pid}")

device = frida.get_usb_device()
session = device.attach(pid)
print(f"[+] Attached to PID {pid}")

script = session.create_script(jscode)
script.on('message', on_msg)
script.load()

print("[*] Hooked! Interact with the game now. Press Ctrl+C to stop.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Stopping...")
    session.detach()
