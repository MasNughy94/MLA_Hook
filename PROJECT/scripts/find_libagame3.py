import frida, time

device = frida.get_device("socket", timeout=5)
session = device.attach(17786)

js = """
// Try various ways to find libagame

// 1. Check if the old base address has the ELF header
var oldBase = ptr("0x032d4000");
console.log("[*] Checking old base " + oldBase + "...");
try {
    var magic = oldBase.readCString(4);
    console.log("[*] At old base: '" + magic + "'");
} catch(e) {
    console.log("[!] Cannot read old base: " + e);
}

// 2. Check common base addresses that ELF files might be loaded at
var candidates = [
    0x02000000, 0x03000000, 0x032d4000, 0x04000000, 0x05000000, 
    0x06000000, 0x07000000, 0x08000000, 0x09000000, 0x0a000000,
    0x10000000, 0x20000000, 0x30000000, 0x40000000,
];
for (var i = 0; i < candidates.length; i++) {
    try {
        var addr = ptr(candidates[i]);
        var magic = addr.readU32();
        if (magic == 0x464c457f) {  // \\x7fELF in LE
            console.log("[+] ELF at " + addr);
        }
    } catch(e) {}
}

// 3. List all loaded modules and their full paths
console.log("\\n[*] Enumerating all modules (full paths)...");
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    var path = mods[i].path;
    if (path.indexOf("agame") >= 0 || path.indexOf("native") >= 0 || path.indexOf("lib") >= 0) {
        if (path.indexOf("libc") >= 0 || path.indexOf("libdl") >= 0 || path.indexOf("libm") >= 0 || 
            path.indexOf("libnative") >= 0) continue;
        console.log("  [" + i + "] " + mods[i].name + " -> " + path);
    }
}

// 4. Try Process.findModuleByName
console.log("\\n[*] Trying Process.findModuleByName...");
try {
    var m = Process.findModuleByName("libagame.so");
    console.log("[*] findModuleByName: " + (m ? m.base : "null"));
} catch(e) {
    console.log("[!] findModuleByName error: " + e);
}

// 5. Try memory ranges scanning
console.log("\\n[*] Checking memory ranges around 0x03000000-0x05000000...");
try {
    var ranges = Process.enumerateRanges('rw-');
    console.log("[*] Found " + ranges.length + " rw- ranges");
    // Check first few
    for (var i = 0; i < Math.min(ranges.length, 10); i++) {
        var r = ranges[i];
        if (r.base.toInt32() > 0x02000000 && r.base.toInt32() < 0x10000000) {
            console.log("  " + r.base + " - " + r.end + " (" + r.size + ") " + r.protection);
        }
    }
} catch(e) {
    console.log("[!] " + e);
}

console.log("\\n[*] Done");
send({type: "done"});
"""

script = session.create_script(js)
script.on("message", lambda m,d: print(m))
script.load()
time.sleep(15)
session.detach()
