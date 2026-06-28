import frida, time

device = frida.get_device("socket", timeout=5)
session = device.attach(17786)

js = """
console.log("[*] Searching for libagame.so base...");

function findPattern(ranges, pattern) {
    var chunkSize = 0x20000;
    for (var r = 0; r < ranges.length; r++) {
        var range = ranges[r];
        var offset = 0;
        while (offset < range.size) {
            var readSz = Math.min(chunkSize, range.size - offset);
            try {
                var ab = range.start.add(offset).readByteArray(readSz);
                var bytes = new Uint8Array(ab);
                for (var i = 0; i < bytes.length - pattern.length + 1; i++) {
                    var match = true;
                    for (var j = 0; j < pattern.length; j++) {
                        if (bytes[i + j] != pattern[j]) { match = false; break; }
                    }
                    if (match) {
                        return range.start.add(offset + i);
                    }
                }
            } catch(e) {
                offset += 0x1000;
                continue;
            }
            offset += chunkSize;
        }
    }
    return null;
}

// Search for ELF header (\\x7fELF) at low addresses
var elfranges = [
    {start: ptr("0x02000000"), size: 0x08000000},
];
var elfMagic = [0x7f, 0x45, 0x4c, 0x46];  // \\x7fELF

console.log("[*] Searching for ELF header...");
var elfAddr = findPattern(elfranges, elfMagic);
if (elfAddr) {
    console.log("[+] ELF header found at " + elfAddr);
    // Verify it's libagame by checking for known offset
    // Antm string might be at various offsets
    // Try to read the ELF header identification
    try {
        var cls = elfAddr.add(4).readU8();
        var data = elfAddr.add(5).readU8();
        console.log("  ELF class: " + cls + " (2=64bit), data: " + data + " (1=LE)");
    } catch(e) {}
}

// Also search for "Antm" pattern
console.log("[*] Searching for 'Antm'...");
var antmAddr = findPattern(elfranges, [0x41, 0x6e, 0x74, 0x6d]);
if (antmAddr) {
    console.log("[+] 'Antm' found at " + antmAddr);
    // Try reading around it to find libagame base
    // Antm might be at base+0x164 (from previous dump)
    var possibleBase = antmAddr.sub(0x164);
    try {
        var magic = possibleBase.readU32();
        if (magic == 0x464c457f) {  // ELF magic in LE
            console.log("[+] libagame base at " + possibleBase + " (Antm at +0x164)");
        }
    } catch(e) {}
    
    // Also try Antm in an array at other offsets
    var offsets_to_try = [0x164, 0x10164, 0x20164, 0x30164, 0x40164, 0x50164];
    for (var i = 0; i < offsets_to_try.length; i++) {
        var testBase = antmAddr.sub(offsets_to_try[i]);
        try {
            var magic = testBase.readU32();
            if (magic == 0x464c457f) {
                console.log("[+] libagame base at " + testBase + " (Antm at +0x" + offsets_to_try[i].toString(16) + ")");
            }
        } catch(e) {}
    }
}

// Search for Te0 table (AES forward T-table)
console.log("[*] Searching for Te0 table...");
// Te0[0] = 0xa56363c6 in LE bytes = c6 63 63 a5
var te0Addr = findPattern(elfranges, [0xc6, 0x63, 0x63, 0xa5]);
if (te0Addr) {
    console.log("[+] Te0 table found at " + te0Addr);
    // Te0 is at file offset 0xf2e340
    var possibleBase = te0Addr.sub(0xf2e340);
    try {
        var magic = possibleBase.readU32();
        if (magic == 0x464c457f) {
            console.log("[+] libagame base at " + possibleBase + " (Te0 at +0xf2e340)");
        }
    } catch(e) {}
}

console.log("[*] Search complete");
send({type: "done"});
"""

script = session.create_script(js)
script.on("message", lambda m,d: print(m))
script.load()
time.sleep(90)
session.detach()
