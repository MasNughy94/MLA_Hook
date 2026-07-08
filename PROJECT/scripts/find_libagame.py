import frida, time

device = frida.get_device("socket", timeout=5)
session = device.attach(17786)

js = """
// Search for "Antm" string to find libagame base
// The string "Antm" should be at libagame_base + some offset
// Let's search in the 32-bit address range

console.log("[*] Searching for Antm string to locate libagame.so...");

function findAntm() {
    // Search in likely address ranges for ARM64 libraries
    var ranges = [
        {start: ptr("0x02000000"), size: 0x08000000},  // 128MB starting at 32MB
        {start: ptr("0x10000000"), size: 0x08000000},
    ];
    
    var chunkSize = 0x10000;
    
    for (var r = 0; r < ranges.length; r++) {
        var range = ranges[r];
        console.log("[*] Scanning " + range.start + " (" + (range.size/0x100000).toFixed(0) + "MB)...");
        
        var offset = 0;
        while (offset < range.size) {
            var readSz = Math.min(chunkSize, range.size - offset);
            try {
                var ab = range.start.add(offset).readByteArray(readSz);
                var bytes = new Uint8Array(ab);
                
                for (var i = 0; i < bytes.length - 3; i++) {
                    if (bytes[i] == 0x41 && bytes[i+1] == 0x6e && bytes[i+2] == 0x74 && bytes[i+3] == 0x6d) {
                        var addr = range.start.add(offset + i);
                        // "Antm" found - subtract known offset to get base
                        // "Antm" is at file offset... let me check: it should be early in the .rodata
                        // For now, just report the address
                        console.log("[+] Found 'Antm' at " + addr);
                        // Common offsets for "Antm": try 0x164 (from previous analysis)
                        // Actually let's not assume offset, just report all finds
                        return addr;
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

var antmAddr = findAntm();
if (antmAddr) {
    console.log("[*] First 'Antm' found at " + antmAddr);
    // Compute possible base addresses
    var possibleOffsets = [0x164, 0x10164, 0x20164, 0x30164, 0x40164];
    for (var i = 0; i < possibleOffsets.length; i++) {
        var base = antmAddr.sub(possibleOffsets[i]);
        // Check if ELF header at this address
        try {
            var magic = base.readCString(4);
            if (magic == "\\x7fELF") {
                console.log("[+] Found libagame base at " + base + " (offset 0x" + possibleOffsets[i].toString(16) + ")");
            }
        } catch(e) {}
    }
}

// Also try to find the Te0 table (known values)
console.log("\\n[*] Searching for Te0 table signature...");
// Te0[0] = 0xa56363c6 in LE = c6 63 63 a5
var te0Sig = [0xc6, 0x63, 0x63, 0xa5];

var ranges = [
    {start: ptr("0x02000000"), size: 0x08000000},
];
var chunkSize = 0x10000;
for (var r = 0; r < ranges.length; r++) {
    var range = ranges[r];
    var offset = 0;
    while (offset < range.size) {
        var readSz = Math.min(chunkSize, range.size - offset);
        try {
            var ab = range.start.add(offset).readByteArray(readSz);
            var bytes = new Uint8Array(ab);
            for (var i = 0; i < bytes.length - 3; i++) {
                if (bytes[i] == te0Sig[0] && bytes[i+1] == te0Sig[1] && 
                    bytes[i+2] == te0Sig[2] && bytes[i+3] == te0Sig[3]) {
                    var addr = range.start.add(offset + i);
                    console.log("[+] Te0 table found at " + addr);
                    // Te0 is at file offset 0xf2e340
                    var base = addr.sub(0xf2e340);
                    try {
                        var magic = base.readCString(4);
                        if (magic == "\\x7fELF") {
                            console.log("[+] Found libagame base at " + base);
                        }
                    } catch(e) {}
                    return;
                }
            }
        } catch(e) {
            offset += 0x1000;
            continue;
        }
        offset += chunkSize;
    }
}

console.log("[*] Search complete");
send({type: "done"});
"""

# Need to handle UTF-8 in the script properly
with open(r"C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\find_libagame.js", "w", encoding="utf-8") as f:
    f.write(js)

with open(r"C:\Users\ADMIN SERVICE\AppData\Local\Temp\opencode\find_libagame.js") as f:
    js_content = f.read()

script = session.create_script(js_content)
script.on("message", lambda m,d: print(m))
script.load()
time.sleep(60)
session.detach()
