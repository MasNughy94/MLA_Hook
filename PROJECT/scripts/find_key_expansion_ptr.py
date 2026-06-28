import frida, time, struct, sys

# Read the global function pointer used for key expansion
# From the code: adrp x2, #0x11e5000; ldr x2, [x2, #0x3a8]
# The runtime address depends on the ADRP calculation. Let's just search for it.

js = """
// Read the global pointer used for AES key expansion
// At runtime: the global at 0x11de000 + 0x3e0 is TLS canary
// The global for key expansion fn ptr:
// In the wrapper at 0xcec634: ldr x2, [x2, #0x3a8]
// x2 comes from: adrp x2, #0x11e5000
// But ADRP at this address targets: page(0x3fc061c) + ???

// Let's read from various candidate globals
var base = ptr("0x032d4000");
var scanBase = base.add(0x11d5000); // First candidate: base + 0x11d5000 ~= 0x11d5000 (file offset)
var scanEnd = base.add(0x11e6000);

// Actually, let's read the ADRP instruction and decode it
// At 0xcec61c: adrp x2, #0x11e5000
var insnAddr = base.add(0xcec61c);
var insnBytes = insnAddr.readU32();
// ADRP encoding: 1 Xd 10000 immhi immlo 0000 0000 0000 0000 0000 imm
// Actually: 0x90000000 | (immhi << 5) | ...
// Let's just dump nearby globals
console.log("[*] ADRP instruction at " + insnAddr + ": 0x" + insnBytes.toString(16));

// Decode ADRP manually
// bit 31 = 1
// bits 30-29 = 00
// bits 28-24 = 10000 
// bits 23-5 = immhi (19 bits)
// bits 4-0 = Rd
// The imm value is: immhi:immlo sign-extended, shifted by 12
var immhi = (insnBytes >> 5) & 0x7FFFF; // 19 bits
var immlo = (insnBytes >> 29) & 0x3; // 2 bits
var imm = ((immhi << 2) | immlo);
// Sign extend from 21 bits
if (imm & 0x100000) {
    imm = imm - 0x200000;
}
var targetPage = ((0xcec61c + 0x032d4000) & ~0xFFF) + (imm * 0x1000);
console.log("[*] Decoded ADRP imm: 0x" + imm.toString(16) + " (signed: " + (imm >= 0x100000 ? imm - 0x200000 : imm) + ")");
console.log("[*] PC page: 0x" + ((0xcec61c + 0x032d4000) & ~0xFFF).toString(16));
console.log("[*] ADRP target runtime: 0x" + targetPage.toString(16));

// Now read the function pointer at x2 + 0x3a8
var globalBase = ptr(targetPage);
var fnPtrAddr = globalBase.add(0x3a8);
try {
    var fnPtr = fnPtrAddr.readPointer();
    console.log("[*] Function pointer at " + fnPtrAddr + ": " + fnPtr);
    console.log("[*] File offset: 0x" + (fnPtr.toInt32() - 0x032d4000).toString(16));
} catch(e) {
    console.log("[!] Read error: " + e);
}

// Also check what file offset this corresponds to
var fnPtrFileOffset = ptr(fnPtr.toInt32() - 0x032d4000);
console.log("[*] Function at file offset: 0x" + fnPtrFileOffset.toString(16));

// Now read the .rodata strings related to key derivation
// "aes encr" and "aes decr" appear in the lookup table area
// Let's read the second half of the table area
var stringsAddr = globalBase.add(0xf20);
try {
    var data = stringsAddr.readByteArray(0x100);
    var bytes = new Uint8Array(data);
    var s = "";
    for (var i = 0; i < bytes.length; i++) {
        s += String.fromCharCode(bytes[i]);
    }
    console.log("[*] Strings at 0xf20: " + s);
} catch(e) {
    console.log("[!] " + e);
}

send({type: "globals_done"});
"""

device = frida.get_device("socket", timeout=5)
session = device.attach(14027)
def on_message(msg, data):
    print(msg)
script = session.create_script(js)
script.on("message", on_message)
script.load()
time.sleep(3)
session.detach()
