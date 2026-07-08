'use strict';

// Read memory and search for hex patterns
function searchHexStrings(buf, base, label) {
    var arr = new Uint8Array(buf);
    var ascii = '';
    for (var i = 0; i < arr.length; i++) {
        var b = arr[i];
        if (b >= 0x20 && b <= 0x7e) {
            ascii += String.fromCharCode(b);
        } else {
            if (ascii.length >= 32) {
                for (var j = 0; j <= ascii.length - 32; j++) {
                    var sub = ascii.substring(j, j + 32);
                    if (/^[0-9a-f]{32}$/i.test(sub)) {
                        console.log('[KEY] ' + sub + ' @ ' + base.add(i - ascii.length + j) + ' (' + label + ')');
                    }
                }
            }
            ascii = '';
        }
    }
    if (ascii.length >= 32) {
        for (var j = 0; j <= ascii.length - 32; j++) {
            var sub = ascii.substring(j, j + 32);
            if (/^[0-9a-f]{32}$/i.test(sub)) {
                console.log('[KEY] ' + sub + ' @ ' + base.add(arr.length - ascii.length + j) + ' (' + label + ')');
            }
        }
    }
}

// Known addresses from /proc/pid/maps
var targets = [
    {base: ptr('0x041f4000'), size: 0x17000, label: 'libagame BSS'},
    {base: ptr('0x0420b000'), size: 0x5e000, label: 'anon BSS ext'},
    // Also check the rodata for our known key
    {base: ptr('0x0300c000'), size: 0x115c000, label: 'libagame RO'},
];

console.log('[+] Scanning specific targets...');
for (var t = 0; t < targets.length; t++) {
    var target = targets[t];
    console.log('[+] Reading ' + target.label + ' @ ' + target.base + ' size ' + target.size.toString(16));
    try {
        var buf = Memory.readByteArray(target.base, target.size);
        if (buf) {
            console.log('[+] Read ' + buf.byteLength + ' bytes');
            searchHexStrings(buf, target.base, target.label);
        }
    } catch(e) {
        console.log('[-] Error reading ' + target.label + ': ' + e);
    }
}

console.log('[+] Done');
