'use strict';

// Scan all writable memory for 32-char hex strings (AES keys)
function hexRelevant(s) {
    return /^[0-9a-f]{32}$/i.test(s);
}

function scanRange(base, size, label) {
    try {
        var bytes = Memory.readByteArray(base, Math.min(size, 0x100000)); // max 1MB per range
        if (!bytes) return;
        var arr = new Uint8Array(bytes);
        
        // Search for printable hex strings
        var ascii = '';
        for (var i = 0; i < arr.length; i++) {
            var b = arr[i];
            if (b >= 0x20 && b <= 0x7e) {
                ascii += String.fromCharCode(b);
            } else {
                if (ascii.length >= 32) {
                    // Check for 32-char hex substrings
                    for (var j = 0; j <= ascii.length - 32; j++) {
                        var sub = ascii.substring(j, j + 32);
                        if (hexRelevant(sub)) {
                            console.log('[KEY] Found: ' + sub + ' @ ' + base.add(i - ascii.length + j) + ' in ' + label);
                        }
                    }
                }
                ascii = '';
            }
        }
        // Handle case where string ends at buffer boundary
        if (ascii.length >= 32) {
            for (var j = 0; j <= ascii.length - 32; j++) {
                var sub = ascii.substring(j, j + 32);
                if (hexRelevant(sub)) {
                    console.log('[KEY] Found: ' + sub + ' @ ' + base.add(arr.length - ascii.length + j) + ' in ' + label);
                }
            }
        }
    } catch(e) {
        // skip ranges we can't read
    }
}

console.log('[+] Scanning writable memory for AES keys...');
var ranges = Process.enumerateRanges('rw-');
console.log('[+] Found ' + ranges.length + ' writable ranges');

for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    var label = r.file ? r.file.path : r.protection;
    scanRange(r.base, r.size, label);
}

console.log('[+] Memory scan complete.');
