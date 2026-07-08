'use strict';

console.log('[+] Hooking strlen to capture AES keys...');

try {
    var strlenAddr = Module.getGlobalExportByName("strlen");
    console.log('[+] strlen @ ' + strlenAddr);

    var foundKeys = {};
    var hookCount = 0;

    Interceptor.attach(strlenAddr, {
        onEnter: function(args) {
            this.ptr = args[0];
        },
        onLeave: function(retval) {
            var len = retval.toInt32();
            if (len === 32 || len === 33) {
                try {
                    var s = this.ptr.readCString();
                    if (/^[0-9a-f]{32}$/i.test(s)) {
                        if (!foundKeys[s]) {
                            foundKeys[s] = 1;
                            console.log('\n[KEY] FOUND AES KEY: ' + s);
                            console.log('[KEY] Length: ' + len);
                        }
                    }
                } catch(e) {}
            }
        }
    });
    console.log('[+] strlen hook installed, waiting for key...');
} catch(e) {
    console.log('[-] Error: ' + e);
}
