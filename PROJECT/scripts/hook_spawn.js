'use strict';

console.log("[+] Hook script loaded.");

// Hook dlopen to catch libagame.so loading
var dlopen = Module.findExportByName(null, "dlopen");
var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");

function onLibraryLoaded(libName) {
  if (libName.indexOf("libagame.so") >= 0) {
    console.log("[+] libagame.so LOADED!");
    setTimeout(installHooks, 100);
  }
}

if (dlopen) {
  Interceptor.attach(dlopen, {
    onEnter: function(args) {
      this.libName = args[0].readCString();
    },
    onLeave: function(retval) {
      if (this.libName && retval) {
        onLibraryLoaded(this.libName);
      }
    }
  });
}

if (android_dlopen_ext) {
  Interceptor.attach(android_dlopen_ext, {
    onEnter: function(args) {
      try { this.libName = args[0].readCString(); } catch(e) {}
    },
    onLeave: function(retval) {
      if (this.libName && retval) {
        onLibraryLoaded(this.libName);
      }
    }
  });
}

function installHooks() {
  var BASE = Module.findBaseAddress("libagame.so");
  if (!BASE) {
    console.log("[-] libagame.so not found after loading");
    return;
  }
  console.log("[+] libagame.so @ " + BASE);
  
  // Try export names first
  var setKey = Module.findExportByName("libagame.so", "_ZN9CCCrypto6setKeyEPKc");
  var getKey = Module.findExportByName("libagame.so", "_ZN9CCCrypto6getKeyEv");
  var getKey2 = Module.findExportByName("libagame.so", "_ZN9CCCrypto7getKey2Ev");
  
  if (setKey) {
    console.log("[+] Hooking setKey (export) @ " + setKey);
    Interceptor.attach(setKey, {
      onEnter: function(args) {
        try {
          console.log("\n=== CCCrypto::setKey ===");
          console.log("KEY: " + args[1].readCString());
        } catch(e) {
          console.log("[setKey err] " + e);
        }
      }
    });
  }
  
  if (getKey) {
    console.log("[+] Hooking getKey (export) @ " + getKey);
    Interceptor.attach(getKey, {
      onLeave: function(retval) {
        try {
          var dataPtr = retval.add(0x10).readU64();
          var size = retval.add(0x00).readU64();
          if (dataPtr && !dataPtr.isNull()) {
            var bytes = dataPtr.readByteArray(Math.min(Number(size), 64));
            var hex = "";
            for (var i = 0; i < bytes.length; i++) {
              hex += ("0" + bytes[i].toString(16)).slice(-2);
            }
            console.log("\n=== CCCrypto::getKey ===");
            console.log("KEY: " + hex);
          }
        } catch(e) {
          console.log("[getKey err] " + e);
        }
      }
    });
  }
  
  if (!setKey && !getKey) {
    // Fallback: use offsets from emulator binary
    console.log("[-] Exports not found, trying offsets...");
    try {
      Interceptor.attach(BASE.add(0xceca74), {
        onEnter: function(args) {
          try {
            console.log("\n=== setKey (offset) ===");
            console.log("KEY: " + args[1].readCString());
          } catch(e) {}
        }
      });
    } catch(e) {
      console.log("[offset setKey failed] " + e);
    }
    try {
      Interceptor.attach(BASE.add(0xcec678), {
        onLeave: function(retval) {
          try {
            var dataPtr = retval.add(0x10).readU64();
            var size = retval.add(0x00).readU64();
            if (dataPtr && !dataPtr.isNull()) {
              var bytes = dataPtr.readByteArray(Math.min(Number(size), 64));
              var hex = "";
              for (var i = 0; i < bytes.length; i++) {
                hex += ("0" + bytes[i].toString(16)).slice(-2);
              }
              console.log("\n=== getKey (offset) ===");
              console.log("KEY: " + hex);
            }
          } catch(e) {}
        }
      });
    } catch(e) {
      console.log("[offset getKey failed] " + e);
    }
  }
  
  console.log("[+] Hooks installed.");
}
