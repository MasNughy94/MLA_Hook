'use strict';

console.log("[+] Hook script loaded.");

// Hook dlopen / android_dlopen_ext to detect libagame.so loading
var dlopen = Module.getGlobalExportByName("dlopen");
var android_dlopen_ext = Module.getGlobalExportByName("android_dlopen_ext");

function onLibLoaded(name) {
  if (name.indexOf("libagame.so") >= 0) {
    console.log("[+] libagame.so LOADED!");
    setTimeout(installHooks, 200);
  }
}

if (dlopen) {
  Interceptor.attach(dlopen, {
    onEnter: function(args) {
      this.libName = args[0].readCString();
    },
    onLeave: function(retval) {
      if (this.libName && !retval.isNull()) {
        onLibLoaded(this.libName);
      }
    }
  });
  console.log("[+] Hooked dlopen @ " + dlopen);
}

if (android_dlopen_ext) {
  Interceptor.attach(android_dlopen_ext, {
    onEnter: function(args) {
      try { this.libName = args[0].readCString(); } catch(e) {}
    },
    onLeave: function(retval) {
      if (this.libName && !retval.isNull()) {
        onLibLoaded(this.libName);
      }
    }
  });
  console.log("[+] Hooked android_dlopen_ext @ " + android_dlopen_ext);
}

function installHooks() {
  var mod = Process.getModuleByName("libagame.so");
  if (!mod) {
    console.log("[-] libagame.so not found via getModuleByName");
    return;
  }
  var BASE = mod.base;
  console.log("[+] libagame.so @ " + BASE + " size=" + mod.size);

  // Try to find crypto symbols via getGlobalExportByName
  var cryptoFuncs = [
    "_ZN9CCCrypto6setKeyEPKc",
    "_ZN9CCCrypto6getKeyEv",
    "_ZN9CCCrypto7getKey2Ev",
    "_ZN9CCCrypto11aes_decryptEPKcPvS1_j",
    "_ZN9CCCrypto11xor_decryptEPcj",
    "_ZN4Data11decryptDataEv"
  ];

  var found = {};
  for (var i = 0; i < cryptoFuncs.length; i++) {
    try {
      var addr = Module.getGlobalExportByName("libagame.so!" + cryptoFuncs[i]);
      found[cryptoFuncs[i]] = addr;
      console.log("[+] Found: " + cryptoFuncs[i] + " @ " + addr);
    } catch(e) {
      // not exported
    }
  }

  // Hook setKey
  if (found["_ZN9CCCrypto6setKeyEPKc"]) {
    Interceptor.attach(found["_ZN9CCCrypto6setKeyEPKc"], {
      onEnter: function(args) {
        try {
          console.log("\n=== CCCrypto::setKey ===");
          console.log("KEY: " + args[1].readCString());
        } catch(e) {
          console.log("[setKey err] " + e);
        }
      }
    });
    console.log("[+] setKey hooked (export)");
  } else {
    console.log("[-] setKey not exported, trying offset 0xceca74");
    try {
      Interceptor.attach(BASE.add(0xceca74), {
        onEnter: function(args) {
          try {
            console.log("\n=== CCCrypto::setKey (offset) ===");
            console.log("KEY: " + args[1].readCString());
          } catch(e) {}
        }
      });
      console.log("[+] setKey hooked (offset)");
    } catch(e) {
      console.log("[-] setKey offset hook failed: " + e);
    }
  }

  // Hook getKey
  if (found["_ZN9CCCrypto6getKeyEv"]) {
    Interceptor.attach(found["_ZN9CCCrypto6getKeyEv"], {
      onLeave: function(retval) {
        try {
          var dataPtr = retval.add(0x10).readU64();
          var size = retval.add(0x00).readU64();
          if (dataPtr && !dataPtr.isNull()) {
            var bytes = dataPtr.readByteArray(Math.min(Number(size), 64));
            var hex = "";
            for (var j = 0; j < bytes.length; j++) {
              hex += ("0" + bytes[j].toString(16)).slice(-2);
            }
            console.log("\n=== CCCrypto::getKey ===");
            console.log("KEY: " + hex);
          }
        } catch(e) {
          console.log("[getKey err] " + e);
        }
      }
    });
    console.log("[+] getKey hooked (export)");
  } else {
    console.log("[-] getKey not exported, trying offset 0xcec678");
    try {
      Interceptor.attach(BASE.add(0xcec678), {
        onLeave: function(retval) {
          try {
            var dataPtr = retval.add(0x10).readU64();
            var size = retval.add(0x00).readU64();
            if (dataPtr && !dataPtr.isNull()) {
              var bytes = dataPtr.readByteArray(Math.min(Number(size), 64));
              var hex = "";
              for (var j = 0; j < bytes.length; j++) {
                hex += ("0" + bytes[j].toString(16)).slice(-2);
              }
              console.log("\n=== CCCrypto::getKey (offset) ===");
              console.log("KEY: " + hex);
            }
          } catch(e) {}
        }
      });
      console.log("[+] getKey hooked (offset)");
    } catch(e) {
      console.log("[-] getKey offset hook failed: " + e);
    }
  }

  console.log("[+] Hooks installed.");
}

// Also try to install hooks immediately in case libagame.so is already loaded
var existingMod = Process.getModuleByName("libagame.so");
if (existingMod) {
  console.log("[+] libagame.so already loaded, installing hooks now.");
  installHooks();
}
