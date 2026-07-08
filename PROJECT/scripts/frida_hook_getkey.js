/*
  Frida hook: Capture AES key from CCCrypto functions
  API: Frida 17.x — use Module.findBaseAddress
*/

const BASE = Module.findBaseAddress("libagame.so");
if (!BASE) {
  console.log("[!] libagame.so not found!");
  Process.enumerateModules().forEach(function(m) {
    if (m.name.indexOf("agame") >= 0) console.log("    found: " + m.name + " @ " + m.base);
  });
} else {
  console.log("[+] libagame.so @ " + BASE);
}

// ── Hook CCCrypto::setKey ──────────────────────────────────────────
// void setKey(CCCrypto* this, const char* hex_string)
// Called ONCE at startup → sets m_sKey
const setKeyAddr = BASE.add(0xceca74);
console.log("[+] setKey @ " + setKeyAddr);
Interceptor.attach(setKeyAddr, {
  onEnter: function (args) {
    try {
      const hexStr = args[1].readCString();
      console.log("\n=== CCCrypto::setKey ===");
      console.log("    hex: " + hexStr);
      console.log("    *** KEY FOUND: " + hexStr);
    } catch (e) {
      console.log("    [err reading string: " + e + "]");
    }
  }
});

// ── Hook CCCrypto::getKey ──────────────────────────────────────────
// Returns std::string* in x0 (stack-allocated string object)
const getKeyAddr = BASE.add(0xcec678);
console.log("[+] getKey @ " + getKeyAddr);
Interceptor.attach(getKeyAddr, {
  onLeave: function (retval) {
    console.log("\n=== CCCrypto::getKey ===");
    console.log("    returned ptr: " + retval);
    try {
      const dataPtr = retval.add(0x10).readU64();
      const size = retval.add(0x00).readU64();
      console.log("    size: " + size + "  data: " + dataPtr);
      if (dataPtr && !dataPtr.isNull()) {
        const bytes = dataPtr.readByteArray(Math.min(Number(size), 64));
        let hex = "";
        for (let i = 0; i < bytes.length; i++) {
          hex += ("0" + bytes[i].toString(16)).slice(-2);
        }
        console.log("    *** AES KEY: " + hex);
      }
    } catch (e) {
      console.log("    read error: " + e);
    }
  }
});

// ── Hook CCCrypto::xor_decrypt ─────────────────────────────────────
// void xor_decrypt(char* data, unsigned int len)
const xorAddr = BASE.add(0xceccec);
console.log("[+] xor_decrypt @ " + xorAddr);
Interceptor.attach(xorAddr, {
  onEnter: function (args) {
    console.log("\n=== CCCrypto::xor_decrypt ===");
    console.log("    data=" + args[0] + " len=" + args[1]);
    try {
      console.log(hexdump(args[0].readByteArray(32), { length: 32 }));
    } catch(e) {}
  }
});

// ── Hook CCCrypto::aes_decrypt ─────────────────────────────────────
// void aes_decrypt(input, ?, key_ref, output, size)
const aesAddr = BASE.add(0xcec5c0);
console.log("[+] aes_decrypt @ " + aesAddr);
Interceptor.attach(aesAddr, {
  onEnter: function (args) {
    console.log("\n=== CCCrypto::aes_decrypt ===");
    console.log("    input=" + args[0] + " size=" + args[4]);
    console.log("    keyRef=" + args[2]);
    try {
      const keyDataP = args[2].add(0x10).readU64();
      const keySize  = args[2].add(0x00).readU64();
      console.log("    key ptr=" + keyDataP + " keySize=" + keySize);
      if (keyDataP && !keyDataP.isNull()) {
        const kb = keyDataP.readByteArray(Math.min(Number(keySize), 32));
        let hex = "";
        for (let i = 0; i < kb.length; i++) {
          hex += ("0" + kb[i].toString(16)).slice(-2);
        }
        console.log("    *** AES KEY: " + hex);
      }
    } catch(e) {
      console.log("    key read error: " + e);
    }
  }
});

// ── Hook Data::decryptData ─────────────────────────────────────────
// Called when game loads .mt files
const decryptDataAddr = BASE.add(0xc82ab0);
console.log("[+] decryptData @ " + decryptDataAddr);
Interceptor.attach(decryptDataAddr, {
  onEnter: function (args) {
    console.log("\n=== Data::decryptData ===");
    console.log("    this=" + args[0]);
    try {
      const ptr = args[0].add(0x00).readU64();
      const sz  = args[0].add(0x08).readU64();
      console.log("    ptr=" + ptr + " size=" + sz);
      if (ptr) {
        console.log("    first 16 bytes: " + hexdump(ptr.readByteArray(16), {length:16}));
      }
    } catch(e) {}
  }
});

console.log("\n[+] Hooks active. Waiting for crypto calls...");
