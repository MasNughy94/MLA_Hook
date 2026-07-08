console.log("Testing getGlobalExportByName for crypto functions...");
var funcs = [
  "_ZN9CCCrypto6setKeyEPKc",
  "_ZN9CCCrypto6getKeyEv",
  "_ZN9CCCrypto7getKey2Ev",
  "_ZN9CCCrypto11aes_decryptEPKcPvS1_j",
  "_ZN9CCCrypto11xor_decryptEPcj",
  "_ZN4Data11decryptDataEv",
  "_ZN9CCCrypto11uncompressEPKcjPj"
];
for (var i = 0; i < funcs.length; i++) {
  try {
    var addr = Module.getGlobalExportByName(funcs[i]);
    console.log("FOUND: " + funcs[i] + " @ " + addr);
  } catch(e) {
    console.log("MISS: " + funcs[i]);
  }
}
console.log("Done.");
