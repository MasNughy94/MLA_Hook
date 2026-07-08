console.log("Searching for libagame.so in memory...");

// Check if we can find the module by different name
var mod = Process.getModuleByName("libagame.so");
if (mod) {
  console.log("FOUND: libagame.so @ " + mod.base + " size=" + mod.size);
} else {
  console.log("libagame.so not found by name");
}

// Try to find it via enumerateRanges looking for ELF headers
var ranges = Process.enumerateRanges('r--');
console.log("r-x ranges: " + ranges.length);
for (var i = 0; i < ranges.length; i++) {
  try {
    var magic = Memory.readCString(ranges[i].base, 4);
    if (magic === '\u007fELF') {
      console.log("  ELF @ " + ranges[i].base + " - " + ranges[i].size + " - " + ranges[i].protection);
    }
  } catch(e) {}
}

// Also try r-x ranges
var rxRanges = Process.enumerateRanges('r-x');
console.log("r-x ranges: " + rxRanges.length);
for (var i = 0; i < Math.min(rxRanges.length, 10); i++) {
  try {
    var magic = Memory.readCString(rxRanges[i].base, 4);
    if (magic === '\u007fELF') {
      console.log("  ELF(r-x) @ " + rxRanges[i].base + " - " + rxRanges[i].size + " - " + rxRanges[i].protection);
    }
  } catch(e) {}
}

// Last resort: check getModuleByAddress for any loaded so with 'game'
var allMods = Process.enumerateModules();
for (var i = 0; i < allMods.length; i++) {
  var m = allMods[i];
  if (m.name.indexOf("lib") >= 0 && m.size > 10000000) { // libs over 10MB
    console.log("BIG MOD: " + m.name + " @ " + m.base + " size=" + m.size);
  }
}

console.log("Done.");
