# .mt File Loading Pipeline — Verified from Binary

## Binary: libagame.so (ARM64, 18.87 MB)
## Verification method: Symbol table (SYMTAB/DYNSYM) + disassembly (Capstone) + RELA entries

---

## CORRECTED PIPELINE OVERVIEW

```
Lua require("module")
    │
    ▼
[cocos2dx_lua_loader] @ 0x474028  ← THE entry point for require()
    │  (extracts path from Lua stack, builds full path)
    │
    ▼
FileUtils::getInstance() → returns FileUtilsAndroid* singleton
    │  (bl 0x7d27e8)
    │
    ├─ ldr x2, [x0]          ; x2 = this->vptr
    ├─ mov x8, x23           ; x8 = &output Data (stack-allocated)
    ├─ mov x1, x19           ; x1 = path string
    ├─ ldr x2, [x2, #0x28]   ; x2 = vptr[5] = FileUtilsAndroid::getDataFromFile
    └─ blr x2                ; call getDataFromFile
         │
         ▼
[FileUtilsAndroid::getDataFromFile] @ 0x7d2f38  (40 bytes)
         │  mov w2, #0       ; mode = 0
         │  bl 0x7d2888      ; call getData
         ▼
[FileUtilsAndroid::getData] @ 0x7d2888  (1456 bytes)
         │  Opens file (AAssetManager or fopen), reads raw bytes
         │  Calls Data::decryptData
         ▼
[Data::decryptData] @ 0xc82ab0  (812 bytes)
         │  Checks "Antm" magic → auto-decrypts
         │  Version 1: AES-ECB + zlib/lmF@ decompress
         │  Version 2: XOR + zlib/lmF@ decompress
         ▼
 Data result returned to loader (via x8/x23)
         │
         ├─ bl 0xc828dc  ← Data::getBuffer → x26 = buffer ptr
         ├─ bl 0xc828e4  ← Data::getSize   → x27 = size
         │
         ▼
[LuaStack::luaLoadBuffer] @ 0x47249c  (240 bytes)
         │  x0 = LuaStack* (from LuaEngine::getInstance)
         │  x1 = Lua state
         │  x2 = buffer (decrypted data)
         │  w3 = size
         │  x4 = chunkname
         │
         ├─ If flag(this+0x2c) != 0:
         │    Check magic at buffer start (via 0x3fad00)
         │    If magic matches:
         │      xxtea_decrypt(0x5b2714) → decrypted buffer
         │      luaL_loadbuffer(0x66b13c) with decrypted data
         │      free(decrypted buffer)
         │
         └─ If flag(this+0x2c) == 0 OR magic doesn't match:
              luaL_loadbuffer(0x66b13c) directly
                  │
                  ▼
         [luaL_loadbuffer] @ 0x66b13c  (84 bytes)
                  │  Loads Lua bytecode (or source) into Lua VM
                  ▼
         Lua VM executes the loaded chunk
```

---

## VERIFIED FUNCTION TABLE

| Step | Function | Address | Size | Evidence |
|------|----------|---------|------|----------|
| 1 | `cocos2dx_lua_loader` | 0x474028 | 2052 | Symbol: `cocos2dx_lua_loader`, BL targets confirmed |
| 2 | `FileUtils::getInstance` | 0x7d27e8 | — | Symbol, called from loader @ 0x4742a8 |
| 3 | vtable[5] (offset 0x28) | 0x7d2f38 | — | RELA: _ZTV[7] = 0x7d2f38 for FileUtilsAndroid |
| 4 | `FileUtilsAndroid::getDataFromFile` | 0x7d2f38 | 40 | Symbol, calls getData with mode=0 |
| 5 | `FileUtilsAndroid::getData` | 0x7d2888 | 1456 | Symbol, contains file I/O + calls decryptData |
| 6 | `Data::decryptData` | 0xc82ab0 | 812 | Symbol, checks "Antm" magic |
| 7 | `CCCrypto::xor_decrypt` | 0xceccec | — | Symbol, called from decryptData |
| 8 | `CCCrypto::aes_decrypt` | 0xcec5c0 | — | Symbol, called from decryptData |
| 9 | `CCCrypto::getKey` | 0xcec678 | — | Symbol, called from decryptData |
| 10 | `ZipUtils::inflateMemory` | 0xca41c4 | — | Symbol, called from decryptData |
| 11 | `CCCrypto::uncompressData` | 0xcecd24 | — | Symbol, lmF@ fallback from decryptData |
| 12 | `Data::getBuffer` | 0xc828dc | — | Called @ 0x4742c4 |
| 13 | `Data::getSize` | 0xc828e4 | — | Called @ 0x4742d0 |
| 14 | `LuaStack::luaLoadBuffer` | 0x47249c | 240 | Symbol, called @ 0x474300 |
| 15 | `xxtea_decrypt` | 0x5b2714 | — | Called from luaLoadBuffer |
| 16 | `luaL_loadbuffer` | 0x66b13c | 84 | Symbol, called from luaLoadBuffer |

---

## DUAL ENTRY POINTS (IMPORTANT CORRECTION)

### Entry 1: `require()` — Primary for .mt files
```
Lua require() → cocos2dx_lua_loader (0x474028)
    → vptr[0x28] = getDataFromFile (0x7d2f38)
    → getData(mode=0)
    → decryptData
    → LuaStack::luaLoadBuffer (XXTEA optional) → luaL_loadbuffer
```
This is the path used by Lua's `require()` function to load .mt files. The `cocos2dx_lua_loader` is registered as the Lua loader.

### Entry 2: `cc.FileUtils:getStringFromFile()` — Explicit Lua API call
```
Lua cc.FileUtils:getInstance():getStringFromFile("path")
    → lua_cocos2dx_FileUtils_getStringFromFile (0x4ed8b4, tolua++ binding)
    → vptr[0x20] = getStringFromFile (0x7d2e38)
    → getData(mode=1)
    → decryptData
    → returns string to Lua
```
This is the tolua++ exported API. Used when Lua scripts explicitly call `getStringFromFile`.

### Key difference:
- `cocos2dx_lua_loader` gets Data → LuaStack::luaLoadBuffer → luaL_loadbuffer
- `lua_cocos2dx_FileUtils_getStringFromFile` returns string directly to Lua

---

## VTABLE DISPATCH (CORRECTED)

### FileUtilsAndroid vtable layout (from RELA entries @ 0x1173ef0)

| vptr offset | Slot | Function | Address |
|-------------|------|----------|---------|
| [0x00] | 0 | ~FileUtilsAndroid (complete dtors) | 0x7d14a0 |
| [0x08] | 1 | ~FileUtilsAndroid (deleting dtors) | 0x7d14b4 |
| [0x10] | 2 | inherited Ref function 1 | 0xc616b4 |
| [0x18] | 3 | inherited Ref function 2 | 0xc6ab2c |
| [0x20] | **4** | **getStringFromFile (override)** | **0x7d2e38** |
| [0x28] | **5** | **getDataFromFile (override)** | **0x7d2f38** |
| [0x30] | 6 | getFileData (override) | 0x7d1600 |
| [0x38] | 7 | inherited | 0xc60fcc |
| [0x40] | 8 | inherited | 0xc63d98 |
| [0x48] | 9 | inherited | 0xc6598c |
| [0x50] | 10 | inherited | 0xc62b38 |
| [0x58] | 11 | inherited | 0xc61130 |
| [0x60] | 12 | platform-specific | 0x7d1524 |
| [0x68] | **13** | **isFileExist (?)** | **0xc6b370** |
| ... | ... | ... | ... |

### Why this matters:
- vptr[0x28] (slot 5) is called by `cocos2dx_lua_loader` → dispatches to **getDataFromFile** (0x7d2f38) ✓
- vptr[0x20] (slot 4) is called by `lua_cocos2dx_FileUtils_getStringFromFile` → dispatches to **getStringFromFile** (0x7d2e38) ✓
- The `cocos2dx_lua_loader` does NOT call getStringFromFile — it calls getDataFromFile directly (faster, no string conversion)

---

## DATA FLOW

### Buffer lifecycle through the pipeline:

```
1. FileUtilsAndroid::getData
   └─ AAssetManager / fopen → raw .mt bytes → heap buffer
   
2. Data::decryptData (called from within getData)
   └─ checks magic "Antm" at offset 0
      ├─ if NO match: returns (buffer unchanged)
      └─ if MATCH:
         ├─ version 1: AES-decrypt payload → zlib/lmF@ decompress → new buffer
         ├─ version 2: XOR-decrypt payload → zlib/lmF@ decompress → new buffer
         └─ replaces Data's internal buffer pointer and size
   
3. getData returns Data to getDataFromFile
   └─ getDataFromFile returns Data to cocos2dx_lua_loader
   
4. cocos2dx_lua_loader extracts buffer/size:
   └─ Data::getBuffer → pointer
   └─ Data::getSize → size
   
5. LuaStack::luaLoadBuffer receives the buffer
   └─ if flag(this+0x2c) != 0 AND buffer has XXTEA signature:
      ├─ xxtea_decrypt → new decrypted buffer
      ├─ luaL_loadbuffer(decrypted, ...)
      └─ free decrypted buffer
   └─ else:
      └─ luaL_loadbuffer(buffer, size, ...)
```

### XXTEA fields in LuaStack:
| Offset | Field | Description |
|--------|-------|-------------|
| +0x2c | flag (byte) | 0 = skip XXTEA, non-0 = attempt |
| +0x30 | xxtea_key | string pointer (decryption key) |
| +0x38 | xxtea_key_len | length of key |
| +0x40 | xxtea_sign | string pointer (signature/magic to detect XXTEA) |
| +0x48 | xxtea_sign_len | length of signature |

### XXTEA flow in luaLoadBuffer (0x47249c):
```
1. Load byte from this+0x2c (flag)
2. If flag == 0: go to step 6 (skip XXTEA)
3. If flag != 0: call 0x3fad00(buffer, this->xxtea_sign, sign_len)
   → checks if buffer starts with the XXTEA signature
4. If signature doesn't match: go to step 6
5. If signature matches:
   a. Skip sign_len bytes from buffer start
   b. xxtea_decrypt(remaining_data, data_len, key, key_len → output_buf, output_size)
   c. luaL_loadbuffer(lua_state, output_buf, output_size, chunkname)
   d. free(output_buf)
   e. return
6. luaL_loadbuffer(lua_state, buffer, size, chunkname)  ← raw passthrough
```

---

## DECRYPTION SUB-FUNCTIONS

### Data::decryptData (0xc82ab0)
```
Data::decryptData(this):
  if this->size < 16: return
  magic = *(uint32*)this->ptr
  if magic != 'Antm' (0x6D746E41): return     // not .mt file
  
  version = this->ptr[4]
  xor_key = *(uint32*)(ptr+8) ^ 0x00ABCDEF
  
  if version == 2:                              // most common
    CCCrypto::xor_decrypt(ptr+16, payload_size)  // xor inner payload
    result = ZipUtils::inflateMemory(...)        // zlib inflate
    if result == NULL:                           // if not zlib format
      result = CCCrypto::uncompressData(...)     // lmF@ format fallback
    replace Data buffer with result
    
  if version == 1:                              // less common
    key = CCCrypto::getKey()                     // retrieve AES key
    CCCrypto::aes_decrypt(ptr+16, size, key, out) // AES decrypt
    result = ZipUtils::inflateMemory(...)        // zlib inflate
    if result == NULL:
      result = CCCrypto::uncompressData(...)     // lmF@ fallback
    replace Data buffer with result
```

### Called from decryptData:

| Address | Size | Function | Role |
|---------|------|----------|------|
| 0xceccec | — | CCCrypto::xor_decrypt | XOR outer layer (version 2) |
| 0xcec5c0 | — | CCCrypto::aes_decrypt | AES-ECB decrypt (version 1) |
| 0xcec678 | — | CCCrypto::getKey | Retrieve AES key |
| 0xca41c4 | — | ZipUtils::inflateMemory | zlib decompression |
| 0xcecd24 | — | CCCrypto::uncompressData | Custom lmF@ decompressor |

---

## CALL GRAPH (FINAL - VERIFIED)

```
require("module.mt")
  │
  ├─ cocos2dx_lua_loader (0x474028)
  │    │  Extracts path from Lua stack
  │    │  Builds full file path  
  │    │
  │    ├─ bl FileUtils::getInstance (0x7d27e8)
  │    │    └─ returns FileUtilsAndroid* singleton
  │    │
  │    ├─ blr vptr[0x28] → getDataFromFile (0x7d2f38)
  │    │    │  via vtable: _ZTV[2+5] = _ZTV[7] = 0x7d2f38
  │    │    │  mode=0 (returns Data, not string)
  │    │    │
  │    │    └─ bl FileUtilsAndroid::getData (0x7d2888)
  │    │         │  Opens file (AAssetManager for Android, fopen for absolute)
  │    │         │  Reads raw bytes → Data
  │    │         │
  │    │         └─ bl Data::decryptData (0xc82ab0) ← conditional on Antm magic
  │    │              │
  │    │              ├─ [Antm v2] bl CCCrypto::xor_decrypt (0xceccec)
  │    │              ├─ [Antm v1] bl CCCrypto::aes_decrypt (0xcec5c0)
  │    │              │              bl CCCrypto::getKey (0xcec678)
  │    │              ├─ bl ZipUtils::inflateMemory (0xca41c4)  ← zlib
  │    │              └─ bl CCCrypto::uncompressData (0xcecd24) ← lmF@ fallback
  │    │
  │    ├─ bl Data::getBuffer (0xc828dc)  → x26 = buffer
  │    ├─ bl Data::getSize (0xc828e4)    → x27 = size
  │    │
  │    ├─ bl LuaEngine::getInstance (0x46ecb4)
  │    │
  │    └─ bl LuaStack::luaLoadBuffer (0x47249c)
  │         │  x0 = LuaStack*, x1 = L, x2 = buffer, w3 = size, x4 = chunkname
  │         │
  │         ├─ [if XXTEA enabled] bl 0x5b2714 (xxtea_decrypt)
  │         │
  │         └─ bl luaL_loadbuffer (0x66b13c)
  │              │
  │              └─ Lua VM executes bytecode
```

---

## VERIFICATION SOURCES

| Evidence | Location | What it proves |
|----------|----------|----------------|
| DYNSYM symbols | Sections 5+6 of ELF | All function addresses and sizes |
| SYMTAB symbols | Section 3 of ELF | Additional mangled C++ symbols |
| RELA (vtable) | .rela.dyn @ 0x28cb78 | Vtable slot→function mappings |
| Disassembly | Capstone on .text | BL targets, calling conventions, register usage |
| Function signatures | ARM64 calling convention | Parameter count, return type via x8 |

### Key findings:
- `cocos2dx_lua_loader` @ 0x474028 is the `require()` handler (NOT the tolua++ binding)
- vptr[0x28] = getDataFromFile (confirmed via RELA + cross-reference)
- Data::decryptData checks "Antm" magic (confirmed via BL targets in getData)
- LuaStack::luaLoadBuffer has conditional XXTEA path (confirmed via disassembly)
- Two-stage decryption possible: Antm format → optional XXTEA

### Hypotheses (unverified):
- XXTEA signature length and key values (not extracted from runtime)
- AES key derivation in getKey (not reversed)
- lmF@ decompression algorithm details (not fully reversed)
- Whether the game actually ENABLES the XXTEA flag (this+0x2c)
- Exact magic string for XXTEA in LuaStack fields
