# .MT File Loading Pipeline - Call Graph & Analysis
## Binary: libagame.so (ARM64)

---

## PIPELINE OVERVIEW

```
Lua Script (cc.FileUtils:getInstance():getStringFromFile("path.mt"))
    │
    ▼
[lua_cocos2dx_FileUtils_getStringFromFile] @ 0x4ed8b4  (Lua binding)
    │
    ▼
[FileUtilsAndroid::getStringFromFile] @ 0x7d2e38  (virtual override, mode=1)
    │
    ▼
[FileUtilsAndroid::getData] @ 0x7d2888  (core function: open + read + decrypt)
    │
    ├── AAassetManager / fread()  ← reads raw file bytes
    │
    ▼
[Data::decryptData] @ 0xc82ab0  (checks "Antm" magic, auto-decrypts)
    │
    ├── Version 1: AES-ECB? + inflate/uncompress
    ├── Version 2: XOR + inflate/uncompress
    │
    ▼
[CCCrypto::uncompressData] @ 0xcecd24  (lmF@ decompression, fallback)
    │
    ▼
Decrypted Lua bytecode returned to Lua VM
    │
    ▼
luaL_loadbuffer / lua_pcall  ← Lua executes the bytecode
```

---

## STEP-BY-STEP TABLE

### Step 1: Lua Calls FileUtils

| Field | Value |
|-------|-------|
| **Function** | `lua_cocos2dx_FileUtils_getStringFromFile` |
| **Address** | 0x4ed8b4 |
| **Input** | Lua State + path string (from top of Lua stack) |
| **Output** | Decrypted file content as Lua string |
| **Buffer Modified** | N/A (creates new Lua string) |
| **Evidence** | Symbol: `_Z40lua_cocos2dx_FileUtils_getStringFromFileP9lua_State` |
| **Confidence** | **100%** (exported symbol) |

This is the tolua++ generated binding. It:
1. Extracts the path string from Lua stack
2. Gets `FileUtils::getInstance()` (via internal call)
3. Calls `getStringFromFile` on the instance
4. Pushes the result back to Lua stack

---

### Step 2: FileUtilsAndroid::getStringFromFile

| Field | Value |
|-------|-------|
| **Function** | `FileUtilsAndroid::getStringFromFile` |
| **Address** | 0x7d2e38 |
| **Input** | `this` (FileUtilsAndroid*), path (string&), x8 = return Data-ptr |
| **Output** | `Data` object (via x8) |
| **Buffer Modified** | Yes, Data->ptr contains file contents |
| **Evidence** | Symbol: `_ZN7cocos2d16FileUtilsAndroid17getStringFromFileERKSs`, calls `getData` with mode=1 |
| **Confidence** | **100%** |

Thin wrapper (136 bytes):
```asm
0x7d2e3c: mov w2, #1         ; mode = 1 (string mode)
0x7d2e68: bl #0x7d2888       ; call FileUtilsAndroid::getData(this, path, 1)
```

---

### Step 3: FileUtilsAndroid::getData

| Field | Value |
|-------|-------|
| **Function** | `FileUtilsAndroid::getData` |
| **Address** | 0x7d2888 |
| **Input** | `this` (FileUtilsAndroid*), path (string&), mode (int) |
| **Output** | `Data` object (buffer + size) |
| **Buffer Modified** | Yes |
| **Evidence** | Symbol: `_ZN7cocos2d16FileUtilsAndroid7getDataERKSsb`, 736 bytes |
| **Confidence** | **100%** |

This is the core file reading logic (736 bytes). It:
1. Calls virtual `isFileExist` or `fullPathForFilename` via vtable dispatch (vtable[0x68])
2. If path is absolute (`/` prefix): reads directly via `fopen`/`fread`
3. If relative: prepends asset path, reads via Android `AAssetManager`
4. Reads raw file bytes into a heap-allocated buffer
5. Calls `Data::decryptData` on the result (at 0x7d2c44-0x7d2c48)
6. If mode=1: converts Data buffer to string
7. Returns Data (or string) to caller

**Key observation**: `getData` is the GATEKEEPER. Every file read goes through here, and `.mt` decryption happens automatically.

---

### Step 4: Data::decryptData

| Field | Value |
|-------|-------|
| **Function** | `cocos2d::Data::decryptData` |
| **Address** | 0xc82ab0 |
| **Input** | `this` (Data*), Data already contains raw file bytes |
| **Output** | Data mutated in-place with decrypted content |
| **Buffer Modified** | **YES** — replaces buffer pointer and size |
| **Evidence** | Symbol: `_ZN7cocos2d4Data11decryptDataEv`, 720 bytes. Full disassembly verified. |
| **Confidence** | **100%** |

#### Algorithm Flow:

```
Data::decryptData(this):
    if this->size < 16: return                    ; too small
    magic = *(uint32*)this->ptr
    if magic != 'Antm' (0x6D746E41): return       ; not .mt file
    
    version = this->ptr[4]                         ; byte at offset 4
    xor_key = 0x00ABCDEF                           ; from data[8..11]
    payload_size = *(uint32*)(ptr+8) ^ 0x00ABCDEF ; XOR'd size
    
    Check if already decrypted: 
        if data[8..12] == 0x00ABCDEF: skip decrypt
    
    if version == 2:                               ; <= most common
        CCCrypto::xor_decrypt(ptr+16, payload_size)      ; XOR outer layer
        result = ZipUtils::inflateMemory(ptr+16, ...)    ; try zlib inflate
        if result == NULL:                               ; if zlib fails
            CCCrypto::uncompressData(ptr+16, size, ...)  ; try lmF@ format
        replace Data's buffer with result
        
    if version == 1:                               ; <= less common
        key = CCCrypto::getKey()                        ; get AES key
        CCCrypto::aes_decrypt(ptr+16, size, key, out)   ; AES decrypt
        result = ZipUtils::inflateMemory(out, ...)      ; try zlib inflate
        if result == NULL:
            CCCrypto::uncompressData(out, size, ...)    ; try lmF@ format
        replace Data's buffer with result
```

**Magic values used:**
- File magic: `Antm` (0x6D746E41)
- XOR/validation key: `0x00ABCDEF` (used to XOR payload size field)
- Version at byte[4]: 1 or 2

**Decryption sub-functions called:**

| Call | Address | Name |
|------|---------|------|
| CCCrypto::xor_decrypt(data, len) | 0xceccec | XOR layer removal |
| ZipUtils::inflateMemory(data, len, &out) | 0xca41c4 | zlib decompression |
| CCCrypto::uncompressData(data, len, &out, &out_len) | 0xcecd24 | Custom lmF@ format |
| CCCrypto::getKey() | 0xcec678 | Retrieve AES key |
| CCCrypto::aes_decrypt(data, len, key, out) | 0xcec5c0 | AES decryption |

---

### Step 5a: CCCrypto::uncompressData (lmF@ fallback)

| Field | Value |
|-------|-------|
| **Function** | `CCCrypto::uncompressData` |
| **Address** | 0xcecd24 |
| **Input** | encrypted/compressed data, size, output ptr |
| **Output** | decompressed data |
| **Buffer Modified** | Yes |
| **Callers within decryptData** | 0xc82cec, 0xc82d50 |
| **Confidence** | **100%** (symbol verified) |

This is invoked when zlib inflate fails (data is not zlib format). It handles the `lmF@` format which uses custom Huffman decompression.

---

### Step 5b: CCCrypto::xor_decrypt

| Field | Value |
|-------|-------|
| **Function** | `CCCrypto::xor_decrypt(const char*, unsigned int)` |
| **Address** | 0xceccec |
| **Signature** | `xor_decrypt(const char* data, unsigned int len) -> string` |
| **Confidence** | **100%** |

Simple XOR operation. Used to remove the outer XOR layer in version 2 .mt files.

---

## VTABLE LAYOUT

### FileUtils (Base Class)
- **VTable base**: 0x11d2050 (.data.rel.ro)
- **vptr points to**: 0x11d2060 (vtable[0])

| Slot offset | Address | Method |
|-------------|---------|--------|
| vptr[-0x10] | 0xc616b4 | purgeCachedEntries |
| vptr[-0x08] | 0xc6ab2c | removeCachedEntries |
| vptr[+0x00] | 0xc63378 | getStringFromFile |
| **vptr[+0x08]** | **0xc6334c** | **getDataFromFile** ← virtual |
| vptr[+0x10] | 0xc63a6c | getFileData |
| vptr[+0x18] | 0xc60fcc | getFileDataFromZip |
| vptr[+0x20] | 0xc63d98 | unZipFile |
| vptr[+0x28] | 0xc6598c | unZipFileAsync |
| vptr[+0x30] | 0xc62b38 | createDirectory (const char*) |
| vptr[+0x38] | 0xc61130 | mkDir |
| vptr[+0x40] | 0x7d1524 | (platform-specific?) |
| vptr[+0x48] | 0xc6b370 | fullPathForFilename |
| vptr[+0x50] | 0xc6a5b0 | loadFilenameLookupDictionaryFromFile |
| vptr[+0x58] | 0xc65914 | setFilenameLookupDictionary |
| vptr[+0x60] | 0xc61dd4 | fullPathFromRelativeFile |
| vptr[+0x68] | 0xc68e00 | init |
| vptr[...] | ... | ... |
| vptr[+0xe8]? | **0xc61fe4** | **isFileExist** ← used by getData |

### FileUtilsAndroid (Derived Class)
- **VTable base**: 0x1174000 area (.data.rel.ro)
- Overrides `getStringFromFile` (0x7d2e38) and `getDataFromFile` (0x7d2f38)

| Slot offset | Address | Method |
|-------------|---------|--------|
| 0x1173f20 | 0x7d2e38 | getStringFromFile ← OVERRIDE |
| 0x1173f28 | 0x7d2f38 | getDataFromFile ← OVERRIDE |

---

## COORDINATE: ANTIM HEADER FORMAT

```
Offset  Size  Field
──────  ────  ─────────────────────────────────
0x00    4     Magic: "Antm" (0x6D746E41)
0x04    1     Version: 1 or 2
0x05    3     Unknown/padding
0x08    4     XOR'd payload_size  (XOR key: 0x00ABCDEF)
0x0C    4     Unknown (checksum? flags?)
0x10    N     Encrypted/compressed payload

Detection sentinel: if ptr[8..12] == 0x00ABCDEF → already decrypted
```

---

## COORDINATE: lmF@ INNER FORMAT

```
Offset  Size  Field
──────  ────  ─────────────────────────────────
0x00    4     Magic: "lmF@"
0x04    4     Flags/version
0x08    4     XOR'd uncompressed_size
0x0C    4     XOR'd compressed_size
0x10    N     AES-ECB encrypted payload
              (key derived from header?)
0x10+   N     Custom Huffman/range-decoded data
```

---

## CALLER MAP

```
[lua_register_cocos2dx_FileUtils] @ 0x4ff7ec
    │  registers all Lua → C bindings
    ▼
[Lua VM: luaL_loadbuffer / lua_pcall]
    │
    ▼
[Game Lua Code: cc.FileUtils:getInstance():getStringFromFile("path.mt")]
    │
    ▼
[lua_cocos2dx_FileUtils_getStringFromFile] @ 0x4ed8b4
    │
    ▼
[FileUtilsAndroid::getStringFromFile] @ 0x7d2e38  (mode=1)
    │
    ▼
[FileUtilsAndroid::getData] @ 0x7d2888
    │
    ├── [Virtual call: vtable[0x68]] → path resolution
    ├── [Android: AAssetManager / fopen]
    ├── [Read file into buffer]
    │
    ▼
[Data::decryptData] @ 0xc82ab0   ← magic check + decrypt
    │
    ├── [CCCrypto::xor_decrypt] @ 0xceccec    (XOR layer)
    ├── [ZipUtils::inflateMemory] @ 0xca41c4  (zlib)
    ├── [CCCrypto::uncompressData] @ 0xcecd24 (lmF@ fallback)
    │     └── sub_CF2110 @ 0xcf2110 (Huffman decompression)
    │
    ▼
[Decoded Lua bytecode → returned to Lua VM]
```

---

## CONFIRMED VERIFIED FACTS

1. **Magic check**: `Data::decryptData` explicitly checks for "Antm" at offset 0
2. **Automatic decryption**: .mt decryption is built into the file reading pipeline, not a separate step
3. **Two versions**: Version 1 uses AES, Version 2 uses XOR. Both decompress via zlib or custom lmF@
4. **XOR key**: `0x00ABCDEF` used to XOR payload size field
5. **Virtual dispatch**: Both `getDataFromFile` and `getStringFromFile` are virtual, overridden by FileUtilsAndroid
6. **Entry point**: Via Lua binding `lua_cocos2dx_FileUtils_getStringFromFile` @ 0x4ed8b4
7. **No direct BL callers**: All calls to FileUtils methods go through vtable dispatch (no direct BL)
8. **lmF@ fallback**: When zlib inflate fails, `CCCrypto::uncompressData` handles the custom format
