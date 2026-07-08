# Data::decryptData — Complete Technical Specification

## Binary: libagame.so (ARM64)
## Address: 0xc82ab0
## Size: 812 bytes
## Symbol: `_ZN7cocos2d4Data11decryptDataEv`

---

## 1. OVERVIEW

`Data::decryptData()` is a member function of `cocos2d::Data` that decrypts `.mt` file
contents in-place. It is called from `FileUtilsAndroid::getData()` (0x7d2888) after
raw file bytes have been read.

The function checks for the `Antm` magic header, then applies one of two decryption
paths depending on the version byte. Both paths decompress the inner payload using
either zlib (gzip) inflate or a custom `lmF@` decompressor (via `CCCrypto::uncompressData`).

---

## 2. Data CLASS LAYOUT (offsets used by this function)

```
Offset  Size  Type    Field         Description
──────  ────  ──────  ────────────  ──────────────────────────────
+0x00     8   char*   _ptr          Pointer to raw data buffer
+0x08     8   size_t  _size         Size of data in bytes
+0x10     8   char*   _tmp          Temporary buffer pointer (save/restore)
+0x18     1   byte    _flags        Bit flags (bit 0 = 1 if decompressed)
```

**Evidence**: `ldr x0, [x20]` / `ldr x1, [x20, #8]` / `str x0, [x20, #0x10]`
at 0xc82ba8 / `strb w1, [x20, #0x18]` at 0xc82c8c.

---

## 3. CALLED FUNCTIONS (complete reference)

Note: For each function, signature is from the mangled symbol name in SYMTAB.

### 3a. `CCCrypto::xor_decrypt` @ 0xceccec (56 bytes)

| Field | Value |
|-------|-------|
| Symbol | `_ZN8CCCrypto11xor_decryptEPcj` |
| Signature | `void xor_decrypt(char* data, unsigned int len)` |
| Evidence | `bl 0xceccec` @ 0xc82b64; x0 = buffer+0x10, w1 = payload_size |
| Effect | XORs payload in-place (key derived from buffer content / hardcoded table) |

### 3b. `CCCrypto::getKey` @ 0xcec678 (44 bytes)

| Field | Value |
|-------|-------|
| Symbol | `_ZN8CCCrypto6getKeyEv` |
| Signature | `void getKey()` (no params per mangling; return via x8 like std::string) |
| Evidence | `bl 0xcec678` @ 0xc82be8; x8 = &stack_string at x29+0x60 |
| Effect | Constructs a `std::string` containing the AES key at the address in x8 |

**HYPOTHESIS**: The function constructs a `std::string` containing the AES
key material. The string is built at the stack location pointed to by x8.

### 3c. `CCCrypto::aes_decrypt` @ 0xcec5c0 (184 bytes)

| Field | Value |
|-------|-------|
| Symbol | `_ZN8CCCrypto11aes_decryptEPKcS1_RKSsPci` |
| Signature | `void aes_decrypt(const char* input, const char* ?, const std::string& key, char* output, int size)` |
| Parameters | x0 = encrypted data, x1 = ? (unused/end marker?), x2 = &key, x3 = output buffer, w4 = data length |
| Evidence | `bl 0xcec5c0` @ 0xc82c0c; args set @ 0xc82bf8-0xc82c08 |
| Return | w0 = 0 (failure) or 1 (success) |
| Internal | First insn: `ldr x2, [x2]` loads key.data_ptr; `ldur x2, [x2, #-0x18]` obtains key length |

**HYPOTHESIS**: The 2nd parameter (const char*) may be an IV or is unused.
The actual output goes to the 4th parameter (char* output = x3 = x24).

### 3d. `ZipUtils::inflateMemory` @ 0xca41c4 (8 bytes)

| Field | Value |
|-------|-------|
| Symbol | `_ZN7cocos2d8ZipUtils13inflateMemoryEPhlPS1_` |
| Signature | `unsigned char* inflateMemory(unsigned char* data, unsigned long len, unsigned char** outPtr)` |
| Parameters | x0 = compressed data, x1 = compressed size, x2 = &out_ptr |
| Evidence | `bl 0xca41c4` @ 0xc82b98, 0xc82c78 |
| Return | x0 = pointer to decompressed buffer (NULL on failure) |

### 3e. `ZipUtils::isGZipBuffer` @ 0xca4638 (52 bytes)

| Field | Value |
|-------|-------|
| Symbol | `_ZN7cocos2d8ZipUtils12isGZipBufferEPKhl` |
| Signature | `bool isGZipBuffer(const unsigned char* data, long len)` |
| Check | data[0] == 0x1F && data[1] == 0x8B (gzip magic) |
| Evidence | `bl 0xca4638` @ 0xc82b7c, 0xc82c60; confirmed by disassembly of 0xca4638 |
| Return | w0 = 0 (not gzip) or 1 (is gzip) |

### 3f. `CCCrypto::uncompressData` @ 0xcecd24 (704 bytes)

| Field | Value |
|-------|-------|
| Symbol | `_ZN8CCCrypto14uncompressDataEPcjPPhRm` |
| Signature | `bool uncompressData(char* data, unsigned int len, char*& outPtr, unsigned long& outSize)` |
| Parameters | x0 = compressed data, w1 = len, x2 = &out_ptr, x3 = &out_size |
| Evidence | `bl 0xcecd24` @ 0xc82cec, 0xc82d50 |
| Return | w0 = 0 (failure) or 1 (success); outputs via x2/x3 references |
| Internal | Checks if len < 0xD → returns 0 (too small to be lmF@) |

### 3g. `Data::clear` @ 0xc828f8 (76 bytes)

| Field | Value |
|-------|-------|
| Symbol | `_ZN7cocos2d4Data5clearEv` |
| Signature | `void Data::clear()` |
| Evidence | `bl 0xc828f8` @ 0xc82c44, 0xc82c90, 0xc82cfc |
| Effect | Frees `_tmp` (if non-null) then `_ptr` via `free()`; sets both to NULL and _size to 0. |

### 3h. Helper: `malloc` @ 0x3fa240 / `free` @ 0x3faf50

Standard C heap functions, confirmed by call context.

### 3i. Helper: `__stack_chk_fail` @ 0x3fa1f0

Called at 0xc82d70 if the stack canary check fails.

---

## 4. COMPLETE REGISTER MAP (within decryptData)

```
x20 = this (Data*), preserved throughout
x21 = data buffer pointer (this->_ptr), reused for payload_size in some paths
x22 = payload_size (sign-extended to 64-bit)
x23 = &stack_output (x29+0x60) — used as std::string target and output_size
x24 = malloc'd temp buffer (version 1) or decompression result (version 2)

Stack layout:
  x29+0x48 = buffer_end (ptr + size, used in v1)
  x29+0x58 = out_ptr (8 bytes, decompression output pointer)
  x29+0x60 = out_size / key_string (8+ bytes, dual-use)
  x29+0x68 = stack canary
```

---

## 5. COMPLETE CONTROL FLOW

```
Data::decryptData(this)
───────────────────────

  ; ── PROLOGUE ──
  save callee-saved registers (x19-x24)
  x20 = this (Data*)
  save stack canary at [x29+0x68]

  ; ── GUARD: size < 16 → early return ──
  if this->_size < 0x10:
      goto EXIT            ; too small for any .mt header

  ; ── GUARD: magic != 'Antm' → early return ──
  x21 = this->_ptr
  w0  = 0x6D746E41                 ; 'Antm' (little-endian)
  w2  = *(uint32_t*)x21           ; first 4 bytes of file
  if w2 != w0:
      goto EXIT                    ; not a .mt file, skip

  ; ── GUARD: already decrypted → early return ──
  w2  = *(uint32_t*)(x21 + 8)     ; bytes at offset 8-11
  w0  = 0x00ABCDEF
  if w2 == w0:
      goto EXIT                    ; sentinel value present → already decrypted

  ; ── VERSION DISPATCH ──
  w0 = *(uint8_t*)(x21 + 4)       ; version byte at offset 4
  if w0 == 1:
      goto VERSION_1
  if w0 == 2:
      goto VERSION_2
  goto EXIT                        ; unknown version, skip

  ; ════════════════════════════════════════════
  ;  VERSION 2 PATH
  ; ════════════════════════════════════════════
VERSION_2:
  ; Step 2a: Compute payload_size and XOR-decrypt
  payload_size = *(uint32_t*)(x21 + 8) XOR 0x00ABCDEF
                      ; w2 was loaded before, w21 = w2 ^ 0xABCDEF
  x22 = sign_extend(payload_size)  ; x22 = payload_size (64-bit)
  xor_decrypt(x21 + 0x10, payload_size)
                      ; XOR outer layer of payload data (in-place)
                      ; buffer+0x10 .. buffer+0x10+payload_size

  ; Step 2b: Check if inner data is gzip
  out_ptr      = NULL   ; [x29+0x58]
  out_size     = 0      ; [x29+0x60]
  
  if isGZipBuffer(this->_ptr + 0x10, payload_size) == 0:
      goto V2_TRY_UNCOMPRESS     ; not zlib, try lmF@

  ; Step 2c: Inflate (zlib decompression)
  result = inflateMemory(this->_ptr + 0x10, payload_size, &out_ptr)
                          ; x0 = result (decompressed data or NULL)
  if result != NULL:
      goto V2_INFLATE_OK

  ; ── Fallback: inflate failed → advance past header ──
  ; Save old ptr, set size to payload_size, advance ptr by 16
  this->_tmp  = this->_ptr       ; save original buffer
  this->_size = payload_size     ; new size = XOR-decoded size
  this->_ptr  = this->_ptr + 0x10 ; skip 16-byte header
  goto EXIT

V2_INFLATE_OK:
  this->_flags |= 1               ; mark as decompressed (byte at +0x18)
  Data::clear(this)               ; free old buffer
  this->_ptr  = out_ptr           ; replace with decompressed data
  this->_size = result            ; result = decompressed size (returned by inflateMemory)
  goto EXIT

V2_TRY_UNCOMPRESS:
  if uncompressData(this->_ptr + 0x10, payload_size, &out_ptr, &out_size) != 0:
      Data::clear(this)           ; free old buffer
      this->_ptr  = out_ptr
      this->_size = out_size
      goto EXIT
  ; lmF@ also failed
  goto V2_FALLBACK                ; advance past header as above

  ; ════════════════════════════════════════════
  ;  VERSION 1 PATH
  ; ════════════════════════════════════════════
VERSION_1:
  ; Step 1a: Allocate temp buffer for decryption output
  payload_size = *(uint32_t*)(x21 + 8) XOR 0x00ABCDEF  ; w22 = payload_size
  x23 = &stack_temp               ; x23 = x29+0x60 (used as key string target & out_size)
  
  temp_buf = malloc(payload_size + 1)     ; x24 = temp_buf
  temp_buf[payload_size] = 0              ; null-terminate

  ; Step 1b: Get AES key (constructed as std::string at x23 = x29+0x60)
  x8 = x23                     ; hidden this ptr or output string location
  getKey()                     ; constructs std::string at x29+0x60

  ; Step 1c: AES decrypt
  aes_success = aes_decrypt(
      input  = this->_ptr + 0x10,      ; encrypted payload
      output = this->_ptr + this->_size, ; buffer_end (unused/IV?)
      key    = *(std::string*)(x29+0x60), ; reference to key string
      extra  = temp_buf,                 ; actual output buffer
      size   = payload_size              ; data length
  )
  ; w22 = aes_success (0=no, 1=yes)

  ; Step 1d: Check if output buffer is a Ref-counted object
  ; (Uses the post-decrypt value at x29+0x60 as a pointer check)
  x2 = *(uint64_t*)(x29+0x60)          ; output_size or output ptr
  if is_not_Ref(x2):                    ; x2 - 0x18 != sentinel
      refcount_decrement(x2)            ; handle Ref counting

  if aes_success == 0:
      goto V1_AES_FAILED                ; free key buffer and exit

  ; Step 1e: Set Data fields to AES output
  payload_size = *(uint32_t*)(x21 + 8) XOR 0x00ABCDEF  ; recalculate
  Data::clear(this)
  this->_ptr  = temp_buf                ; x24 = buffer with AES output
  this->_size = payload_size

  ; Step 1f: Try decompression on AES-decrypted data
  if isGZipBuffer(temp_buf, payload_size) == 0:
      goto V1_TRY_UNCOMPRESS

  ; gzip format detected
  result = inflateMemory(temp_buf, payload_size, &out_ptr)
  if result != NULL:
      this->_flags |= 1
      Data::clear(this)
      this->_ptr  = out_ptr
      this->_size = result              ; decompressed size
      goto EXIT

  ; inflate failed, keep AES output as-is
  goto EXIT

V1_TRY_UNCOMPRESS:
  if uncompressData(temp_buf, payload_size, &out_ptr, &out_size) != 0:
      Data::clear(this)
      this->_ptr  = out_ptr
      this->_size = out_size
      goto EXIT
  ; uncompress failed, keep AES output as-is
  goto EXIT

V1_AES_FAILED:
  ; free temp_buf and exit
  free(temp_buf)
  goto EXIT

  ; ════════════════════════════════════════════
  ;  EXIT
  ; ════════════════════════════════════════════
EXIT:
  if stack_canary != saved_canary:
      __stack_chk_fail()
  restore callee-saved registers
  return
```

---

## 6. BUFFER TRANSFORMATION DIAGRAM

### Version 2 Path (most common)

```
Input Buffer (this->_ptr, this->_size)
┌─────────────────────────────────────────────────┐
│ 0x00: 'Antm' (4 bytes)                          │
│ 0x04: version = 2 (1 byte)                      │  ← Header (16 bytes)
│ 0x05: padding (3 bytes)                         │
│ 0x08: XOR'd payload_size (4 bytes)              │
│ 0x0C: unknown (4 bytes)                         │
│ 0x10+ ┌──────────────────────────────────┐      │
│       │ XOR-encrypted payload             │      │  ← Payload (payload_size bytes)
│       │  (contains gzip OR lmF@ data)     │      │
│       └──────────────────────────────────┘      │
└─────────────────────────────────────────────────┘

  │
  ▼ Step 1: XOR Decrypt (in-place on payload)
  │         xor_decrypt(buffer+0x10, payload_size)
  │         → pointer unchanged, buffer modified in-place
  │
  ▼ Step 2a: isGZipBuffer() check
  │         If gzip: inflateMemory() → new buffer
  │         If NOT gzip: uncompressData() → new buffer
  │
  ▼ Step 2b (success): new buffer allocated
  │         this->_ptr = decompressed_data (new allocation)
  │         this->_size = decompressed_size
  │         Old buffer freed via Data::clear()
  │
  ▼ Output Buffer
  │         Decrypted Lua bytecode in new buffer
```

### Version 2: Buffer pointer state machine

| Step | _ptr | _size | _tmp | _flags |
|------|------|-------|------|--------|
| Entry | original_buf | file_size | ? | ? |
| After XOR | original_buf (data mutated) | file_size | ? | ? |
| After inflate OK | out_ptr | decomp_size | ? | 1 (bit0) |
| Inflate fail fallback | original_buf+0x10 | payload_size | original_buf | ? |

### Version 1 Path

```
Input Buffer (this->_ptr, this->_size)
┌─────────────────────────────────────────────────┐
│ 0x00: 'Antm' (4 bytes)                          │
│ 0x04: version = 1 (1 byte)                      │  ← Header (16 bytes)
│ 0x05: padding (3 bytes)                         │
│ 0x08: XOR'd payload_size (4 bytes)              │
│ 0x0C: unknown (4 bytes)                         │
│ 0x10+ ┌──────────────────────────────────┐      │
│       │ AES-encrypted payload             │      │  ← Payload (payload_size bytes)
│       │  (contains gzip OR lmF@ data)     │      │
│       └──────────────────────────────────┘      │
└─────────────────────────────────────────────────┘

  │
  ▼ Step 1: getKey() → obtain AES key
  │
  ▼ Step 2: aes_decrypt() → new buffer (malloc'd: payload_size+1)
  │         input = buffer+0x10
  │         output = temp_buf (x24)
  │         key = from getKey()
  │         → temp_buf filled with AES-decrypted data
  │
  ▼ Step 3: Set Data to temp_buf
  │         Data::clear(this)
  │         this->_ptr = temp_buf
  │         this->_size = payload_size
  │
  ▼ Step 4: isGZipBuffer() check
  │         If gzip: inflateMemory() → new buffer
  │         If NOT gzip: uncompressData() → new buffer
  │
  ▼ Step 5 (success): new buffer replaces temp_buf
  │         this->_ptr = decompressed_data
  │         this->_size = decompressed_size
  │         temp_buf freed via Data::clear()
  │
  ▼ Output Buffer
  │         Decrypted Lua bytecode in new buffer
```

---

## 7. BRANCH TABLE

| Label / Address | Condition | Taken → | Fall-through → | Description |
|-----------------|-----------|---------|----------------|-------------|
| 0xc82ae0 | this->_size < 0x10 | EXIT | continue | Minimum header size check |
| 0xc82af8 | *(uint32*)this->_ptr != 'Antm' | EXIT | 0xc82b24 | Magic check |
| 0xc82b34 | *(uint32*)(buf+8) == 0xABCDEF | EXIT | continue | Already decrypted check |
| 0xc82b40 | version == 1 | VERSION_1 | continue | Dispatch v1 |
| 0xc82b48 | version != 2 | EXIT | VERSION_2 | Dispatch v2 (or unknown) |
| 0xc82b84 | !isGZipBuffer(payload, size) | 0xc82cd8 | continue (inflate) | Try inflate or uncompress |
| 0xc82ba0 | inflateMemory() == NULL | 0xc82ba4 (fallback) | 0xc82c84 (ok) | Inflate result |
| 0xc82cf4 | uncompressData() == 0 | 0xc82ba4 (fallback) | 0xc82cf8 (ok) | uncompress result |
| 0xc82c64 | !isGZipBuffer(aes_output, sz) | 0xc82d40 (try unc) | continue (inflate) | Post-AES decompress |
| 0xc82c80 | inflateMemory() == NULL | EXIT | 0xc82c84 (ok) | Post-AES inflate result |
| 0xc82d58 | uncompressData() == 0 | EXIT | 0xc82cf8 (ok) | Post-AES uncompress result |

---

## 8. RETURN PATHS

Every return path goes through the `EXIT` label at 0xc82afc which checks the
stack canary and restores registers. The function never fails
explicitly — if no .mt header is found or decryption fails, it returns
with `this` unchanged.

| Path | Condition | this->_ptr | this->_size | this->_flags |
|------|-----------|------------|-------------|--------------|
| Early return | size < 16 OR no 'Antm' magic OR already decrypted OR unknown version | unchanged | unchanged | unchanged |
| V2: Inflate OK | gzip detected + inflate succeeds | out_ptr (new alloc) | decompressed_size | bit0=1 |
| V2: uncompress OK | not gzip + uncompress succeeds | out_ptr (new alloc) | out_size | ? |
| V2: Both fail | inflate + uncompress both fail | original_buf+0x10 (advance 16) | payload_size | ? |
| V1: AES + Inflate OK | AES succeeds + gzip detected + inflate succeeds | out_ptr (new alloc) | decompressed_size | bit0=1 |
| V1: AES + uncompress OK | AES succeeds + not gzip + uncompress succeeds | out_ptr (new alloc) | out_size | ? |
| V1: AES OK, decompress fail | AES succeeds but inflate + uncompress fail | temp_buf (AES output) | payload_size | ? |
| V1: AES fail | AES returns 0 | (old buffer freed, then?) | — | — |

---

## 9. KEY CONSTANTS

| Constant | Value | Usage |
|----------|-------|-------|
| Magic | `0x6D746E41` ('Antm') | File identification @ offset 0 |
| XOR key | `0x00ABCDEF` | XOR key for size field @ offset 8 & payload decryption |
| Version offset | +4 | Byte at offset 4: 1 = AES, 2 = XOR |
| Header size | 16 bytes | Full header before payload starts @ offset 16 |
| Gzip magic | `0x1F8B` (bytes 0x1F, 0x8B) | Detected by `isGZipBuffer` |

---

## 10. CALL GRAPH (internal)

```
Data::decryptData (0xc82ab0)
  ├── CCCrypto::xor_decrypt (0xceccec)        ; v2 only
  ├── ZipUtils::isGZipBuffer (0xca4638)       ; both v1 & v2
  ├── ZipUtils::inflateMemory (0xca41c4)      ; both v1 & v2
  ├── CCCrypto::uncompressData (0xcecd24)     ; both v1 & v2
  ├── CCCrypto::getKey (0xcec678)             ; v1 only
  ├── CCCrypto::aes_decrypt (0xcec5c0)        ; v1 only
  ├── Data::clear (0xc828f8)                  ; buffer management
  ├── malloc (0x3fa240)                       ; heap allocation (v1 temp buf)
  └── free (0x3faf50)                         ; heap deallocation
```

---

## 11. HYPOTHESES (unverified from disassembly)

1. **`CCCrypto::getKey` implementation**: The mangled name shows `void getKey()`
   with no parameters and no return type encoded. The calling code uses x8 as a
   hidden output parameter (constructs a `std::string` at x29+0x60). The exact
   key derivation algorithm (hardcoded, file-based, or derived) is unknown.

2. **`aes_decrypt` 2nd parameter**: The symbol shows `const char*` as the 2nd
   parameter. From the calling code it receives `buffer_end` (ptr + size). This
   may serve as an IV, an output boundary marker, or be unused. (MODE: The
   function name contains "aes" but the exact mode — ECB, CBC, etc. — is not
   determined from this function's disassembly alone.)

3. **`CCCrypto::uncompressData` algorithm**: The symbol confirms `bool
   uncompressData(char*, unsigned int, char*&, unsigned long&)`. The function
   checks for minimum size 0xD and handles the `lmF@` format internally. The
   exact decompression algorithm (custom Huffman, LZSS, etc.) is not determined
   from this function's disassembly alone.

4. **Unknown field at offset 0x0C**: The 4 bytes at header offset 12 are read
   but not obviously used in decryptData. May be a checksum, flags field, or
   timestamp.

5. **`Data::_tmp` field (+0x10)**: Used only in the V2 fallback path
   (inflate+uncompress both fail). The old buffer pointer is stored there, but
   it is unclear if/how this field is cleaned up later.

6. **`_flags` field (+0x18)**: Only the lowest bit (0x01) is observed being set
   (when inflate succeeds). Other bits may have meanings not revealed by
   decryptData.
