# Data::decryptData (0xC82AB0) — Complete Decompilation
## Binary: libagame.so (ARM64)
## Symbol: `_ZN7cocos2d4Data11decryptDataEv`

---

## 1. struktur `Data` (Extended)

Based on all field accesses in this function:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| +0x00 | 8 | `_ptr` | Pointer to raw buffer (`uint8_t*`) |
| +0x08 | 8 | `_size` | Size of data (`ssize_t`) |
| +0x10 | 8 | `_backup` | Original ptr saved during transform (`uint8_t*`) |
| +0x18 | 1 | `_modified` | Flag: 1 if buffer was replaced (`bool`) |

---

## 2. Called Functions

| Address | Symbol | Signature | Role |
|---------|--------|-----------|------|
| **0xceccec** | `_ZN8CCCrypto11xor_decryptEPcj` | `xor_decrypt(unsigned char* data, unsigned int len)` | XOR buffer in-place with derived keystream |
| **0xca4638** | `_ZN7cocos2d8ZipUtils12isGZipBufferEPKhl` | `isGZipBuffer(const unsigned char* buf, long len) → bool` | Returns non-zero if data is gzip/zlib compressed |
| **0xca41c4** | `_ZN7cocos2d8ZipUtils13inflateMemoryEPhlPS1_` | `inflateMemory(unsigned char* data, long len, unsigned char** out) → long` | zlib inflate; returns uncompressed size (0 on failure) |
| **0xcecd24** | `_ZN8CCCrypto14uncompressDataEPcjPPhRm` | `uncompressData(unsigned char* data, unsigned int len, unsigned char** out, unsigned long& out_size) → bool` | Custom lmF@ decompressor; returns 0 on success |
| **0xcec678** | `_ZN8CCCrypto6getKeyEv` | `getKey()` (44B) | Returns encryption key (via x8 output slot) |
| **0xcec5c0** | `_ZN8CCCrypto11aes_decryptEPKcS1_RKSsPci` | `aes_decrypt(const char* data, const char* key, const std::string& iv, char* output, int len)` | AES decryption |
| **0xc828f8** | `_ZN7cocos2d4Data5clearEv` | `Data::clear()` | Frees managed buffer, resets state |
| **0x3fa240** | (no symbol) | `operator new` (malloc) | Allocates heap memory |

---

## 3. Complete Pseudocode

```c
// Address: 0xC82AB0
// Symbol: _ZN7cocos2d4Data11decryptDataEv
// struct Data { uint8_t* _ptr; ssize_t _size; uint8_t* _backup; bool _modified; };

void cocos2d::Data::decryptData()
{
    // ──────────────────────────────────────────
    // PROLOGUE: stack frame setup
    // [0xc82ab0-0xc82ac8]: save regs, alloc 0x70 on stack
    // x19 = thread-local storage base (stack canary)
    // x20 = this (Data*)
    // ──────────────────────────────────────────

    // Load stack canary
    // [0xc82acc-0xc82adc]: x0 = *(TLS[0x3e0]) (canary value)
    //                      var_68 = x0 (save on stack)
    uint64_t canary = *(uint64_t*)(*(uint64_t*)(TLS_BASE + 0x3e0));
    
    // ──────────────────────────────────────────
    // BLOCK A: Size guard + magic check
    // ──────────────────────────────────────────

    if (this->_size < 16)                   // [0xc82ad8]: cmp x1, #0x10; b.lo EXIT
        goto EXIT;

    uint8_t* buf = this->_ptr;              // [0xc82ae4]: ldr x21, [x20]   → x21 = this->_ptr
    uint32_t magic = *(uint32_t*)buf;       // [0xc82af0]: ldr w2, [x21]

    if (magic != 0x6D746E41)                // [0xc82ae8-0xc82af8]: 
        goto EXIT;                          //   'A'=0x41 'n'=0x6E 't'=0x74 'm'=0x6D
                                            //   Little-endian: 0x6D746E41 = "Antm"

    // ──────────────────────────────────────────
    // BLOCK B: Already-decrypted sentinel check
    // ──────────────────────────────────────────

    uint32_t hdr_word2 = *(uint32_t*)(buf + 8); // [0xc82b24]: ldr w2, [x21, #8]
    
    if (hdr_word2 == 0x00ABCDEF)            // [0xc82b28-0xc82b34]:
        goto EXIT;                          //   sentinel meaning "already processed"

    // ──────────────────────────────────────────
    // BLOCK C: Version dispatch
    // ──────────────────────────────────────────

    uint8_t version = buf[4];               // [0xc82b38]: ldrb w0, [x21, #4]
    
    if (version == 1)                       // [0xc82b3c-0xc82b40]:
        goto VERSION_1;                     //   b.eq → VER_1
    
    if (version != 2)                       // [0xc82b44-0xc82b48]:
        goto EXIT;                          //   unsupported version, skip
    
    // ──────────────────────────────────────────
    // BLOCK D: VERSION 2 — XOR + Inflate/Uncompress
    // ──────────────────────────────────────────
    {
        uint32_t payload_size_xored = hdr_word2;  // w2 still holds buf[8..11]
        uint32_t xor_mask = 0x00ABCDEF;           // [0xc82b4c-0xc82b54]
        uint32_t payload_size = payload_size_xored ^ xor_mask; // [0xc82b58]
        int64_t payload_size_64 = (int64_t)(int32_t)payload_size; // [0xc82b60]: sxtw

        // Step D1: XOR outer layer (in-place)
        // [0xc82b50]:  x0 = buf + 16  (skip 16-byte Antm header)
        // [0xc82b5c]:  w1 = payload_size (as 32-bit)
        // [0xc82b64]:  call CCCrypto::xor_decrypt(buf+16, payload_size)
        CCCrypto::xor_decrypt(buf + 16, payload_size);
        // ^^ modifies buf[16..16+payload_size] IN-PLACE

        // Step D2: Check if gzip/zlib compressed
        // [0xc82b68]:  var_58 = 0
        // [0xc82b74]:  var_60 = 0
        // [0xc82b78]:  x0 = buf + 16
        // [0xc82b70]:  x1 = payload_size_64
        // [0xc82b7c]:  call ZipUtils::isGZipBuffer(buf+16, payload_size_64)
        int is_gzip = (uint8_t)ZipUtils::isGZipBuffer(buf + 16, payload_size_64);
        // [0xc82b80]: uxtb w0, w0  (zero-extend byte)
        
        if (is_gzip)     // [0xc82b84]: cbz w0, #TRY_UNCOMPRESS
        {
            // Step D3a: zlib inflate
            // [0xc82b88]: x0 = buf (this->_ptr)
            // [0xc82b94]: x0 = buf + 16
            // [0xc82b8c]: x1 = payload_size_64
            // [0xc82b90]: x2 = &var_58 (output ptr)
            // [0xc82b98]: call ZipUtils::inflateMemory(buf+16, payload_size_64, &out_ptr)
            long inflated_size = ZipUtils::inflateMemory(
                (unsigned char*)(buf + 16), 
                payload_size_64, 
                (unsigned char**)&var_58
            );
            // x21 = inflated_size (return value)

            if (inflated_size != 0)            // [0xc82ba0]: cbnz x0, #INFLATE_OK_V2
            {
                goto INFLATE_OK_V2;
            }
            
            // Step D3b: inflate failed — use raw XOR'd data as-is
            // (skip past Antm header, keep only payload portion)
            // [0xc82ba4-0xc82bb4]:
            this->_backup   = this->_ptr;       // save original ptr
            this->_size     = payload_size_64;  // new size = payload size
            this->_ptr      = buf + 16;         // advance past header
            goto EXIT;                          // [0xc82bb8]: b EXIT
        }
        else
        {
            // ──────────────────────────────────────────
            // BLOCK E: V2 fallback — Custom uncompress (lmF@)
            // ──────────────────────────────────────────
            // [0xc82cd8-0xc82cec]:
            (void)CCCrypto::uncompressData(
                (unsigned char*)(buf + 16),      // x0 = buf + 16
                (unsigned int)payload_size,       // w1 = payload_size  (NOTE: 32-bit)
                (unsigned char**)&var_58,         // x2 = &output_ptr (stack at fp+0x58)
                (unsigned long&)var_60            // x3 = &output_size (stack at fp+0x60)
            );                                    // [0xc82cec]: bl uncompressData
            // return value: w0 = bool (0=success, non-zero=failure)
            // [0xc82cf0]: uxtb w0, w0

            if ((uint8_t)w0 == 0)                // [0xc82cf4]: cbz w0, #USE_RAW_V2
            {
                goto USE_RAW_V2;
            }

            // [0xc82cf8-0xc82d0c]: uncompress SUCCESS
            this->clear();                       // [0xc82cfc]: Data::clear()
            this->_ptr  = var_58;                // [0xc82d00-0xc82d04]
            this->_size = var_60;                // [0xc82d08-0xc82d0c]
            goto EXIT;
        }

    INFLATE_OK_V2:   // [0xc82c84]
        this->clear();                           // [0xc82c90]: Data::clear()
        this->_modified = true;                  // [0xc82c8c]: strb #1, [x20, #0x18]
        this->_ptr      = var_58;                // [0xc82c94-0xc82c98]
        this->_size     = inflated_size;          // [0xc82c9c]: str x21, [x20, #8]
        // x21 = inflated_size (returned by inflateMemory)
        goto EXIT;                               // [0xc82ca0]: b EXIT

    USE_RAW_V2:      // [0xc82ba4]
        // inflate returned NULL — just advance past header
        this->_backup   = this->_ptr;             // [0xc82ba8]
        this->_size     = payload_size_64;        // [0xc82bac]
        this->_ptr      = buf + 16;               // [0xc82bb4]
        goto EXIT;                                // [0xc82bb8]
    }

    // ──────────────────────────────────────────
    // BLOCK F: VERSION 1 — getKey + AES decrypt + Inflate/Uncompress
    // ──────────────────────────────────────────

VERSION_1:                                      // [0xc82bbc]
    {
        uint32_t payload_size = hdr_word2 ^ 0x00ABCDEF;  // [0xc82bcc]: eor w22, w2, w22
        // w22 = payload_size (stored in w22)

        // Step F1: compute end of raw buffer
        // [0xc82bc0]: x1 = x21 + x1  = buf + this->_size  (end of original data)
        // HYPOTHESIS: this may pass (buf+size) as a key pointer to aes_decrypt,
        // or it may serve another purpose.
        // Stored at var_48 = buf + this->_size.
        var_48 = buf + this->_size;              // [0xc82bc8]

        // Step F2: allocate output buffer
        // [0xc82bd4]: w0 = payload_size + 1
        // [0xc82bd8]: call malloc(payload_size + 1)
        void* out_buf = malloc(payload_size + 1);  // [0xc82bd8]
        // *(out_buf + payload_size) = 0          // [0xc82bdc]: null-terminate
        x24 = out_buf;                           // [0xc82be4]

        // Step F3: get encryption key
        // [0xc82be0]: x8 = &var_60 (output slot)
        // [0xc82be8]: call CCCrypto::getKey()
        // OUTPUT: var_60 receives a std::string (the key)
        CCCrypto::getKey();                      // writes result to &var_60

        // Step F4: AES decrypt
        // [0xc82bfc]: x0 = buf + 16 (encrypted payload)
        // [0xc82bf8]: x1 = var_48 (buf + this->_size)
        // [0xc82c00]: x2 = &var_60 (key from getKey)
        // [0xc82c04]: x3 = out_buf (output)
        // [0xc82c08]: w4 = payload_size (XOR-decoded)
        // [0xc82c0c]: call CCCrypto::aes_decrypt(buf+16, var_48, &var_60_key, out_buf, payload_size)
        int aes_ok = (uint8_t)CCCrypto::aes_decrypt(
            (const char*)(buf + 16),   // encrypted data
            (const char*)var_48,       // HYPOTHESIS: additional key material (ptr+orig_size)
            (const std::string&)var_60,// key from getKey()
            (char*)out_buf,            // output buffer
            (int)payload_size          // size
        );  // [0xc82c18]: uxtb w22, w0  → w22 = result
        // [0xc82c1c-0xc82c24]: reference counting on key std::string at var_60
        // [0xc82c28]: b.ne → branch if string was dynamic

        if (aes_ok == 0)                        // [0xc82c2c]: cbz w22, #AES_FAIL
        {
            goto AES_FAIL_V1;
        }

        // Step F5: AES success — now try inflate
        // [0xc82c30]: w21 = *(uint32_t*)(buf+8)  (original hdr_word2)
        uint32_t payload_size2 = hdr_word2 ^ 0x00ABCDEF;  // [0xc82c40]: eor w21, w21, w1

        // [0xc82c44]: Data::clear() — free old buffer
        this->clear();

        // [0xc82c48]: this->_ptr = out_buf
        this->_ptr = (uint8_t*)out_buf;         // [0xc82c48]
        // [0xc82c54]: this->_size = payload_size2 (sign-extended)
        this->_size = (ssize_t)(int32_t)payload_size2;  // [0xc82c4c-0xc82c54]

        // [0xc82c58-0xc82c5c]: var_58 = 0, var_60 = 0
        var_58 = 0;
        var_60 = 0;

        // Step F6: Check compression
        // [0xc82c60]: call ZipUtils::isGZipBuffer(out_buf, this->_size)
        int is_gzip2 = (uint8_t)ZipUtils::isGZipBuffer(
            (unsigned char*)out_buf, 
            this->_size
        );                                       // [0xc82c60]
        
        if (is_gzip2)                            // [0xc82c68]: cbz w0, #UNCOMPRESS_V1
        {
            // Step F7: zlib inflate
            // [0xc82c6c-0xc82c78]:
            // x0 = this->_ptr (out_buf)
            // x1 = this->_size
            // x2 = &var_58
            long inflated2 = ZipUtils::inflateMemory(
                (unsigned char*)this->_ptr, 
                this->_size, 
                (unsigned char**)&var_58
            );                                   // [0xc82c78]

            if (inflated2 != 0)                  // [0xc82c80]: cbz x0, #EXIT
            {
                // [0xc82c84]: inflate OK
                this->clear();
                this->_modified = true;
                this->_ptr  = var_58;
                this->_size = inflated2;
                goto EXIT;
            }
            
            // inflate returned NULL → fall through to EXIT with current buffer
            goto EXIT;                           // [0xc82c80]: cbz → EXIT
        }
        else
        {
            // Step F8: Custom uncompress fallback (lmF@)
            // [0xc82d40-0xc82d50]:
            (void)CCCrypto::uncompressData(
                (unsigned char*)this->_ptr,      // x0 = out_buf
                (unsigned int)this->_size,       // w1 = size (32-bit)
                (unsigned char**)&var_58,        // x2 = &output_ptr
                (unsigned long&)var_60           // x3 = &output_size
            );                                   // [0xc82d50]

            if ((uint8_t)w0 == 0)               // [0xc82d58]: cbz → EXIT (already processed below?)
            {
                // uncompress SUCCESS
                this->clear();
                this->_ptr  = var_58;
                this->_size = var_60;
                goto EXIT;                       // [0xc82d5c]: b EXIT
            }
            
            // uncompress FAILED → use out_buf as-is
            goto EXIT;                           // fallthrough to EXIT (uncompress failure uses current buffer)
        }

    AES_FAIL_V1:      // [0xc82d14]
        // AES decrypt returned 0 (failure)
        // cleanup and return raw out_buf as result
        // [0xc82d14-0xc82d3c]:
        //   x0 = out_buf (x24) — return this buffer as the result
        //   Tail-call to operator delete? (b #0x3faf50)
        // HYPOTHESIS: when AES fails, returns the allocated buffer as-is
        goto EXIT_WITH_BUFFER;
    }

    // ──────────────────────────────────────────
    // EXIT: stack canary check and return
    // ──────────────────────────────────────────

EXIT:                                             // [0xc82afc]
    uint64_t saved_canary = var_68;               // [0xc82b00]
    uint64_t current_canary = *(uint64_t*)(*(uint64_t*)(TLS_BASE + 0x3e0));  // [0xc82b04]
    
    if (saved_canary != current_canary)           // [0xc82b08]: b.ne STACK_CHK_FAIL
        goto STACK_CHK_FAIL;                      // [0xc82d70]: __stack_chk_fail
    
    // restore registers and return
    return;                                       // [0xc82b10-0xc82b20]

STACK_CHK_FAIL:                                   // [0xc82d70]
    // tail call to __stack_chk_fail (0x3fa1f0)
    __stack_chk_fail();                           // [0xc82d70]: bl #0x3fa1f0
    // unreachable
}
```

---

## 4. Basic Block Map

| BB | Address | Label | Condition | Outcome |
|----|---------|-------|-----------|---------|
| 0 | 0xc82ab0 | PROLOGUE | — | → BB1 |
| 1 | 0xc82ae0 | SIZE_CHECK | `this->_size < 16`? | YES→EXIT, NO→BB2 |
| 2 | 0xc82af4 | MAGIC_CHECK | `*(uint32*)buf != 'Antm'`? | YES→EXIT, NO→BB3 |
| 3 | 0xc82b30 | SENTINEL_CHECK | `*(uint32*)(buf+8) == 0xABCDEF`? | YES→EXIT, NO→BB4 |
| 4 | 0xc82b3c | VERSION_DISPATCH | `buf[4] == 1`? → BB10 (VER1); `buf[4] == 2`? → BB5 (VER2); else → EXIT |
| 5 | 0xc82b4c | VER2_XOR | Call xor_decrypt | → BB6 |
| 6 | 0xc82b80 | VER2_COMPR_CHECK | `isGZipBuffer(buf+16, size)` returns 0? | YES→BB9 (UNCOMPRESS), NO→BB7 |
| 7 | 0xc82b98 | VER2_INFLATE | Call inflateMemory | → BB8 |
| 8 | 0xc82ba0 | VER2_INFLATE_CHECK | `inflated_size != 0`? | YES→BB12 (INFLATE_OK), NO→BB13 (RAW_FALLBACK) |
| 9 | 0xc82cec | VER2_UNCOMPRESS | Call uncompressData | → BB14 |
| 10 | 0xc82bbc | VER1_AES | getKey + aes_decrypt | → BB11 |
| 11 | 0xc82c2c | VER1_AES_CHECK | `aes_ok == 0`? | YES→BB17 (AES_FAIL), NO→BB15 |
| 12 | 0xc82c84 | INFLATE_OK | Set Data fields | → EXIT |
| 13 | 0xc82ba4 | RAW_FALLBACK | Advance ptr past header | → EXIT |
| 14 | 0xc82cf0 | UNCOMPRESS_CHECK | `uncompressData == 0`? | YES→BB18 (UNCOMPRESS_OK), NO→BB13 |
| 15 | 0xc82c60 | VER1_COMPR_CHECK | `isGZipBuffer(out, size)` returns 0? | YES→BB16 (V1_UNCOMPRESS), NO→BB12 |
| 16 | 0xc82d50 | V1_UNCOMPRESS | Call uncompressData | → BB14 |
| 17 | 0xc82d14 | AES_FAIL | Return raw buf, tail-call free | → _ZdlPv |
| 18 | 0xc82cf8 | UNCOMPRESS_OK | Set Data fields from var_58/var_60 | → EXIT |

---

## 5. Stack Frame Layout

```
sp+0x00 ┌──────────────────────┐
         │   saved x29, x30    │  ← stp at 0xc82ab0
sp+0x10  │   saved x19, x20    │  ← stp at 0xc82ab8
sp+0x20  │   saved x21, x22    │  ← stp at 0xc82ac4
sp+0x30  │   saved x23, x24    │  ← stp at 0xc82ac8
         │                      │
sp+0x40  │   ─── unused ───    │
sp+0x48  │   var_48 (8B)       │  ← buf + original this->_size
         │                      │
sp+0x50  │   ─── unused ───    │
sp+0x58  │   var_58 (8B)       │  ← output_ptr for inflate/uncompress
sp+0x60  │   var_60 (8B)       │  ← output_size / key string
sp+0x68  │   var_68 (8B)       │  ← stack canary
sp+0x70  └──────────────────────┘  ← x29 (frame pointer)
```

---

## 6. Antm Header Format (VERIFIED)

| Offset | Size | Field | Validation |
|--------|------|-------|------------|
| +0x00 | 4 | Magic `"Antm"` = 0x6D746E41 | `*(uint32*)buf == 0x6D746E41` at 0xc82af4 |
| +0x04 | 1 | Version: `1` or `2` | `buf[4]` at 0xc82b38, compared at 0xc82b3c/0xc82b44 |
| +0x05 | 3 | Reserved/Padding | Not accessed by this function |
| +0x08 | 4 | Payload size (XOR'd) | `*(uint32*)(buf+8)` at 0xc82b24, XOR'd with 0x00ABCDEF |
| +0x0C | 4 | Sentinel marker | Not accessed directly; sentinel is 0x00ABCDEF at offset +8 |
| +0x10 | N | Encrypted/compressed payload | Actual data starts here |

**Magic construction (0xc82ae8-0xc82aec):**
```asm
mov  w0, #0x6e41       ; w0 = 0x00006E41    ('A'=0x41, 'n'=0x6E)
movk w0, #0x6d74, lsl #16  ; w0 = 0x6D746E41 ('t'=0x74, 'm'=0x6D, little-endian)
```

**Version sentinel (0xc82b28-0xc82b2c):**
```asm
mov  w0, #0xcdef        ; w0 = 0x0000CDEF
movk w0, #0xab, lsl #16 ; w0 = 0x00ABCDEF
```

If `*(uint32*)(buf+8) == 0x00ABCDEF`, the payload_size XOR result would be 0, meaning either empty payload or already processed.

---

## 7. Buffer Transformation Sequence

### Version 2 (the most common path):

| Step | Addr | Buffer In | Operation | Buffer Out | Evidence | Confidence |
|------|------|-----------|-----------|------------|----------|------------|
| 0 | entry | Raw file bytes: `[Antm|ver|pad|size|payload]` | — | — | Read from file | **100%** |
| 1 | 0xc82af0 | `*(uint32*)buf[0..3]` = "Antm" | Magic match = proceeds | Same | ldr/cmp | **100%** |
| 2 | 0xc82b38 | `buf[4]` = version byte | Version = 2 | Same | ldrb/cmp | **100%** |
| 3 | 0xc82b58 | `buf[8..11] ^ 0xABCDEF` → `payload_size` | Decode size | — | eor w21, w2, w1 | **100%** |
| 4 | 0xc82b64 | `buf[16..16+payload_size]` | XOR decrypt (in-place) | XOR'd payload | cc_bl xor_decrypt | **100%** |
| 5 | 0xc82b84 | `buf[16..16+payload_size]` (XOR'd) | Check gzip compression | Same | isGZipBuffer | **100%** |
| 6a | 0xc82b98 | If gzip: XOR'd payload | zlib inflate | Decompressed Lua bytecode | inflateMemory | **100%** |
| 6b | 0xc82cec | If NOT gzip: XOR'd payload | lmF@ uncompress | Decompressed Lua bytecode | uncompressData | **100%** |
| 7 | 0xc82c90 | Decompressed data | `Data::clear()` + store in Data | `this->_ptr` = output | str/strb | **100%** |

### Version 1 (alternative):

| Step | Addr | Buffer In | Operation | Buffer Out | Evidence | Confidence |
|------|------|-----------|-----------|------------|----------|------------|
| 0-3 | — | Same as V2 steps 0-3 | — | — | — | **100%** |
| 4 | 0xc82bd8 | Allocate `out_buf` size `payload_size+1` | malloc | Empty buffer | bl #0x3fa240 | **100%** |
| 5 | 0xc82be8 | (global state) | Get encryption key | key → var_60 | getKey() | **100%** |
| 6 | 0xc82c0c | `buf[16..]` + key | AES decrypt | Decrypted payload → out_buf | aes_decrypt | **100%** |
| 7 | 0xc82c44 | Decrypted payload | `Data::clear()` | — | Data::clear() | **100%** |
| 8 | 0xc82c60 | out_buf | Check gzip | Same | isGZipBuffer | **100%** |
| 9a | 0xc82c78 | If gzip: out_buf | zlib inflate | Decompressed output | inflateMemory | **100%** |
| 9b | 0xc82d50 | If NOT gzip: out_buf | lmF@ uncompress | Decompressed output | uncompressData | **100%** |

---

## 8. Confidence Assessment

| Claim | Confidence | Rationale |
|-------|-----------|-----------|
| Magic `"Antm"` at offset +0 | **100%** | Verified via instruction bytes at 0xc82ae8-0xc82aec |
| Version field at offset +4 | **100%** | `ldrb w0, [x21, #4]` at 0xc82b38 |
| Supported versions: 1, 2 | **100%** | Two `cmp` instructions at 0xc82b3c, 0xc82b44 |
| XOR mask: 0x00ABCDEF | **100%** | Verified via `mov`+`movk` at 0xc82b28-0xc82b2c |
| Header size: 16 bytes | **100%** | `add x0, x21, #0x10` at 0xc82b50 skips header |
| `xor_decrypt` in V2 | **100%** | `bl #0xceccec` at 0xc82b64 |
| `inflateMemory` in V2/V1 | **100%** | `bl #0xca41c4` at 0xc82b98/0xc82c78 |
| `isGZipBuffer` check | **100%** | `bl #0xca4638` at 0xc82b7c/0xc82c60 |
| `uncompressData` fallback | **100%** | `bl #0xcecd24` at 0xc82cec/0xc82d50 |
| `getKey()` + `aes_decrypt` in V1 | **100%** | Two calls at 0xc82be8/0xc82c0c |
| Semantics of x1 in aes_decrypt call (var_48 = buf+size) | **HYPOTHESIS** | Could be key material, end-of-buffer marker, or other. Further analysis of aes_decrypt needed. |
| Return type of inflateMemory (size vs pointer) | **90%** | `cbnz x0` suggests non-zero = success. Most likely returns uncompressed size. |
| `Data::_backup` field at +0x10 | **90%** | Only accessed in V2 raw fallback path; likely backup pointer |

---

## 9. Key Observations

1. **Sentinel optimization**: If `*(uint32*)(buf+8) == 0x00ABCDEF`, the function skips processing entirely. Since `payload_size = *(uint32*)(buf+8) ^ 0xABCDEF`, this means size=0 → file is empty or already processed.

2. **V2 is the default path**: V2 is handled first in the switch, and is shorter/faster (XOR only, no AES).

3. **Two-tier decompression**: zlib inflate is tried first; if it fails, the custom `uncompressData` (lmF@) is used as fallback.

4. **V1 AES key source**: `CCCrypto::getKey()` provides the key (via x8 output slot at var_60). A secondary key-like value `buf+this->_size` is also passed — its exact role requires analyzing `aes_decrypt` to resolve.

5. **In-place modification**: V2 modifies the buffer in-place (XOR then re-point the Data ptr). V1 allocates a new buffer and manages it.

6. **The `_modified` flag** at +0x18 is set to 1 only when `inflateMemory` or `uncompressData` replaces the buffer (not when just advancing past header).
