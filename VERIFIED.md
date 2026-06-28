# VERIFIED.md - Temuan Terverifikasi
## Project: MLA (Mobile Legends: Adventure) - Binary Analysis
### Target: libagame.so (ARM64, 18.87 MB)

---

## 1. BINARY STRUCTURE

| Property | Value |
|----------|-------|
| Format | ELF64 ARM64 little-endian |
| Entry Point | 0x3fc000 |
| .text | 0x3fc000 - 0xdf61ec (10.45 MB) |
| .rodata | 0xdf6200 - 0xf8c640 (1.59 MB) |
| .data + .bss | 0x115d478 - 0x125E5D0 |
| Imported Libraries | libGLESv2, libEGL, liblog, libOpenSLES, libz, libandroid, libdl, libstdc++, libm, libc |
| Total Exported Functions | 29,933 (statically linked) |
| Total Imported Functions | 513 |

## 2. STATICALLY LINKED LIBRARIES TERIDENTIFIKASI

| Library | Evidence |
|---------|----------|
| cocos2d-x | Ribuan simbol `_ZN7cocos2d*` (game engine) |
| cocostudio | Simbol `_ZN10cocostudio*` (UI editor) |
| OpenSSL 1.1.x | EVP_*, AES_*, RSA_*, EC_*, SHA*, MD5*, HMAC*, dll. |
| Lua 5.x | lua_*, luaL_*, luaopen_* functions |
| tolua++ | tolua_* functions |
| libwebsockets | lws_* functions |
| CRI Atom (ADX) | criAtom*, criFs*, criMvPly*, dll (audio engine) |
| libz (zlib) | deflate*, inflate* (statically linked, not imported) |
| libpng | png_* functions |
| libjpeg | jpeg_* functions |
| FreeType | FT_* functions |
| libwebm (VP9) | vpx_codec_* |
| Spine Runtime | spBone_*, spMeshAttachment_*, dll (animation) |
| LZMA SDK | LzmaDec_* (decoder only) |
| libuv | uv_* functions |
| libxxtea | xxtea_encrypt, xxtea_decrypt |
| RapidJSON | rapidjson namespace |
| tinyxml2 | tinyxml2 namespace |
| minizip | unz* functions |
| Moonton Protector | MoontonProtect, MPCipher, MPMd5Cipher |

## 3. CRYPTO FUNCTIONS - TERVERIFIKASI

### 3.1 TEA Functions (Confirmed by symbol names)

| Address | Name (mangled) | Signature | Confidence |
|---------|----------------|-----------|------------|
| 0x43a9a4 | `_Z13TeaEncryptECBPKcS0_Pc` | `TeaEncryptECB(const char*, const char*, char*)` | **100%** |
| 0x43aa80 | `_Z13TeaDecryptECBPKcS0_Pc` | `TeaDecryptECB(const char*, const char*, char*)` | **100%** |

**Evidence**: C++ mangled names directly confirm "TeaEncryptECB" and "TeaDecryptECB". Parameters: 3 pointers (key, input, output).

### 3.2 oi_symmetry Functions (Confirmed by symbol names)

| Address | Name (mangled) | Confidence |
|---------|----------------|------------|
| 0x43ab54 | `_Z24oi_symmetry_encrypt2_leni` | **100%** |
| 0x43ab80 | `_Z20oi_symmetry_encrypt2PKciS0_PcPi` | **100%** |
| 0x43ae3c | `_Z20oi_symmetry_decrypt2PKciS0_PcPi` | **100%** |

**oi_symmetry_decrypt2 signature**: `(const char* in, int in_len, const char* key, char* out, int* out_len) -> void`

### 3.3 getkey Function (Confirmed)

| Address | Name | Confidence |
|---------|------|------------|
| 0x43b33c | `_Z6getkeyPKcPc` | **100%** |

**Signature**: `getkey(const char* hex_str, char* key_out)` - converts hex string to binary key.

### 3.4 EncryptLib Class (Confirmed)

| Address | Method | Signature |
|---------|--------|-----------|
| 0x43b3b8 | `EncryptLib::EncryptLib()` | Constructor |
| 0x43b3bc | `EncryptLib::~EncryptLib()` | Destructor |
| 0x43b3c0 | `EncryptLib::getInstance()` | Singleton getter |
| 0x43b424 | `EncryptLib::encrypt(Ss, Ss)` | `encrypt(string, string) -> string` |
| 0x43b42c | `EncryptLib::decryption(void*, Ss)` | `decryption(void*, string)` |
| 0x43b488 | `EncryptLib::decryption2ByteArray(const char*, int, const char*, char*, int&)` | **Key function** |

### 3.5 XXTEA Functions (Confirmed - DIFFERENT ADDRESSES from Season 1)

| Address | Name (mangled) | Signature |
|---------|----------------|-----------|
| 0x5b2664 | `_Z13xxtea_encryptPhjS_jPj` | `xxtea_encrypt(uchar*, uint, uchar*, uint, uint*)` |
| 0x5b2714 | `_Z13xxtea_decryptPhjS_jPj` | `xxtea_decrypt(uchar*, uint, uchar*, uint, uint*)` |
| 0x470f8c | `_ZN7cocos2d8LuaStack22cleanupXXTEAKeyAndSignEv` | Cleanup key |
| 0x47112c | `_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKciS2_i` | Set key & sign |

### 3.6 AES Class (Custom, not OpenSSL)

| Address | Method | Notes |
|---------|--------|-------|
| 0xcf3998 | `AES::MakeKey(const char*, const char*, int, int)` | Key schedule |
| 0xcf335c | `AES::EncryptBlock(const char*, char*)` | Block encrypt |
| 0xcf367c | `AES::DecryptBlock(const char*, char*)` | Block decrypt |
| 0xcf2ce8 | `AES::DefEncryptBlock(const char*, char*)` | Default encrypt |
| 0xcf3020 | `AES::DefDecryptBlock(const char*, char*)` | Default decrypt |
| 0xcf468c | `AES::Encrypt(const char*, char*, size_t, int)` | Multi-block |
| 0xcf47f8 | `AES::Decrypt(const char*, char*, size_t, int)` | Multi-block |

### 3.7 CCCrypto Class (Cocos2D-X Crypto Bridge)

| Address | Method |
|---------|--------|
| 0xced7a8 | `CCCrypto::aes_encrypt(string, string) -> string` |
| 0xcedfe4 | `CCCrypto::aes_decrypt(string, string) -> string` |
| 0xcecc44 | `CCCrypto::xor_encrypt(const char*, unsigned int) -> string` |
| 0xceccec | `CCCrypto::xor_decrypt(const char*, unsigned int)` |
| 0xcec678 | `CCCrypto::getKey()` |
| 0xcec6a4 | `CCCrypto::getKey2()` |
| 0xced8f4 | `CCCrypto::cbc_encrypt(string, function, int, string) -> string` |
| 0xced91c | `CCCrypto::cbc_decrypt(const char*, const char*, function, int, const char*, string&)` |

### 3.8 cocos2d::ZipUtils (Compression)

| Address | Method |
|---------|--------|
| 0xca4144 | `cocos2d::ZipUtils::inflateMemoryWithHint(uchar*, ulong, uchar**, ulong, ulong)` |
| 0xca41c4 | `cocos2d::ZipUtils::inflateMemory(uchar*, ulong, uchar**)` |
| 0xca4318 | `cocos2d::ZipUtils::deflateMemoryWithHint(uchar*, ulong, uchar**, ulong, ulong)` |
| 0xca4398 | `cocos2d::ZipUtils::deflateMemory(uchar*, ulong, uchar**)` |
| 0xca43a0 | `cocos2d::ZipUtils::inflateGZipFile(const string&, uchar**)` |
| 0xca47e8 | `cocos2d::ZipUtils::inflateCCZBuffer(const char*, ulong, uchar**)` |
| 0xca4b14 | `cocos2d::ZipUtils::inflateCCZFile(const string&, uchar**)` |
| 0xca4cb4 | `cocos2d::ZipUtils::setPvrEncryptionKey(uint, uint, uint, uint)` |
| 0xca4c8c | `cocos2d::ZipUtils::setPvrEncryptionKeyPart(int, uint)` |

### 3.9 cocos2d::FileUtils (File I/O)

| Address | Method | Role |
|---------|--------|------|
| 0xc6334c | `FileUtils::getDataFromFile(const string&) -> Data` | **Key: Read file to Data** |
| 0xc63a6c | `FileUtils::getFileData(const string&, const char*, long*) -> uchar*` | Raw file read |
| 0xc61fe4 | `FileUtils::isFileExist(const string&) -> bool` |
| 0xca3ff8 | `ZipUtils::inflateMemoryWithHint(uchar*, ulong, uchar**, ulong, ulong)` | Inflate |

### 3.10 OpenSSL Decryption Functions

| Function | Address |
|----------|---------|
| `CRYPTO_cbc128_decrypt` | 0xa3ffb0 |
| `CRYPTO_cbc128_encrypt` | 0xa3fda0 |
| `AES_cbc_encrypt` | 0xa857fc |
| `AES_set_decrypt_key` | 0xa85b58 |
| `AES_set_encrypt_key` | 0xa85818 |
| `EVP_aes_128_ecb` | 0xa2ce88 |
| `EVP_aes_128_cbc` | (present, check) |
| `EVP_aes_128_ctr` | 0xa2cec4 |
| `EVP_aes_128_ccm` | 0xa2cfb4 |
| `EVP_aes_256_cfb8` | 0xa2cf60 |
| `EVP_EncryptInit_ex` | 0xa33e04 |
| `EVP_EncryptUpdate` | 0xa33530 |
| `EVP_EncryptFinal_ex` | 0xa33a28 |
| `EVP_DecryptInit_ex` | 0xa33ecc |
| `EVP_DecryptUpdate` | 0xa337ec |
| `EVP_DecryptFinal_ex` | 0xa33b3c |
| `PKCS5_PBKDF2_HMAC` | 0xada4b4 |

---

## 4. COMPRESSION FUNCTIONS

### 4.1 zlib (statically linked)
- `deflate`, `deflateInit2_`, `deflateEnd`, `deflateReset`, `deflateSetDictionary`
- `inflate`, `inflateInit2_`, `inflateEnd`, `inflateReset`, `inflateSetDictionary`
- Full zlib API available

### 4.2 LZMA SDK
- `LzmaDec_InitDicAndState` @ 0xcf20d0
- `LzmaDec_Allocate` @ 0xcf2a00
- `LzmaDec_FreeProbs` @ 0xcf2810
- **Note**: Only DECODER, no encoder — suggests decompression only

### 4.3 minizip (ZIP)
- `unzStringFileNameCompare` @ 0xce159c
- `unzOpenCurrentFilePassword` @ 0xce2fe8
- `unzGetCurrentFileZStreamPos64` @ 0xce2594
- `call_zseek64` @ 0xcf7ec0

---

## 5. BUILD ENVIRONMENT EVIDENCE

**Strings found in .rodata**:
- `C:/MGame/branch/base/Client/` — Build path, confirms developer is Moonton
- `libil2cpp.so` — Unity reference? (unused)
- MoontonProtect JNI signatures found

---

## 6. FUNCTION INDEX - ORDERED BY ROLE

### Crypto Pipeline (potential .mt decryption path)

```
FileUtils::getDataFromFile (.mt file)
    ↓
EncryptLib::decryption or decryption2ByteArray
    ├── getkey (hex string → binary key)
    └── oi_symmetry_decrypt2
            └── TeaDecryptECB (called internally)
    ↓
[Output: lmF@ format?]
    ↓
ZipUtils::inflateMemory / inflateGZipFile (zlib decompression)
    ↓
[Output: Lua bytecode?]
```

---

## 7. CORRECTIONS FROM SEASON 1

| Season 1 Claim | Address | Actual | Correct Address |
|----------------|---------|--------|-----------------|
| xxtea_encrypt | 0x14ef12 | ❌ Wrong (not in .text) | 0x5b2664 |
| xxtea_decrypt | 0x11ec3a | ❌ Wrong | 0x5b2714 |
| setXXTEAKeyAndSign | 0x11e59e | ❌ Wrong | 0x47112c |
| cleanupXXTEAKeyAndSign | 0x11e4bf | ❌ Wrong | 0x470f8c |
| EncryptLib::decryption | 0x43b43c | ❌ Off by 16 | 0x43b42c |
| EncryptLib::encrypt | 0x43b7a8 | ❌ Wrong | 0x43b424 |
