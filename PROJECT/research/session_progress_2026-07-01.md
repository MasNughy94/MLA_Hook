# MLA Reverse Engineering - Session Progress (2026-07-01)

## Current Status: ACTIVE - Frida tracing phase

## What was achieved in this session

### 1. Symbol Table Parsing (libagame.so)
Parsed ELF64 AArch64 stripped binary from emulator (APK version 1.1.664, versionCode=12079).
- STRTAB: VA=0x10b760, file offset ~1,095,520 (1.5MB string table)
- SYMTAB: VA=0x41bf0, file offset ~269,296 (31,013 functions, 5,248 objects)
- LOAD[0]: file_off=0, vaddr=0, size=18,199,828
- LOAD[1]: file_off=0x115d478, vaddr=0x0115d478, size=662,200
- Mapping: vaddr < 0x115d478 â†’ direct offset; vaddr >= 0x115d478 â†’ offset = 0x115d478 + (vaddr - 0x0115d478)

### 2. Key Symbols Discovered (libagame.so)

**Encryption-related:**
- `xxtea_decrypt` @ VA=0x005b2714 (176 bytes) - XXTEA algorithm
- `xxtea_encrypt` @ VA=0x005b2664 (176 bytes)
- `TeaDecryptECB` @ VA=0x0043aa80 (212 bytes) - TEA ECB
- `oi_symmetry_decrypt2` @ VA=0x0043ae3c (1196 bytes) - Moonton custom cipher
- `oi_symmetry_encrypt2_leni` @ VA=0x0043ab54 (44 bytes)
- `EncryptLib::decryption` @ VA=0x0043b42c (92 bytes)
- `EncryptLib::decryption2ByteArray` @ VA=0x0043b488 (188 bytes)
- `CCCrypto::aes_decrypt` @ VA=0x00cedf34 (176 bytes) - AES CBC wrapper
- `CCCrypto::aes_decrypt` (overload) @ VA=0x00cedffc (308 bytes)
- `LuaStack::setXXTEAKeyAndSign` @ VA=0x0047112c (208 bytes)
- `LuaStack::cleanupXXTEAKeyAndSign` @ VA=0x00470f8c (68 bytes)
- `AES::DecryptBlock` @ VA=0x00cf367c (796 bytes)
- `AES::EncryptBlock` @ VA=0x00cf335c (800 bytes)
- `aes_encrypt` @ VA=0x00ceed54 (3312 bytes)

**zlib/compression:**
- `lua_moonton_zlibInflate` @ VA=0x00412a18 (496 bytes)
- `lua_moonton_zlibDeflate` @ VA=0x00412828 (496 bytes)
- `inflateInit_` @ VA=0x00dcab10 (368 bytes)
- `inflate` @ VA=0x00dcad08 (6392 bytes)
- `deflate` @ VA=0x00dc7dac (5380 bytes)

**Game-related (moonton):**
- `lua_moonton_asyncLoadRes` @ VA=0x00411ddc (416 bytes)
- `lua_register_all_moonton` @ VA=0x00420180 (80 bytes)
- `lua_moonton_InitCRIWARE` @ VA=0x00412dac (2216 bytes)
- `lua_moonton_checkMsgHeader` @ VA=0x00412614 (532 bytes)
- `lua_moonton_XXH32` @ VA=0x00412c08 (420 bytes)
- `lua_moonton_getDoubleBinary` @ VA=0x0040a59c (64 bytes) - possibly loads .mt files!

**CCCrypto class:**
- `CCCrypto::getKey` @ VA=0x00cec678 (44 bytes)
- `CCCrypto::getKey2` @ VA=0x00cec6a4 (44 bytes)
- `CCCrypto::setKey2` @ VA=0x00cecb5c (232 bytes)
- `CCCrypto::xor_encrypt` @ VA=0x00cecc44 (168 bytes)
- `CCCrypto::uncompressData` @ VA=0x00cecd24 (704 bytes)

### 3. .mt File Analysis

File: `e9f3b8900afa5a2838f0e356b74e30a9.mt` (100,209 bytes)
- Header: `Antm` (4 bytes) + `\x01\x57\x01\x46` (4 bytes version/flags?)
- After byte 8: AES-ECB encrypted payload (key 0xf5a193d50ade553e9835595f5cd75ddd DOES NOT produce 'lmF@' magic)
- The AES key 0xf5a193d50ade553e9835595f5cd75ddd NOT found in binary

### 4. Frida Setup
- Frida-server running at `/data/local/tmp/frida-server` on emulator
- Device: 127.0.0.1:21503 (MEmu Android 12)
- Game PID: 4703 (com.moonton.mobilehero)
- frida-server port: 27042 (forwarded via 27043)
- APK version: 1.1.664 (versionCode=12079)

### 5. Call Graph (in progress)

```
File .mt (Antm header)
  â†“ (Lua script calls)
lua_moonton_asyncLoadRes (0x00411ddc)
  â†“ (determines file type)
lua_moonton_getDoubleBinary (0x0040a59c) â† possibly reads .mt file
  â†“
[UNKNOWN] â† What decrypts .mt?
  â†’ oi_symmetry_decrypt2 (0x0043ae3c) - Moonton custom cipher
  â†’ EncryptLib::decryption (0x0043b42c)
  â†’ XXTEA via LuaStack (0x0047112c â†’ 0x005b2714)
  â†’ AES via CCCrypto (0x00cedf34)
  â†“
[UNKNOWN decompression] â† Range decoder or zlib?
  â†’ lua_moonton_zlibInflate (0x00412a18)
  â†’ inflate (0x00dcad08)
  â†“
Parser (Lua/protobuf)
```

## Last Action Before Save
Was about to use Frida to find the AES/XXTEA key from the running game process (PID 4703).

## Next Steps (Resume from here)

1. **Use Frida to hook the game and find the encryption key:**
   - Connect Frida to PID 4703
   - Hook `CCCrypto::setKey2` (0x00cec678) to capture the AES key
   - Hook `LuaStack::setXXTEAKeyAndSign` (0x0047112c) to capture XXTEA key
   - Hook `lua_moonton_getDoubleBinary` (0x0040a59c) to trace .mt file loading

2. **Alternative: Search for key in binary more thoroughly**
   - Search near `CCCrypto::setKey2` function for the key data
   - Search for XXTEA delta constant (0x9e3779b9) patterns

3. **Fix the decoder:**
   - Once key is found, update `lmf_decoder.py` or create new decoder
   - Compare output byte-by-byte to find exact algorithm differences

4. **Build complete call graph:**
   - Frida trace lua_moonton_getDoubleBinary with arguments
   - Find what calls which decrypt function
   - Document the full pipeline

## Files Reference
- Binary: `C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\emulator_mt\libagame.so`
- .mt files: `C:\Users\NGEONG\Videos\PROJECT\emulator_mt\*.mt`
- Python decoder: `C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\scripts\lmf_decoder.py`
- Master doc: `C:\Users\ADMIN SERVICE\Videos\MLA\PROJECT\from_termux\mla_reverse_engineering_resume_Android.md`

## Frida Connection Command
```bash
ADB="D:/Program Files/Microvirt/MEmu/adb.exe"
EMU="127.0.0.1:21503"
"$ADB" -s "$EMU" forward tcp:27042 tcp:27043
# Then in Python:
device = frida.get_device_manager().add_remote_device('127.0.0.1')
session = device.attach(4703)  # com.moonton.mobilehero PID
```
