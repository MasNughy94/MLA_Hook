# Gap Analysis — .mt File Decryptor Feasibility

---

## 1. PIPELINE STAGE ASSESSMENT

### Stage 1: File Path Resolution & Reading

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| `require()` hook → `cocos2dx_lua_loader` | **VERIFIED** | Symbol 0x474028, BL targets confirmed in disassembly | Tidak ada | N/A |
| `FileUtils::getInstance()` → singleton | **VERIFIED** | Symbol 0x7d27e8, BL @ 0x4742a8 | Tidak ada | N/A |
| vtable[5] dispatch → `getDataFromFile` | **VERIFIED** | RELA _ZTV[7]=0x7d2f38, BLR @ 0x4742bc | Tidak ada | N/A |
| `FileUtilsAndroid::getData` (AAssetManager/fopen) | **VERIFIED** | Symbol 0x7d2888, 1456 bytes, file I/O calls present | Tidak ada untuk decryptor (decryptor membaca dari disk langsung) | N/A |

### Stage 2: Antm Header Parsing

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| Size guard (< 16 → skip) | **VERIFIED** | 0xc82ad8-0xc82ae0 | Tidak ada | N/A |
| Magic check (`Antm` @ offset 0) | **VERIFIED** | 0xc82ae8-0xc82af8, nilai 0x6D746E41 | Tidak ada | N/A |
| Already-decrypted check (offset 8 == 0xABCDEF) | **VERIFIED** | 0xc82b24-0xc82b34 | Tidak ada | N/A |
| Version byte (offset 4) | **VERIFIED** | 0xc82b38-0xc82b48 | Tidak ada | N/A |
| Payload size (offset 8) XOR 0x00ABCDEF | **VERIFIED** | 0xc82b58 | Tidak ada | N/A |
| Unknown field (offset 0x0C, 4 bytes) | **PARTIAL** | Dibaca tetapi tidak digunakan dalam decryptData | Fungsi field ini (checksum? flags?) | Rendah — tidak mempengaruhi decrypt, hanya parsing |
| Header size = 16 bytes | **VERIFIED** | Payload selalu dimulai di offset 0x10 | Tidak ada | N/A |

### Stage 3: Decryption — Version 2 (XOR path)

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| `xor_decrypt` dipanggil | **VERIFIED** | BL @ 0xc82b64 ke 0xceccec; simbol `_ZN8CCCrypto11xor_decryptEPcj` | Tidak ada | N/A |
| Parameter: data = payload, len = payload_size | **VERIFIED** | x0 = buffer+0x10, w1 = payload_size | Tidak ada | N/A |
| Algoritma XOR internal | **UNKNOWN** | Belum dianalisis | **XOR key/pattern** — apakah fixed key? derived? byte-by-byte? | **BLOCKING** — tanpa ini, v2 tidak bisa didecrypt |
| Operasi in-place | **VERIFIED** | Buffer yang sama, tidak ada alokasi baru | Tidak ada | N/A |

### Stage 4: Decryption — Version 1 (AES path)

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| `getKey()` dipanggil | **VERIFIED** | BL @ 0xc82be8 ke 0xcec678; simbol `_ZN8CCCrypto6getKeyEv` | Fungsi ada, dipanggil | N/A |
| `getKey()` parameter dan return | **PARTIAL** | x8 = &stack_string sebelum call; tidak ada parameter formal | **Algoritma internal getKey** — bagaimana key dihasilkan/diambil? | **BLOCKING** — tanpa key, AES tidak bisa didecrypt |
| `aes_decrypt` dipanggil | **VERIFIED** | BL @ 0xc82c0c ke 0xcec5c0; simbol `_ZN8CCCrypto11aes_decryptEPKcS1_RKSsPci` | Tidak ada | N/A |
| Parameter aes_decrypt | **PARTIAL** | x0=payload, x1=buffer_end, x2=&key, x3=temp_buf, w4=size | **Mode AES** — ECB? CBC? Parameter ke-2 (const char*) untuk apa? | **MEDIUM** — jika mode salah, hasil decrypt berbeda |
| Return value aes_decrypt | **VERIFIED** | w0 = 0 (fail) / 1 (success) | Tidak ada | N/A |
| Alokasi buffer | **VERIFIED** | malloc(payload_size+1) @ 0x3fa240 | Tidak ada | N/A |

### Stage 5: Compression Detection

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| `isGZipBuffer` dipanggil | **VERIFIED** | BL @ 0xc82b7c, 0xc82c60 ke 0xca4638; simbol `_ZN7cocos2d8ZipUtils12isGZipBufferEPKhl` | Tidak ada | N/A |
| Check: data[0]==0x1F && data[1]==0x8B | **VERIFIED** | Disassembly 0xca4638-0xca465c | Tidak ada | N/A |

### Stage 6: Decompression — zlib

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| `inflateMemory` dipanggil | **VERIFIED** | BL @ 0xc82b98, 0xc82c78 ke 0xca41c4; simbol `_ZN7cocos2d8ZipUtils13inflateMemoryEPhlPS1_` | Tidak ada | N/A |
| Parameter: compressed data, size, &out_ptr | **VERIFIED** | x0=data, x1=size, x2=&out_ptr | Tidak ada | N/A |
| Return: pointer to decompressed (NULL=gagal) | **VERIFIED** | x0 = result, cbnz @ 0xc82ba0 | Tidak ada | N/A |
| Implementasi = zlib standar | **VERIFIED** | zlib statically linked, `inflate` function tersedia di binary | Tidak ada | N/A |

### Stage 7: Decompression — lmF@ (Custom)

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| `uncompressData` dipanggil | **VERIFIED** | BL @ 0xc82cec, 0xc82d50 ke 0xcecd24; simbol `_ZN8CCCrypto14uncompressDataEPcjPPhRm` | Tidak ada | N/A |
| Parameter: data, size, &out_ptr, &out_size | **VERIFIED** | x0=data, w1=size, x2=&out_ptr, x3=&out_size | Tidak ada | N/A |
| Size guard (< 0xD → return 0) | **VERIFIED** | 0xcecd28-0xcecd2c | Tidak ada | N/A |
| lmF@ magic header | **PARTIAL** | Terdokumentasi di PIPELINE.md | **Format `lmF@` belum diverifikasi penuh** — struktur header, XOR key untuk size field | **HIGH** — jika file menggunakan lmF@ |
| Algoritma decompress internal | **PARTIAL** | Terdapat di 0xcecd24 (704 bytes), memanggil sub_CF2110 (Huffman/range decoder) | **Detail algoritma** — emulasi sebelumnya gagal (return 1 bukan 0) | **HIGH** — critical untuk files yang pake lmF@ |
| sub_CF2110 → sub_CF0B04 (range decoder) | **PARTIAL** | Didekompilasi di session.md, state + tree building + main decode | **Root cause emulation failure** — cbnz jump ke error path @ 0xcf24e4 | **HIGH** — decompressor belum bekerja |

### Stage 8: Post-decrypt — LuaStack::luaLoadBuffer (XXTEA)

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| `luaLoadBuffer` dipanggil | **VERIFIED** | BL @ 0x474300 ke 0x47249c; simbol cocos2d::LuaStack::luaLoadBuffer | Tidak ada | N/A |
| Flag check (byte at this+0x2c) | **VERIFIED** | ldrb w0, [x0, #0x2c]; cbz @ 0x4724dc | Tidak ada | N/A |
| XXTEA sign check (call 0x3fad00) | **VERIFIED** | 0x4724f4: bl 0x3fad00 dengan buffer + this->xxtea_sign | **Apa yang dilakukan 0x3fad00?** — mungkin strncmp atau memcmp | N/A |
| `xxtea_decrypt` dipanggil | **VERIFIED** | BL @ 0x47255c ke 0x5b2714; simbol `_ZN7cocos2d8ZipUtils13xxtea_decryptEPhjS_jPj` | Tidak ada | N/A |
| `luaL_loadbuffer` | **VERIFIED** | BL @ 0x47250c, 0x472574 ke 0x66b13c | Tidak ada | N/A |
| XXTEA key (this+0x30) | **PARTIAL** | Field teridentifikasi, di-set via `setXXTEAKeyAndSign` | **Nilai key** — apakah di-set oleh game? dari mana? | **MEDIUM** — jika XXTEA diaktifkan |
| XXTEA sign (this+0x40) | **PARTIAL** | Field teridentifikasi | **Nilai sign** — magic bytes untuk deteksi XXTEA | **MEDIUM** — sama |
| Apakah XXTEA diaktifkan? | **UNKNOWN** | Flag byte (this+0x2c) tidak diketahui nilainya saat runtime | **Nilai flag** — apakah 0 atau non-0? | **HIGH** — jika flag=1, decryptData output masih perlu XXTEA decrypt |
| `setXXTEAKeyAndSign` caller | **UNKNOWN** | Fungsi 0x47112c tersedia | **Siapa yang memanggil?** — inisialisasi LuaStack | **MEDIUM** — bisa dilacak dari xref |

### Stage 9: Lua VM

| Tahap | Status | Bukti | Masih Belum Diketahui | Dampak |
|-------|--------|-------|----------------------|--------|
| `luaL_loadbuffer` | **VERIFIED** | 0x66b13c, standar Lua API | Tidak ada | N/A |

---

## 2. BLOCKING ISSUES (Diurutkan berdasarkan prioritas)

### Priority 1: Algoritma xor_decrypt (0xceccec) — Version 2 path

**Informasi hilang**: XOR key/pattern yang digunakan oleh `CCCrypto::xor_decrypt`.

**Mengapa penting**: Version 2 adalah path paling umum menurut dokumentasi. Tanpa algoritma XOR, v2 files tidak bisa didecrypt sama sekali.

**Dapatkah diperoleh dari analisis statis?**: **YA** — fungsi ini hanya 56 bytes. Analisis Capstone penuh dapat mengungkap:
- XOR key (fixed atau derived dari parameter)
- Pola XOR (byte-by-byte, word, atau streaming)
- Apakah fungsi identik dengan `xor_encrypt` (0xcecc44)

**Apakah memerlukan runtime?**: TIDAK — logika XOR biasanya sederhana dan sepenuhnya dapat dibalik dari disassembly.

**Dampak blocking**: Jika v2 adalah mayoritas file, decryptor tidak berfungsi sama sekali.

### Priority 2: Algoritma getKey (0xcec678) + aes_decrypt (0xcec5c0) — Version 1 path

**Informasi hilang**: 
- `getKey()`: Bagaimana AES key dihasilkan/diperoleh (hardcoded, derived dari file, dari Android Keystore?)
- `aes_decrypt`: Mode AES (ECB, CBC, CTR?), tujuan parameter ke-2 (buffer_end/IV?)

**Mengapa penting**: Kedua sample .mt yang tersedia (`e/` directory) adalah **version 1**. Tanpa ini, sample yang ada tidak bisa didecrypt.

**Dapatkah diperoleh dari analisis statis?**: 
- `getKey()` (44 bytes): **YA** — fungsi kecil, analisis penuh bisa mengungkap sumber key (string hardcoded, file, atau turunan). Jika key berasal dari file atau Android API, perlu runtime.
- `aes_decrypt` (184 bytes): **PARTIAL** — mode AES dapat ditentukan dari melihat internal call (OpenSSL EVP_* atau custom AES::*). Tapi jika ada parameter IV dinamis, runtime mungkin diperlukan.

**Apakah memerlukan runtime?**: 
- `getKey()`: MUNGKIN — jika key berasal dari Android Keystore atau file eksternal, runtime diperlukan.
- `aes_decrypt`: TIDAK — mode dan key schedule bisa ditentukan statis.

**Dampak blocking**: Sample yang tersedia adalah v1 → decryptor tidak berguna untuk sample yang ada.

### Priority 3: lmF@ decompression (uncompressData @ 0xcecd24) — Fallback path

**Informasi hilang**: Algoritma decompress custom `lmF@` belum berhasil direproduksi.

**Mengapa penting**: Jika file setelah decrypt/XOR tidak memiliki header gzip (0x1F8B), game menggunakan path ini. Prioritas lebih rendah karena:
- zlib path dicek terlebih dahulu
- Banyak file mungkin menggunakan zlib

**Dapatkah diperoleh dari analisis statis?**: **YA** — fungsi 704 bytes sudah dianalisis sebagian di session.md. Masalah ada di emulasi (sub_CF2110 → cbnz jump ke error). Root cause bisa ditemukan dengan analisis lebih lanjut.

**Apakah memerlukan runtime?**: TIDAK — algoritma sepenuhnya di binary. Hanya perlu reverse engineering yang benar.

**Dampak blocking**: Hanya untuk file yang menggunakan lmF@. Jika mayoritas file menggunakan zlib, blocking rendah untuk decryptor dasar.

### Priority 4: XXTEA path (LuaStack::luaLoadBuffer)

**Informasi hilang**: 
- Nilai flag XXTEA (this+0x2c) saat runtime
- XXTEA key dan sign string
- Siapa yang memanggil `setXXTEAKeyAndSign`

**Mengapa penting**: Jika flag non-0, output dari decryptData masih perlu XXTEA decrypt sebelum masuk Lua VM.

**Dapatkah diperoleh dari analisis statis?**: **YA** — dapat dilacak dari xref ke `setXXTEAKeyAndSign` (0x47112c) dan inisialisasi LuaStack.

**Apakah memerlukan runtime?**: MUNGKIN — key bisa berasal dari file konfigurasi atau hardcoded. Jika hardcoded, statis cukup.

**Dampak blocking**: Jika XXTEA aktif, output decryptor masih terenkripsi XXTEA dan tidak berguna.

---

## 3. KEPUTUSAN FINAL

| Pertanyaan | Jawaban |
|------------|---------|
| Apakah berdasarkan seluruh bukti yang tersedia saat ini kita sudah dapat membuat tool decryptor yang menghasilkan output identik dengan game? | **NO** |

### Alasan:

**Blocking issues total ada 3 yang harus diselesaikan:**

1. **xor_decrypt (Priority 1)** — Algoritma XOR belum dianalisis sama sekali. Fungsi 56 bytes perlu didisassembly dan direverse. Tanpa ini, version 2 path tidak berfungsi.

2. **getKey + aes_decrypt (Priority 2)** — Kedua sample yang tersedia adalah version 1. `getKey()` (44 bytes) perlu dianalisis untuk mengetahui sumber AES key. `aes_decrypt` (184 bytes) perlu dianalisis untuk menentukan mode AES. Tanpa ini, sample yang ada tidak bisa didecrypt.

3. **lmF@ decompressor (Priority 3)** — Jika file menggunakan `lmF@` (bukan zlib), decompressor custom diperlukan. Implementasi yang ada (dari session.md) memiliki bug yang belum teratasi.

**Informasi yang cukup untuk decryptor PARTIAL**:
- Struktur Antm header: **LENGKAP**
- Deteksi gzip/zlib: **LENGKAP**
- InflateMemory (zlib) standar: **LENGKAP**
- Standard Lua API: **LENGKAP**
- Buffer management dan alokasi: **LENGKAP**
- Vtable dispatch: **LENGKAP**

### Rekomendasi untuk mencapai YES:

1. **Analisis `xor_decrypt` (0xceccec, 56 bytes)**: Disassembly lengkap → reverse algoritma XOR. Estimasi: 1 jam.

2. **Analisis `getKey` (0xcec678, 44 bytes)**: Disassembly lengkap → tentukan sumber key. Estimasi: 1-2 jam. Jika key hardcoded, langsung dapat. Jika dari file/config, perlu lacak lebih lanjut.

3. **Analisis `aes_decrypt` (0xcec5c0, 184 bytes)**: Disassembly lengkap → tentukan mode AES, parameter ke-2. Estimasi: 2-3 jam.

4. **Debug lmF@ decompressor**: Perbaiki emulasi sub_CF2110 → sub_CF0B04. Butuh analisis lebih lanjut tentang penyebab jump ke error path. Estimasi: 4-8+ jam.

5. **Verifikasi XXTEA**: Cari xref ke `setXXTEAKeyAndSign` untuk menentukan apakah XXTEA diaktifkan. Estimasi: 1 jam.

**Total estimasi minimum: 9-15 jam analisis statis** (tanpa runtime/Frida).

### Catatan tentang sample yang ada:
- `e/` directory berisi 2 file .mt, **keduanya version 1 (AES)**
- `decrypted_output/` berisi hasil percobaan sebelumnya (lmF@ decompress dengan key `f5a193d5`, XML, dan raw)
- `mt_dump/` referensi format .mt tidak diperiksa
- Tanpa analisis `getKey` dan `aes_decrypt`, sample yang ada tidak bisa diproses
