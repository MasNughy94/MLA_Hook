# Resume Reverse Engineering Mobile Legends Adventure (MLA)
**Terakhir diperbarui:** 2026-06-30 (Update: decoder 100% verified)
**Penyimpanan:** /storage/emulated/0/Fonts/ + C:\Users\ADMIN SERVICE\Pictures\RESUME\

## 1. Arsitektur Pipeline

```
.mt file (Antm magic, AES-ECB encrypted)
    â”‚
    â–¼
AES Decrypt (key: f5a193d50ade553e9835595f5cd75ddd, mode: ECB)
    â”‚
    â–¼
lmF@ format (inner compressed header)
    â”œâ”€â”€ Header (14 bytes): magic "lmF@", e, reserved[5], ds (XOR 0x3EA)
    â”œâ”€â”€ Payload terenkripsi XOR (16 byte pertama XOR 0xEC)
    â””â”€â”€ Data terkompresi (range coder LZMA-like)
    â”‚
    â–¼
Decompress LZMA â†’ output (Roo Binary / Lua bytecode / unknown)
```

## 2. AES Layer

**File kunci:** `process_mt_all.py`, fungsi `aes_decrypt()`

```python
AES_KEY = bytes.fromhex("f5a193d50ade553e9835595f5cd75ddd")
cipher = AES.new(AES_KEY, AES.MODE_ECB)
```

- Magic: `Antm` (4 byte pertama .mt file)
- Mode: **ECB** (bekerja untuk file single-block; multi-block mungkin perlu CBC dengan IV derivasi)
- Skip 16 byte header `Antm` + 12 byte reserved sebelum decrypt

**Catatan:** Document resume mengatakan AES-128-CBC (unknown IV), tapi ECB berhasil. Jika ada file multi-block yang gagal, coba CBC dengan IV dari byte 4-19 header.

## 3. lmF@ Header Parse

```python
hdr = data[:14]         # "lmF@" + 10 bytes
e = hdr[4]              # encoded parameter
ws = e // 9             # window size exponent
r9 = e % 9              # reserved?  
ps = (ws * 0xCCCCCCCD) >> 34  # position bits
r5 = ws - ps * 5        # literal context bits
te = (0x300 << (r5 + r9)) + 0x736  # total table entries
mk = (1 << ps) - 1      # position mask
ds = unpack('<I', data[0x0A:0x0E])[0] ^ 0x3EA  # decompressed size
```

**Konstanta:**
- Table base: 0x736 (literal tree root)
- Match length tree: 0x332 (short match)  
- Match decision: state + 0xC0
- Distance slot: 0x1B0 + sc * 64

## 4. Range Decoder â€” FIXED IMPLEMENTATION

**Konstanta:**
```python
_P_INIT = 0x400          # Initial probability (1024 = kBitModelTotal/2)
_P_MAX = 0x800           # Max probability (2048 = kBitModelTotal)
_P_SHIFT = 5             # Probability update rate
_RBITS = 11              # Range bits
_RENORM = 0x1000000      # Renorm threshold (24 bits)
```

**Initial state dari 5 byte context (cd[0:5]):**
```python
self.si = cd[0] & 0xF        # State (0-12)
self.h = 0xFFFFFFFF          # Range (full 32-bit)
self.l = (cd[1]<<24)|(cd[2]<<16)|(cd[3]<<8)|cd[4]  # Code (big-endian)
```

âš ï¸ **PENTING:** Initial `l` menggunakan big-endian byte order dari cd[1..4]. Endianness tidak berpengaruh signifikan karena renormalisasi cepat menimpa nilai awal.

### 4.1 Renormalisasi (`_rn`)
```python
def _rn(self):
    while self.h < _RENORM:      # < 0x1000000
        self.h = (self.h << 8) & 0xFFFFFFFF
        if self.dp < len(self.cd):
            self.l = ((self.l << 8) | self.cd[self.dp]) & 0xFFFFFFFF
            self.dp += 1
        else:
            self.l = (self.l << 8) & 0xFFFFFFFF
```

### 4.2 Decode 1 bit (`_db(pr)`)
```python
def _db(self, pr):
    self._rn()
    m = ((self.h >> _RBITS) * pr) & 0xFFFFFFFF
    if self.l < m:
        self.h = m
        return 0          # left: bit = 0
    else:
        self.l = (self.l - m) & 0xFFFFFFFF
        self.h = (self.h - m) & 0xFFFFFFFF
        return 1          # right: bit = 1
```

âš ï¸ **Model `_db(pr)`** â€” Caller mengelola update tabel probabilitas (`_upd`), mirip implementasi native. Berbeda dari model `_db(idx)` di kode original.

### 4.3 Update Probabilitas

```python
def _upd(prob, bit):
    if bit == 0:
        # Naikkan probabilitas (bit 0 jadi lebih mungkin)
        return (prob + ((_P_MAX - prob) >> _P_SHIFT)) & 0xFFFF
    else:
        # Turunkan probabilitas (bit 1 jadi lebih mungkin)
        return (prob - (prob >> _P_SHIFT)) & 0xFFFF
```

## 5. Decompression Loop

### 5.1 Main Decision
```python
ci = (self.si << 4) + (self.bc & self.mk)   # context index
pr = self.tbl[ci]
is_match = self._db(pr)
self.tbl[ci] = _upd(pr, is_match)
```
- `si = ctx[0] & 0xF` â€” state dari context byte terbaru
- `mk = (1 << ps) - 1` â€” position mask (biasanya 3 atau 7)
- `bc` â€” counter byte output (bukan bit!)
- Jika bit = 0 â†’ **LITERAL**, bit = 1 â†’ **MATCH**

### 5.2 LITERAL Decode

**FIXED: Binary tree (no-context)**
```python
def _decode_literal(self):
    ii = 1
    while ii <= 0xFF:
        pr = self.tbl[0x736 + ii]
        b = self._db(pr)
        self.tbl[0x736 + ii] = _upd(pr, b)
        ii = (ii << 1) | b
    return ii & 0xFF
```
Tree root di 0x736+1, setiap node punya 2 child: `ii = (ii << 1) | bit`.

**Catatan:** Native mungkin gunakan context `(prev_byte >> (8-lc)) + ((bc & lp_mask) << lc)` untuk memilih tree yang berbeda. Coba implementasi:

```python
ctx_lc = (self.pb >> (8 - lc)) + ((self.bc & lp_mask) << lc)
tree_start = 0x736 + ctx_lc * 0x300
# tapi pastikan tree_start + 0xFF < te
```

### 5.3 MATCH Length

```python
def _decode_match_length(self):
    si2 = self.si + 0xC0
    if si2 >= self.te: si2 = 0xC0
    pr = self.tbl[si2]; bs = self._db(pr); self.tbl[si2] = _upd(pr, bs)
    
    if bs == 0:
        # Short match: tree at 0x332
        ii = 1
        while ii <= 7:
            idx = 0x332 + ii
            if idx >= self.te: break
            pr = self.tbl[idx]; b = self._db(pr); self.tbl[idx] = _upd(pr, b)
            ii = (ii << 1) | b
        l2 = (ii & 0xFF) + 3    # range: 3..(7+3=10?) â†’ 3..10
    else:
        # Long match: sequential bits at (si << 4) + 0xCC + i
        l2 = 0
        for i in range(5):
            idx = (self.si << 4) + 0xCC + i
            if idx >= self.te: break
            pr = self.tbl[idx]; b = self._db(pr); self.tbl[idx] = _upd(pr, b)
            l2 = (l2 << 1) | b
            if b == 0: break
        l2 += 3                  # range: 3..(31+3=34)
    return l2
```

### 5.4 MATCH Distance

```python
def _decode_match_distance(self, l2):
    sc = min(l2 - 3, 3)          # slot context (0-3)
    sb = 0x1B0 + sc * 64         # slot base
    
    sl = 0                       # decoded slot
    for i in range(6):
        idx = sb + i
        if idx >= self.te: break
        pr = self.tbl[idx]; b = self._db(pr); self.tbl[idx] = _upd(pr, b)
        sl = (sl << 1) | b
        if b == 0: break
    
    if sl < 4:
        d2 = sl + 1              # direct distance
    else:
        ex = (sl >> 1) - 1       # extra bits count
        d2 = ((2 + (sl & 1)) << ex) + 1
        for i in range(ex):
            idx = sb + 6 + i
            if idx >= self.te: break
            pr = self.tbl[idx]; b = self._db(pr); self.tbl[idx] = _upd(pr, b)
            d2 = (d2 << 1) | b
    return d2
```

### 5.5 Match Copy â€” FIXED

```python
src_base = self.wp - d2
for i in range(l2):
    if 0 <= src_base < 4096:           # bounds check
        src = (src_base + i) & 0xFFF   # advance through window
        by = self.w[src]
    else:
        by = 0                         # jika invalid, isi 0
    self.out.append(by)
    self.w[self.wp & 0xFFF] = by
    self.wp += 1
    self.pb = by
    self._shift_ctx(by)
```

âš ï¸ **BUG ORIGINAL (sekarang fixed):**
- Original: `src = (self.wp - d2) & 0xFFF` â€” selalu ambil dari posisi SAMA setiap iterasi
- Fixed: `src = (src_base + i) & 0xFFF` â€” advance melalui source bytes
- Juga: bounds check `0 <= src_base < 4096` untuk mencegah out-of-bounds

## 6. Ringkasan Bug & Fix

| Bug | Kode Original | Kode Fixed | Dampak |
|-----|---------------|------------|--------|
| Match copy tidak advance | `src = (wp-d2)&0xFFF` (sama terus) | `(src_base+i) & 0xFFF` | RLE syndrome |
| Match overflow | Tidak ada batas | `l2 = min(l2, remaining)` | Byte terakhir korup |
| Bounds check src | `w[src]` langsung | `if 0 <= src_base < 4096` | Match ke posisi -1 |
| Literal via formula | `_decode_literal_formula()` | Binary tree `0x736+ii` | Byte pertama salah |
| `_db(idx)` model | `_db(idx)` update tabel internal | `_db(pr)` caller manage | Divergensi probabilitas |
| State machine terpisah | `self.state = 0..12` | `self.si = ctx[0] & 0xF` | Match decision kacau |
| Renorm order | Check di dalam _db | Sama (tidak masalah) | Tidak berdampak |
| Endianness | BE vs LE | Sama (renorm cepat timpa) | Tidak berdampak |

## 7. Hasil Test

| Versi | Match % | Keterangan |
|-------|---------|------------|
| Original (process_mt_all.py) | ~1% | Semua bug |
| + Binary tree literal | ~5% | First byte benar |
| + Copy fix + bounds check | **31.5%** | Best so far (Android) |
| **Python decoder (claude)** | **100%** | **32553/32553 bytes, verified** |
| Target native | 100% | **TERCAPAI** (via Python) |

**Verified:** `0000488d2f64199aca0cc7d54e7d11c0.mt` â†’ `01_aes_output.bin` â†’ `0002_final_decompressed.bin` = **32553/32553 bytes match**.

**Catatan:** Perbedaan hasil 31.5% di Android vs 100% di Windows karena:
- Android `process_mt_all.py` pakai implementasi berbeda (masih ada bug)
- Decoder 100% ada di `PROJECT/scripts/lmf_decoder.py` (binary tree literal, `_db(pr)` model, match copy advance)
- Kedua implementasi perlu disinkronisasi

## 8. Masih Tersisa (Open Problems)

### 8.1 ~~Main Decision Divergence di Byte ke-2~~ âœ… **RESOLVED**
- **Status:** Decoder Python (`lmf_decoder.py`) menghasilkan **100% match** â€” 32553/32553 bytes.
- Root cause yang diperbaiki:
  1. Binary tree literal (bukan formula-based) â€” `0x736 + ii`
  2. `_db(pr)` model â€” caller manage probability update
  3. Match copy advance properly â€” `(src_base + i) & 0xFFF`

### 8.2 AES Mode
- Document bilang AES-128-CBC, kita pakai ECB
- Untuk file multi-block, perlu cari IV (mungkin dari byte 4-19 header .mt)

### 8.3 Native Binary
- `mt_native` (ARM64 ELF) tidak tersedia
- Frida hook untuk libagame.so diperlukan untuk verifikasi native

### 8.4 Sinkronisasi Implementasi
- `lmf_decoder.py` (Windows, 100%) vs `process_mt_all.py` + `lmf_fix.py` (Android, 31.5%)
- Perlu merge decoder 100% ke `process_mt_all.py`

## 9. Perintah Berguna

```bash
# Test semua file
cd ~ && python3 -c "import process_mt_all as p; p.main()" scan downloads/mt_test_vectors
cd ~ && python3 -c "import struct,glob,os; ...[inline test script]..."

# Process file spesifik
cd ~ && python3 process_mt_all.py process-file path/file.mt output_dir

# Frida hooks
cd ~ && ls downloads/frida*  # frida_hook_decompress.js, frida_dump_decoder.js
```

## 10. File Referensi

```bash
~/process_mt_all.py              # Main production script (FIXED)
~/lmf_fix.py                     # Alternative decompressor
~/mt_tool.py                     # Original buggy version
~/downloads/mt_tool_v2.py        # Second version
~/downloads/decode_full.py       # Full pipeline test
~/downloads/roo_parser.py        # Roo Binary parser
/storage/emulated/0/Alarms/lmf_decompress.py   # Alarms/working reference
/storage/emulated/0/PROJECT/REVERSE/lmf_decompress.py  # Experimental
~/downloads/mt_test_vectors/     # 92 pairs .lmf + .luac
/storage/emulated/0/Download/mla_reverse_engineering_resume.tex  # LaTeX doc
```

## 11. Langkah Selanjutnya (Prioritas)

1. **Frida tracing**: Hook `sub_CF2110` di libagame.so saat game berjalan untuk capture:
   - Initial range decoder state (h, l, tbl snapshot)
   - Per-byte output native
   - Context index untuk literal tree
   
2. **Implementasikan literal tree dengan context**: Gunakan formula `(prev_byte >> (8-lc)) + ((bc & lp_mask) << lc)` untuk select tree

3. **Probabilitas dinamis**: Coba initial probabilitas berbeda per region tabel (0x400 bukan untuk semua entry)

4. **Formula 5 untuk main decision**: Dari document, formula 5 diverifikasi untuk test vector. Mungkin main decision pakai formula sementara literal pakai binary tree.

5. **Validasi dengan file APK asli**: Process semua .mt di `~/downloads/mla_frida_signed.apk` (728MB)
