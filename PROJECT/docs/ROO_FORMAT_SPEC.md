# Roo Binary Format Specification v1.0
# =====================================
# Based on corpus-wide analysis of 7,258 decompressed .mt assets
# from Mobile Legends: Adventure (MLA)

---

## 1. FILE PACKAGING & DECRYPTION PIPELINE

.mt file → Outer Decryption → Inner Decompression → Roo Binary

### 1.1 Outer Layer: Antm + AES-128-ECB

Offset  Size  Field
------  ----  -----
0       4     Magic: "Antm" (0x6d746e41 LE)
4       1     Encryption type (always 0x01)
5       11    Reserved/header (all zeros)
16      *     AES-128-ECB ciphertext

AES Key (hex): f5a193d50ade553e9835595f5cd75ddd

Decryption: Strip 16-byte Antm header, pad ciphertext to 16-byte boundary,
AES-ECB decrypt, return decrypted bytes (unpadded).

### 1.2 Inner Layer: lmF@ + Custom Range Coder

After AES decryption, the data starts with:

Offset  Size  Field
------  ----  -----
0       4     Magic: "lmF@" (0x40466d6c LE)
4       1     Flags byte 0 (exponent for probability table)
5       3     Flags bytes 1-3 (window size, encoded)
8       2     Reserved
10      4     Encoded uncompressed size: raw ^ 0x3EA
14      *     Compressed payload

Header Parse:
- flags[0] = raw[4]
- flags[1..3] = raw[5..7]
- flags[3] ^= 0x05  (XOR with 5)
- flags[4] = raw[8]
- decompressed_size = u32_le(raw[10:14]) ^ 0x3EA
- XOR first 16 bytes of payload (or decompressed_size, whichever is smaller) with 0xEC

Compression Algorithm: Custom range coder + LZ77
- Probability table initialized to 0x400
- Window size from flags (minimum 0x1000)
- Adaptive probability updates (shift = 5)
- Binary tree decoders for literals, lengths, distances
- State machine driven decompression loop
- Output is the raw Roo binary format

---

## 2. ROO BINARY FORMAT OVERVIEW

After decompression, the data consists of:

- 69-byte shared header (template)
- Body: sequence of 3-byte records [tag, value1, value2]
- Optional: 1-2 trailing bytes (alignment/padding, ignored)

### 2.1 Header Structure (69 bytes)

All 7,243 main-type files share this exact header (only byte 68 varies):

Offset  Offset  Size  Value     Meaning
(hex)   (dec)
------  ------  ----  -----     -------
00      0       4     1B4C6D00  Modified Lua magic; standard Lua is 1B4C7561
04      4       2     0000      Unknown
06      6       4     526F6F00  "Roo\0" (format identifier)
0A      10      16    0000...   Zero padding
1A      26      2     D1D1      Static marker byte pair
1C      28      34    0000...   Zero padding (D1 at offset 60 = 0x3C)
3E      62      6     000000... Zero padding
44      68      1     A9/AA/AB  Format subtype:
                                 - 0xA9: Standard 3-byte records (7243 files)
                                 - 0xAA: Variant 3-byte records (12 files)
                                 - 0xAB: Different format (1 file)

Total: 69 bytes (0x45)

The header is byte-identical across all 7243 main-type files except for
the subtype byte at offset 68.

### 2.2 Body Structure

The body starts at offset 69 and is a sequence of consecutive 3-byte records.
If the body length is not divisible by 3, trailing bytes are ignored.

Record format:
  Byte 0: tag (0x00 = empty/template, 0x01-0xFF = data field)
  Byte 1: value1 (V1) — typically a u8 or lower byte of u16
  Byte 2: value2 (V2) — typically a u8 or upper byte of u16

Combined value: u16 = V1 | (V2 << 8), little-endian

### 2.3 Record Types

#### Empty Record (tag=0x00, V1=0x00, V2=0x00)
~82% of all body bytes. These fill the space between override records.

#### Template Record (tag=0x00, V1≠0 or V2≠0)
Default/skeleton values for fields. These define:
- Which fields exist in each data type
- Default values used when no override is present
- The entry structure template

Template records are shared cross-file — files of the same type have
identical template records at identical positions.

#### Override Record (tag≠0x00)
An instance-specific field value. The tag identifies which field.
Override records appear at specific positions in the body to override
specific template defaults.

### 2.4 Position-Encoded Field IDs

The body is a sparse position-encoded dictionary:
- Record position (byte offset / 3) = implicit field ID
- tag=0 at position N = "use template default for field N"
- tag≠0 at position N = "field N has value (V1, V2)"

This means:
- The template defines fields 0..N with default values
- Individual entries override specific fields
- Fields that aren't overridden use template defaults
- New fields CANNOT be added (they'd need template defaults)

### 2.5 Tag Byte Interpretation

The tag byte identifies which logical field the override applies to.
Tags are typically ASCII letters:

  Range 0x41-0x5A (A-Z): Common in general data types
  Range 0x61-0x7A (a-z): Common in hero-related data
  Range 0xA0-0xBF:      Common in variant 0xAA files
  Other ranges:         Specialized fields

All 255 non-zero byte values (0x01-0xFF) appear as tags across the corpus,
but each file type uses only a subset (avg. ~20 tags per data type).

Most common tags across corpus:
  0x6F (o), 0x6E (n), 0x6D (m), 0x6C (l), 0x67 (g), 0x4C (L)

### 2.6 Value Interpretation

V1 and V2 encode field values. Based on corpus analysis:

Type          Encoding                     Examples
----          --------                     --------
u16           V1 | (V2 << 8)              IDs, counts
u8 pair       V1=low_id, V2=high_id       Composite keys
boolean       0x00/0x01 in V1 or V2       Flags
small enum    0x00-0xFF in V1 or V2       Categorical values
offset        0 or specific byte values   Internal references

~70% of values are in range 0-255 (single byte IDs), suggesting
small-integer identifiers are the most common field type.

### 2.7 Entry Structure

Entries are variable-length clusters of override records.
They are NOT fixed-size structs — entries of the same type can have
different fields depending on which values deviate from template defaults.

Entry clustering algorithm:
  1. Collect all override records (tag≠0)
  2. Sort by body position
  3. Group consecutive records where gap ≤ 30 bytes
  4. Each group = one entry

Each entry represents one game entity instance:
- Hero data entries: ~7-12 override records, tags are lowercase
- Item entries: ~3-8 override records, mixed tags
- Configuration entries: 1-3 override records, sparse

### 2.8 Format Variants

#### Type 0xA9 (7243 files, 99.8%)
Standard 3-byte record format as described above.

#### Type 0xAA (12 files, 0.2%)
Same 69-byte header and 3-byte record format, but:
- Tag bytes cluster in 0xA0-0xCF range (vs ASCII letters)
- Body begins with 0xAA marker (AA 00 00 80 80...)
- Used for specific game data subtypes

#### Type 0xAB (1 file)
Different format, possibly fixed-width or binary:
- 63,639 bytes, 7% non-zero
- 8-byte aligned structures
- Contains ASCII substrings
- Appears to be a different serialization format

#### Truncated (2 files)
Only 60 bytes (header ends at offset 60, missing the 6F A9 footer).
Likely empty data stubs.

---

## 3. CORPUS STATISTICS

Metric                    Value
------                    -----
Total .mt files           7,258
Valid Roo files           7,256
Truncated files           2
Type 0xA9 (main)          7,243
Type 0xAA (variant)       12
Type 0xAB (other)         1
Unique tag values         255
Unique tag-set clusters   7,092 (one per data type essentially)
Max file size             3.4 MB
Median file size          13.7 KB
Avg entries per file      ~42
Avg override records      ~20
Avg template records      ~10
Override density          ~18%

---

## 4. FILE NAMING

All .mt files are named by MD5 hash of the ENCRYPTED content.
The manifest files (resList.lua, resSizeList.lua) provide:

- resList.lua:    Original .mt filename → content hash (what the data represents)
- resSizeList.lua: Original .mt filename → size in KB

The content hash from resList can be used to identify data types:
- Files with identical content hashes contain the same data
- File size correlates with data complexity (more entries = larger file)
- No explicit type/name information exists — type must be inferred from
  tag set and entry structure

---

## 5. SCHEMA INFERENCE METHODOLOGY

For each data type (cluster of files sharing the same tag set):

1. Parse all files in the cluster
2. Identify template defaults (tag=0, V1/V2≠0 at consistent positions)
3. Identify ID fields (tags appearing exactly once per entry)
4. Identify variable fields (tags with multiple unique values)
5. Map field positions to tags
6. Analyze value ranges for each tag
7. Cross-reference entry counts with known game data patterns

---

## 6. FREQUENTLY USED TAGS

Position ranges across corpus for key tag groups:

Lowercase letters (a-z = 0x61-0x7A):
  Most frequently used tag range for hero/character data files
  Typically 10-20 tags per file using this range

Uppercase letters (A-Z = 0x41-0x5A):
  Most frequently used tag range for general game data
  Typically 15-30 tags per file using this range

Non-printable tags (0x01-0x40, 0x7F-0x9F, 0xA0-0xFF):
  Used in specialized data files
  Often appear in files with >50 tags (comprehensive databases)
