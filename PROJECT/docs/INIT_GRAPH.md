# Initialization Call Graph — libagame.so & libhades.so

## Overview
Complete call graph of startup, covering linker-level init, JNI_OnLoad, and engine bootstrap.

---

## Legend
```
[Node]         Function/entry point
{Node}         Data structure / memory region
→ ...          Calls / depends on
← ...          Called by
`address`      Virtual address (static base = 0)
===            Major phase boundary
```

---

## 1. libhades.so — ByteDance TGRP Downloader

### 1.1 Linker-Level Init (Phase 2.1–2.4)

```
[Android linker64]  ← App process / System.loadLibrary("hades")
  │
  ├──{RELA entries}──→{.init_array: 70 function pointers stored in GOT}
  │                      at 0x1db000 (GOT range)
  │
  ├──[DT_INIT: 0x6bc14]──→??? (obfuscated — likely real entry decryption)
  │
  ├──[DT_INIT_ARRAY[0]: 0x3c28c]──→trampoline branches to dispatcher
  │   │                              at 0x22dd0
  │   └──[0x22dd0]──→GOT-based indirect jump (adrp x16, #0x1db000;
  │                   └────────────────────────────────── ldr x17, [x16,#ofs]; br x17)
  │                                 This is a trampoline table — all 70 init
  │                                 functions redirect through their GOT entries.
  │
  ├──[DT_INIT_ARRAY[1]: 0x3c27c]──→Moonton Protect init
  │   mov x0, #0x1d2000            │ prepare metadata struct
  │   add x0, x0, #0x240           │   → address 0x1d2240
  │   b #0x22dd0                   │   → dispatcher→calls real init function
  │
  ├──[Moonton Protect init at GOT[0x1db000+?]]──→decrypts string table
  │   0x22f80: decrypts .rodata strings → .data (0x1dc000+)
  │           "download_common", "download_failed", "download_field", etc.
  │           (TGRP downloader setup)
  │
  └──[69 more init functions at GOT-0x1db000+...]──→various sub-system inits
```

### 1.2 JNI_OnLoad (Phase 2.5)

```
[JNI_OnLoad @ 0xb04c8 → body @ 0xb0398]
  │
  ├──→[0xa5ee8] module_init / check version
  │
  ├──→[0xa5f00] env / JNI setup
  │
  ├──→[0xa5d44] version / platform checks
  │
  ├──→FindClass("com/bytedance/hades/tgrp/impl/TGRPDownloaderImpl")
  │    string at .rodata + 0xd5c (relative to 0x178000)
  │
  ├──→FindClass("com/bytedance/hades/tgrp/impl/TGRPServiceImpl")
  │    string at .rodata + 0xd8d (relative to 0x178000)
  │
  ├──→RegisterNatives(TGRPDownloaderImpl, table@0x1dc3b0, 51 methods)
  │   Methods include:
  │   ├── nativeGetTGRPDownloader
  │   ├── nativeGetConfiguration
  │   ├── nativeGetDataMigration
  │   ├── nativeGetEventReporter
  │   ├── nativeInit
  │   ├── nativeSetLogLevel
  │   ├── nativeSetSSLPinCertCallback
  │   └── ... 44 more
  │
  ├──→RegisterNatives(TGRPServiceImpl, table@0x1dc878, 2 methods)
  │   ├── nativeSetLogLevel
  │   └── nativeInitTGRPService
  │
  └──→return JNI_VERSION_1_4 (0x10004)
```

**Important**: `libhades.so` JNI_OnLoad does NOT interact with libagame.so.
TGRP is purely a downloader/updater that fetches game assets from ByteDance's CDN.

---

## 2. libagame.so — Main Game Engine (Packed)

### 2.1 Linker-Level Init — RELA Unpacking (Phase 3.1–3.4)

```
[Android linker64]  ← App process / System.loadLibrary("agame")
  │
  ├── Map LOAD segments (6 program headers):
  │   LOAD[0]: 0x00000000 – 0x115b514 (RX, .text + .rodata + .dynstr + .dynsym)
  │   LOAD[1]: 0x115c000 – 0x118c000 (RW, .init_array + .fini_array + .dynamic)
  │   LOAD[2]: 0x118c000 – 0x11d4000 (RW, .got + .data + .rela.plt)
  │   LOAD[3]: 0x11d4000 – 0x11e7000 (RW, .data.rel.ro + .got.plt + more data)
  │   LOAD[4]: 0x11e7000 – 0x11e8000 (RW, more data)
  │   LOAD[5]: 0x11e8000 – 0x124f000 (RW, BSS)
  │
  ├── Process DT_RELA — 61,660 entries total
  │   │
  │   ├─── RELA targeting .init_array (0x115d478–0x115dad8):
  │   │    ├── entry[0]:  r_offset=0x115d478, addend=0x3ff5a0
  │   │    │   → writes: *(base+0x115d478) = base + 0x3ff5a0
  │   │    ├── entry[1]:  r_offset=0x115d480, addend=0x3ff5cc
  │   │    ├── entry[2]:  r_offset=0x115d488, addend=0x3ff6f4
  │   │    ├── entry[3]:  r_offset=0x115d490, addend=0x3ff744
  │   │    ├── entry[4]:  r_offset=0x115d498, addend=0x3ff7ac
  │   │    ├── entry[5]:  r_offset=0x115d4a0, addend=0x3ff878
  │   │    ├── entry[6]:  r_offset=0x115d4a8, addend=0x3ff8a0
  │   │    ├── entry[7]:  r_offset=0x115d4b0, addend=0x3ff98c
  │   │    ├── entry[8]:  r_offset=0x115d4b8, addend=0x3ffa2c
  │   │    ├── entry[9]:  r_offset=0x115d4c0, addend=0x3ffb14
  │   │    ├── entry[10]: r_offset=0x115d4c8, addend=0x3ffb38
  │   │    ├── entry[11]: r_offset=0x115d4d0, addend=0x3ffb70
  │   │    ├── entry[12]: r_offset=0x115d4d8, addend=0x3ffbdc
  │   │    ├── entry[13]: r_offset=0x115d4e0, addend=0x3ffc28
  │   │    ├── entry[14]: r_offset=0x115d4e8, addend=0x3ffc60
  │   │    ├── entry[15]: r_offset=0x115d4f0, addend=0x3ffcc0
  │   │    ├── entry[16]: r_offset=0x115d4f8, addend=0x3ffd84
  │   │    ├── entry[17]: r_offset=0x115d500, addend=0x3ffda0
  │   │    ├── entry[18]: r_offset=0x115d508, addend=0x3ffe10
  │   │    ├── entry[19]: r_offset=0x115d510, addend=0x3ffe88
  │   │    ├── entry[20]: r_offset=0x115d518, addend=0x3ffea0
  │   │    ├── entry[21]: r_offset=0x115d520, addend=0x3ffefc
  │   │    ├── entry[22]: r_offset=0x115d528, addend=0x3fff68
  │   │    ├── entry[23]: r_offset=0x115d530, addend=0x3fffa4
  │   │    ├── entry[24]: r_offset=0x115d538, addend=0x400010
  │   │    ├── entry[25]: r_offset=0x115d540, addend=0x400074
  │   │    ├── entry[26]: r_offset=0x115d548, addend=0x4000ac
  │   │    ├── entry[27]: r_offset=0x115d550, addend=0x4000d0
  │   │    ├── entry[28]: r_offset=0x115d558, addend=0x400114
  │   │    ├── entry[29]: r_offset=0x115d560, addend=0x400140
  │   │    ├── entry[30]: r_offset=0x115d568, addend=0x4002b8
  │   │    ├── entry[31]: r_offset=0x115d570, addend=0x4002e8
  │   │    ├── entry[32]: r_offset=0x115d578, addend=0x400328
  │   │    ├── entry[33]: r_offset=0x115d580, addend=0x400360
  │   │    ├── entry[34]: r_offset=0x115d588, addend=0x400424
  │   │    ├── entry[35]: r_offset=0x115d590, addend=0x400624
  │   │    ├── entry[36]: r_offset=0x115d598, addend=0x400638
  │   │    ├── entry[37]: r_offset=0x115d5a0, addend=0x400898
  │   │    ├── entry[38]: r_offset=0x115d5a8, addend=0x4008f0
  │   │    ├── entry[39]: r_offset=0x115d5b0, addend=0x400938
  │   │    ├── entry[40]: r_offset=0x115d5b8, addend=0x400964
  │   │    ├── entry[41]: r_offset=0x115d5c0, addend=0x400988
  │   │    ├── entry[42]: r_offset=0x115d5c8, addend=0x400a24
  │   │    ├── entry[43]: r_offset=0x115d5d0, addend=0x400a48
  │   │    ├── entry[44]: r_offset=0x115d5d8, addend=0x400a80
  │   │    ├── entry[45]: r_offset=0x115d5e0, addend=0x400aac
  │   │    ├── entry[46]: r_offset=0x115d5e8, addend=0x400ae4
  │   │    ├── entry[47]: r_offset=0x115d5f0, addend=0x400b44
  │   │    ├── entry[48]: r_offset=0x115d5f8, addend=0x400b58
  │   │    ├── entry[49]: r_offset=0x115d600, addend=0x400ba0
  │   │    ├── entry[50]: r_offset=0x115d608, addend=0x400d24
  │   │    ├── entry[51]: r_offset=0x115d610, addend=0x400dd8
  │   │    └── entry[52]: r_offset=0x115d618, addend=0x400e44
  │   │
  │   ├─── RELA targeting .got / .data / .got.plt — all 61,660 entries
  │   │   Most are R_AARCH64_RELATIVE (type=1027)
  │   │   Computed as: *(base + r_offset) = base + r_addend
  │   │
  │   └─── NO RELA entries target the .dynamic section (0x11d9db0–0x11da030)
  │        └── DT_INIT (0x1706b3) is NOT fixed by RELA
  │
  ├── GNU_RELRO protect (range: 0x115d478 – 0x11e8000)
  │   ├── .init_array (0x115d478) → read-only
  │   ├── .fini_array (0x115dad8) → read-only
  │   ├── .dynamic (0x11d9db0) → read-only
  │   ├── .got (0x118c000) → read-only  [wait — this includes the main GOT!]
  │   └── .got.plt (0x11d6b70) → read-only
  │
  ├── [DT_INIT: 0x1706b3] — Decoy / obfuscated
  │   Location: .dynstr section, at string "...e\x00_ZN7cocos2d..."
  │   Instruction: 0x65005F5A  (unknown decode; likely harmless/quick-return)
  │   WAIT: is 0x1706b3 within .dynstr?  .dynstr at 0x10b760, size 0x1706c4
  │   So range = 0x10b760 – 0x27BE24. Yes, 0x1706b3 is inside .dynstr.
  │
  ├── [DT_INIT_ARRAY: 0x115d478] ── 53 entries, NOW POPULATED by RELA
  │   │
  │   ├── entry[0]: *0x115d478 = base + 0x3ff5a0
  │   ├── entry[1]: *0x115d480 = base + 0x3ff5cc
  │   ├── entry[2]: *0x115d488 = base + 0x3ff6f4
  │   ├── ...
  │   ├── entry[50]: *0x115d608 = base + 0x400d24
  │   ├── entry[51]: *0x115d610 = base + 0x400dd8
  │   └── entry[52]: *0x115d618 = base + 0x400e44
  │
  └── [Linker calls .init_array in order, left to right]
      └── Calling each of the 53 functions sequentially
```

### 2.2 .init_array — Static Init Functions

The 53 RELA entries populate .init_array with offsets in range 0x3ff5a0–0x400e44.
This range is within .text (0x3fc000–0xdf61ec). Functions include:

```
___cxx_global_var_init      — initializes global C++ objects
__GLOBAL__sub_I_xxx         — C++ file-level initialization
__static_initialization_and_destruction_0 — standard static init
...
```

**One of these 53 functions calls CCCrypto::setKey(hex_string).**
The specific entry is unknown statically because:
- The function bodies are small stubs that chain to other init functions
- The RELA addends are the function addresses; their names require symbol resolution

### 2.3 Moonton Protect RELA Injection — Technical Detail

```
Standard ELF loading sequence (no packer):
  1. File on disk: .init_array has correct function pointers
  2. Linker reads .init_array directly
  3. Calls each function

Moonton Protect (this binary):
  1. File on disk: .init_array is all ZEROS
  2. Linker processes RELA table → 53 R_AARCH64_RELATIVE entries
  3. Each entry WRITES the function pointer into .init_array slot
  4. Linker then reads .init_array (now populated)
  5. Calls each function normally

Why this works:
  - The RELA table is standard ELF, so the linker processes it normally
  - The R_AARCH64_RELATIVE entry's r_addend contains the "secret" function offset
  - The linker computes: *(base + r_offset) = base + r_addend
  - The r_offset points to an .init_array slot
  - This is indistinguishable from a normal GOT/data relocation

Detection avoidance:
  - Static analysis sees zeros in .init_array → might miss the RELA
  - RELA entries are mixed among 61,659 other entries
  - No custom unpacking code, no mprotect, no memcpy
  - Entirely leverages standard ELF behavior
```

### 2.4 JNI_OnLoad (Phase 3.5)

```
[JNI_OnLoad @ 0x7d3600]
  │
  ├──→[0x7e484c] Engine init function (stores JNIEnv*)
  │   │  mov w0, #3
  │   │  bl 0x3f9bc0        // log setup
  │   │  str x19, [got+0x480]  // save JNIEnv*
  │   │  b 0x3fa8e0          // another init branch
  │   └── ... returns to JNI_OnLoad
  │
  ├──→[0x7856d0] Store JNIEnv* in GOT
  │   │  ldr x1, [got+0x78]
  │   │  str x0, [x1]        // save JNIEnv* at *GOT[0x78]
  │   └── returns
  │
  └──→ return JNI_VERSION_1_4
```

**JNI_OnLoad does NOT call setKey or decryptData.**
Crypto initialization happens earlier, during .init_array processing.

---

## 3. Crypto System Initialization (The Gap)

### 3.1 Current State — Unknown Caller

```
[MISSING LINK] ←── The caller of CCCrypto::setKey exists but cannot be
                    identified statically. Likely scenarios:
  │
  ├── Scenario A: setKey called by one of the 53 .init_array functions
  │   ├── The caller is a C++ static constructor
  │   └── The function body contains BL to 0xceca74 (setKey)
  │
  ├── Scenario B: setKey called indirectly via function pointer
  │   ├── .init_array entry sets up a callback/vtable
  │   └── Engine initialization calls the callback → setKey runs
  │
  └── Scenario C: setKey called lazily (first decryptData triggers it)
      ├── decryptData checks if m_sKey is empty
      └── If empty, calls setKey itself (but setKey has 0 callers)
```

**Weight of evidence**: Scenario A is most likely — one of the 53 RELA-injected
.init_array entries calls setKey directly. The function at `base + offset` was
called by the linker during startup, but we can't follow the call statically
because the link is via RELA+linker, not via BL.

**The static analysis tool cannot see this caller because**:
- capstone searches for `BL 0xceca74` — but the .init_array doesn't have
  function bodies, only function pointers stored by RELA
- The function that calls setKey IS somewhere in .text, but the only reference
  to it is the RELA entry, and the reference to setKey inside it is via BL

### 3.2 The setKey Function (0xceca74)

```
CCCrypto::setKey(CCCrypto *this, const char *hex_key)
  ASSUMED: "this" = &m_Instance (singleton), callee-safe regs
  
  ldr x2, [x0, #offset_of_m_sKey]   // m_sKey (std::string)
  bl 0xcec900                        // hex_decode: converts hex → binary
  // hex_decode at 0xcec900:
  //   char c = *src;
  //   if (c >= '0' && c <= '9') result |= (c - '0');
  //   else if (c >= 'A' && c <= 'F') result |= (c - 'A' + 10);
  //   else if (c >= 'a' && c <= 'f') result |= (c - 'a' + 10);
  
  str x0, [got_0x11E4670]  ← THIS UPDATES THE POINTER
  // GOT[0x11E4670] now points to m_sKey which contains decoded key bytes
```

---

## 4. Data::decryptData (When Crypto Is Used)

```
[Data::decryptData @ 0xc82a24]  ← called by file system when loading .mt files
  │
  ├──→[CCCrypto::getKey @ 0xc82be8]
  │   │  ldr x0, [got_0x11E4670]   // load pointer to m_sKey
  │   │  bl 0xcec900 / hex_encode?  // or just returns the raw key bytes
  │   └── returns key material to decryptData
  │
  ├──→[Some AES/CBC decrypt function]
  │   Uses the returned key
  │
  └──→ returns decrypted data to caller (Lua/engine)
```

---

## 5. Data Flow Summary

```
┌─────────────────────────────────────────────────────────────┐
│  DISK (libagame.so)                                         │
│  .init_array = [0, 0, 0, ..., 0]   (51+2 zeros)             │
│  .rela.dyn has 61,660 entries                               │
│    └── 53 entries with r_offset in .init_array range        │
│  DT_INIT = 0x1706b3 (decoy/string data)                    │
│  JNI_OnLoad = 0x7d3600 (standard)                          │
│  m_sKey in BSS = empty                                     │
└──────────────┬──────────────────────────────────────────────┘
               │ System.loadLibrary("agame")
               ▼
┌─────────────────────────────────────────────────────────────┐
│  ANDROID LINKER64                                           │
│  ① Map segments (6 LOAD PHDR)                               │
│  ② Process RELA → fill .init_array, .got, .data            │
│  ③ GNU_RELRO → .init_array becomes read-only               │
│  ④ Execute DT_INIT (quick return? or crash?)               │
│  ⑤ Execute .init_array[0..52]                              │
│     └── One of them calls CCCrypto::setKey("a1b2c3...")    │
│  ⑥ Continue to DT_FINI                                     │
└──────────────┬──────────────────────────────────────────────┘
               │ Loading complete, JNI_OnLoad called
               ▼
┌─────────────────────────────────────────────────────────────┐
│  ENGINE (Cocos2d-x → Lua → JS?)                             │
│  ① JNI_OnLoad stores JNIEnv*                               │
│  ② Lua engine init runs .lua scripts                       │
│  ③ Scripts access assets (".mt" files)                     │
│  ④ File system calls Data::decryptData                     │
│  ⑤ decryptData calls CCCrypto::getKey                      │
│  ⑥ getKey returns m_sKey (already set in phase ② step ⑤)  │
│  ⑦ AES/CBC decrypt using m_sKey                            │
│  ⑧ Decrypted data returned to Lua                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Known Addresses Summary

| Address | Symbol | Role |
|---------|--------|------|
| 0x0000 | ELF header | ET_DYN shared library |
| 0x3fc000 | .text start | Executable code segment |
| 0x10b760 | .dynstr start | Dynamic string table |
| 0x115d478 | .init_array start | 53 zero entries → 53 RELA fixes |
| 0x115b514 | .text end | End of executable code |
| **0x11E4670** | m_sKey GOT ptr | Pointer to m_sKey std::string |
| **0x124eb50** | m_sKey object | Actual std::string (BSS) |
| 0x7d3600 | JNI_OnLoad | Entry point from Java |
| **0xceca74** | CCCrypto::setKey | Sets m_sKey from hex string |
| 0xcec900 | hex_decode helper | Parses "0-9A-Fa-f" hex chars |
| 0xc82a24 | Data::decryptData | .mt file decryption |
| 0xc82be8 | CCCrypto::getKey | Returns m_sKey contents |
| 0x1706b3 | DT_INIT (decoy) | In .dynstr, not real code |
| 0x11d9db0 | .dynamic section | DT_* entries including DT_INIT |

### libhades.so Key Addresses

| Address | Symbol | Role |
|---------|--------|------|
| 0x0000 | ELF header | ET_EXEC executable |
| 0x1db000 | GOT | Function pointer table for trampolines |
| 0x1d2000 | .init_array (real, 70 entries) | Real init functions |
| 0x1d2240 | Metadata struct | Passed to Moonton Protect dispatcher |
| 0xb04c8 | JNI_OnLoad | TGRP class registration |
| 0xb0398 | JNI_OnLoad (real body) | After JNI dispatcher resolves |
| 0x22dd0 | Dispatcher | Trampoline: adrp → ldr → br |
| 0x22f80 | String decrypt | Decrypts downloader strings |
| 0x1dc3b0 | Native methods table | TGRPDownloaderImpl (51 methods) |
| 0x1dc878 | Native methods table | TGRPServiceImpl (2 methods) |
