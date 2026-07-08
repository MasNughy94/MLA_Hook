# Startup Timeline — Mobile Legends Adventure

## Overview

This document traces the execution timeline from process start to first `Data::decryptData()` call,
with focus on when and how `CCCrypto::m_sKey` is initialized.

---

## Phase 0: Process Start (Android App Launch)

```
[Zygote] → fork() → [App Process]
```
- Android app process created by Zygote
- Dalvik/ART VM initialized
- Application class loaded and `onCreate()` called

---

## Phase 1: Java Native Library Loading

| Step | Action | Library | Details |
|------|--------|---------|---------|
| 1.1 | `System.loadLibrary("hades")` | libhades.so | Loaded first (ByteDance TGRP) |
| 1.2 | `System.loadLibrary("agame")` | libagame.so | Main game engine (packed) |
| 1.3 | Other libraries loaded | Various | crashlytics, Bugly, datastore |

### Timing Note
libhades.so is likely loaded before libagame.so via explicit Java code
(e.g., `System.loadLibrary("hades"); System.loadLibrary("agame");`)
OR via a custom `Hades_dlopen()` that decrypts libagame.so before loading.

---

## Phase 2: libhades.so Initialization (ByteDance TGRP)

### 2.1 Dynamic Linker — Standard Processing
```
[Android linker64] maps libhades.so segments
├── LOAD[0]: 0x00000000 – 0x001cca60 (RX, text)
├── LOAD[1]: 0x001d2000 – 0x001f4cb0 (RW, data+BSS)
├── Apply RELA relocations
├── RELRO remap (0x1d2000-0x1ec000 → R)
└── Execute DT_INIT_ARRAY (2 entries per obfuscated dynamic section)
```

### 2.2 Obfuscated DT_INIT_ARRAY (what linker actually runs)

| Entry | Vaddr | Function | Purpose |
|-------|-------|----------|---------|
| [0] | 0x3c28c | `b #0x3c288` / `cbz x0, ...` | Trampoline placeholder |
| [1] | 0x3c27c | `adrp x0, #0x1d2000; add x0, #0x240; b #0x22dd0` | MOUNTON PROTECT INIT — passes metadata (0x1d2240) to dispatcher |

**Key finding**: The REAL .init_array has 70 entries (0x1d2000, size 0x230), but the obfuscated
dynamic section only exposes 2 entries from the wrong address (0x1d2230 = .fini_array).
The 70 real init functions are called by the Moonton Protect init handler.

### 2.3 Dispatcher Function at 0x22dd0

```
0x22dd0: GOT-based trampoline dispatch
         └── ADRP x16, #0x1db000; LDR x17, [x16, #offset]; BR x17
```

This is a **trampoline table** that loads function pointers from the GOT and jumps through them.
All 70 .init_array entries and the entry point decryption go through this table.
The GOT entries are resolved at load time via standard RELA processing.

### 2.4 Entry Point Decryption (init_array[0] = 0x22f80)

```
0x22f80: Repeatedly calls 0x3c2b8 with pairs:
         src: .rodata (0x16f000+) — encrypted data
         dst: .data (0x1dc000+) — decrypted output
         Strings decrypted: "download_common", "download_failed", etc.
```

This is the **ByteDance TGRP downloader string table** being decrypted. It sets up
download/update functionality used for hot-patching and asset downloading.

### 2.5 JNI_OnLoad (entry at 0xb04c8, real body at 0xb0398)

```
JNI_OnLoad(env):
├── 0xb03bc: bl 0xa5ee8       // check/module_init
├── 0xb03c8: bl 0xa5f00       // env setup
├── 0xb03d4: bl 0xa5d44       // version/platform check
├── 0xb03e4: FindClass("com/bytedance/hades/tgrp/impl/TGRPDownloaderImpl")
│              at string 0x178000+0xd5c
├── 0xb0400: FindClass("com/bytedance/hades/tgrp/impl/TGRPServiceImpl")
│              at string 0x178000+0xd8d
├── 0xb0430: RegisterNatives(class1, table@0x1dc3b0, 0x33=51 methods)
│              Methods include nativeGetTGRPDownloader, nativeInit, etc.
├── 0xb0450: RegisterNatives(class2, table@0x1dc878, 2 methods)
│              Methods include nativeSetLogLevel, nativeInitTGRPService
└── 0xb048c: return JNI_VERSION_1_4 (0x10004)
```

**libhades.so does NOT load or initialize libagame.so.**
It only registers its own TGRP downloader/service classes.

### 2.6 libhades.so Key Symbols

| Symbol | Address | Type | Purpose |
|--------|---------|------|---------|
| `JNI_OnLoad` | 0xb04c8 | FUNC | Standard JNI entry point |
| `Hades_dlopen` | 0x7aff0 | FUNC | Custom dlopen wrapper (→0x22b10 trampoline) |
| `Hades_dlsym` | 0x7aff4 | FUNC | Custom dlsym wrapper (→0x22990 trampoline) |

---

## Phase 3: libagame.so Initialization (Packed)

### 3.1 File-Level Observations

| Artifact | Observed Value | What It Means |
|----------|---------------|---------------|
| `.init_array` (51 entries at 0x115d478) | ALL ZEROS | Filled at runtime via RELA |
| `DT_INIT` (value 0x1706b3) | Points into .dynstr (string table) | Decoy — never executed directly |
| `DT_INIT_ARRAY` (0x115d478, size 0x660) | Correct VA for .init_array | Linker will run these after RELA |
| `DT_INIT_ARRAYSZ` (0x660) | Matches .init_array section | 51 entries at 8 bytes each |
| `DT_RELACOUNT` (0xf0dc = 61,660 entries) | Massive RELA table | Most entries are R_AARCH64_RELATIVE |
| `JNI_OnLoad` at 0x7d3600 | Legitimate function | Returns JNI_VERSION_1_4 |

### 3.2 RELA-Based Unpacking Mechanism (**KEY INSIGHT**)

```
At load time, the Android linker:
1. Maps LOAD segments
2. Processes RELA entries (61,660 total)
3. Among them, 53 entries target the .init_array range (0x115d478-0x115dad8)
4. Each RELA entry writes: *(base + r_offset) = base + r_addend
5. This fills the .init_array with actual function pointers
6. GNU_RELRO remaps the range as read-only
7. Linker calls DT_INIT (decoy — harmless instruction or quick return)
8. Linker calls .init_array functions (now populated with real addresses)
```

**Evidence**:
- RELA entry[0]: r_offset=0x115d478, addend=0x3ff5a0 → function at base+0x3ff5a0
- RELA entry[1]: r_offset=0x115d480, addend=0x3ff5cc → function at base+0x3ff5cc
- ...53 entries total, covering the entire .init_array

### 3.3 DT_INIT Decoy Analysis

```
DT_INIT = 0x1706b3 (in .dynstr, mid-string: "...e\x00_ZN7cocos2d...")
Instruction at 0x1706b3: 0x65005F5A
```
The first 4 bytes decode to a non-standard AARCH64 instruction. This is either:
- A harmless instruction that executes and falls through
- A `ret` equivalent that immediately returns
- Or it assumes the linker will not reach this point (if a prior RELA fixes it)

**Currently unknown**: whether this instruction causes a crash or returns silently.
Testing on real hardware is needed.

### 3.4 .init_array Functions (RELA-populated)

The 53 init functions (RELA addends) at runtime:
```
base + 0x3ff5a0, base + 0x3ff5cc, ..., base + 0x4003f8
```

These point into the .text segment (0x3fc000 – 0xdf61ec). Their exact purposes require
runtime analysis, but likely include:
- C++ static constructors (initializing global objects)
- Engine subsystem initialization
- **CCCrypto::setKey() initialization**
- Asset system initialization

### 3.5 JNI_OnLoad (0x7d3600)

```
JNI_OnLoad(env):
├── bl 0x7e484c       // Init function 1: stores JNIEnv*, engine setup
│   ├── bl 0x3fa670     // Platform/utility init
│   ├── mov w0, #3; bl 0x3f9bc0  // Logging setup (log level 3)
│   └── str x19, [got+0x480]     // Store JNIEnv* globally
│   └── b 0x3fa8e0     // Branch to another init
└── bl 0x7856d0       // Init function 2: stores JNIEnv* at got+0x78
    └── ldr x1, [got+0x78]; str x0, [x1]; ret  // Quick env pointer save
└── return JNI_VERSION_1_4
```

---

## Phase 4: Engine Initialization

### 4.1 Cocos2d-x Engine Setup

From the .init_array functions and JNI_OnLoad chain:
- Cocos2d-x renderer initialization
- Lua engine setup
- File system initialization
- OpenGL ES context creation (via `nativeOnSurfaceCreated` JNI callbacks)

### 4.2 Asset System Initialization

The `Data::decryptData` function (which calls `CCCrypto::getKey` at 0xc82be8)
is part of the .mt file decryption pipeline. It requires:
1. Asset system to be initialized
2. File system to be ready
3. `CCCrypto::m_sKey` to be set (via `CCCrypto::setKey`)

### 4.3 When CCCrypto::setKey is Called

**Key finding: setKey (0xceca74) has ZERO direct callers statically.**

The call chain is broken by the Moonton Protect packer. The most likely scenario:

```
[Process RELA → fills .init_array]
    ↓
[Linker calls .init_array[0..52] − one of these is:]
    ↓
[__cxx_global_var_init or similar static constructor]
    ↓
[Some static initializer calls CCCrypto::setKey(hex_string)]
```

The `hex_string` parameter is the native .mt decryption key, compiled into the binary
but encoded/encrypted in the packed text. During the init function chain, it gets
decoded via the hex decoder at 0xcec900 and stored in `m_sKey`.

---

## Phase 5: First Data::decryptData Call

```
[Game finishes loading]
    ↓
[Lua scripts execute]
    ↓
[Lua requires .mt asset → FileSystem::readFile(".mt_file")]
    ↓
[Data::decryptData(buffer, size)]
    ↓
[CCCrypto::getKey() → returns m_sKey]
    ↓
[AES/CBC decryption with m_sKey]
    ↓
[Decrypted asset returned to Lua/Engine]
```

---

## Critical Path Summary

```
Phase     What Happens                          Who Does It
─────     ─────────────────────────────         ──────────────────
0         Process start                         Zygote/ART
1.1       System.loadLibrary("hades")           Java VM
1.2       System.loadLibrary("agame")           Java VM
2.1-2.4   libhades.so init (TGRP downloader)    Android linker + hades init funcs
2.5       libhades.so JNI_OnLoad                ART (Java native call)
3.1-3.4   libagame.so init (RELA unpacks        Android linker
          .init_array, DT_INIT decoy)
3.5       libagame.so JNI_OnLoad                ART (Java native call)
4         Engine/Cocos2d-x/Lua init             .init_array + JNI callbacks
4.3       CCCrypto::setKey("hexkey")            Static constructor from .init_array
5         Data::decryptData (.mt files)         Engine code triggered by Lua
```

### Key Unknowns
1. **Exact setKey caller**: Which .init_array entry calls setKey? Requires runtime hook.
2. **DT_INIT behavior**: Does 0x1706b3 crash or return silently? Test on device.
3. **Hades_dlopen usage**: Is libagame.so loaded via System.loadLibrary or Hades_dlopen?
4. **Key value**: The hex string passed to setKey can only be captured at runtime.
