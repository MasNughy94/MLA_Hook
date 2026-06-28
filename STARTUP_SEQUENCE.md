# Startup Sequence Analysis — Mobile Legends Adventure

## Executive Summary

Moonton Protect uses a **RELA-injection packing technique** for libagame.so. The `.init_array`
is stored as all-zeros in the binary file and filled at load time via 53 `R_AARCH64_RELATIVE`
entries in `.rela.dyn`. This subverts static analysis — you cannot find callers of
`CCCrypto::setKey` by searching for BL instructions because the call chain flows through
linker-level RELA resolution and indirect function pointers.

---

## The Packing Technique

### Standard ELF vs. Moonton Protect

| Aspect | Normal ELF | Moonton-Packed (this binary) |
|--------|-----------|------------------------------|
| .init_array on disk | Has real function pointers | ALL ZEROS |
| .init_array at runtime | Read directly from segment | Populated by RELA relocations |
| Static analysis of .init_array | Can read function addresses | Zeroes — looks empty |
| RELA table | Standard GOT/data entries | Includes .init_array entries |
| DT_INIT | Real init function | Points to string data (decoy) |
| DT_BIND_NOW | Optional | SET — forces immediate resolution |

### Why It Works

The Moonton Protect packer modifies the linker's view of the binary by:
1. **Zeroing .init_array** — hides the real init function pointers from static dumpers
2. **Adding RELA entries** for each .init_array slot — the linker's own relocation mechanism
   writes the correct function pointers at load time
3. **Setting DT_BIND_NOW** — ensures all RELA entries are processed (including the
   .init_array ones) before any code runs
4. **GNU_RELRO** — after RELA processing, the .init_array is made read-only, preventing
   further tampering

The result: at runtime, everything works correctly. At static analysis time, the
.init_array appears empty, and searches for function callers yield zero results.

---

## Detailed Startup Sequence

### Step 1: System.loadLibrary("agame")

```
Android Java runtime calls System.loadLibrary("agame")
  → Android linker64 is invoked
  → Opens libagame.so from APK/lib/arm64-v8a/
  → Maps it into process memory
```

### Step 2: Segment Mapping

```
6 LOAD segments mapped:

LOAD[0] (RX):  0x00000000 – 0x115b514  (.text, .rodata, .dynstr, .dynsym)
LOAD[1] (RW):  0x115c000 – 0x118c000  (.init_array, .fini_array, .dynamic)
LOAD[2] (RW):  0x118c000 – 0x11d4000  (.got, .data, .rela.plt)
LOAD[3] (RW):  0x11d4000 – 0x11e7000  (.data.rel.ro, .got.plt)
LOAD[4] (RW):  0x11e7000 – 0x11e8000  (small data section)
LOAD[5] (RW):  0x11e8000 – 0x124f000  (BSS — zero-initialized)

Key addresses at this point:
  - .init_array at 0x115d478: all zeros (0x660 bytes = 51 entries)
  - m_sKey pointer at 0x11E4670: points to 0x124eb50 (BSS, empty string)
  - m_sKey string at 0x124eb50: empty (BSS is zeroed)
```

### Step 3: RELA Processing (The "Unpacking")

```
Linker iterates 61,660 RELA entries.
For each R_AARCH64_RELATIVE (type 1027):
  *(base + r_offset) = base + r_addend

53 of these entries target .init_array (0x115d478 – 0x115dad8):
  Entry  0: r_offset=0x115d478, addend=0x3ff5a0 → [0x115d478] = base+0x3ff5a0
  Entry  1: r_offset=0x115d480, addend=0x3ff5cc → [0x115d480] = base+0x3ff5cc
  Entry  2: r_offset=0x115d488, addend=0x3ff6f4 → [0x115d488] = base+0x3ff6f4
  ...
  Entry 52: r_offset=0x115d618, addend=0x400e44 → [0x115d618] = base+0x400e44

Other entries target .got, .data, .got.plt — standard relocations.
```

### Step 4: RELRO Protection

```
After all RELA entries are processed:
  mprotect(0x115d478, 0x8ab88, PROT_READ)
  // Range: 0x115d478 – 0x11e8000
  // .init_array, .fini_array, .dynamic, .got, .got.plt → READ ONLY
```

### Step 5: DT_INIT Execution (Decoy)

```
Linker sees DT_INIT = 0x1706b3 (non-zero, so attempts to call it)
  → Jumps to base + 0x1706b3
  → This address is in .dynstr (string table)
  → Instruction at this address: 0x65005F5A
  → Unknown behavior (see note below)
```

**Note**: If this instruction crashes, then libagame.so must be loaded through a custom loader
(not the standard one). If it returns silently, then the linker continues normally to
.init_array.

**Alternative theory**: The GOT entry for DT_INIT might be replaced via RELA. However, we
confirmed NO RELA entries target the .dynamic section (0x11d9db0 – 0x11da030), so the
value at 0x1706b3 is not fixed by RELA.

### Step 6: .init_array Execution

```
Linker calls 53 init functions in order [0..52]:

init[0]  = base + 0x3ff5a0
init[1]  = base + 0x3ff5cc
init[2]  = base + 0x3ff6f4
init[3]  = base + 0x3ff744
init[4]  = base + 0x3ff7ac
init[5]  = base + 0x3ff878
...
init[51] = base + 0x400dd8
init[52] = base + 0x400e44
```

These functions are C++ static constructors, including:
- `__cxx_global_var_init` — initializes global C++ objects
- File-level initialization functions (`__GLOBAL__sub_I_xxx`)
- Static initialization of singleton instances

**One of these 53 calls CCCrypto::setKey(hex_key_string).**

The exact entry cannot be identified statically because the .init_array-to-function
mapping is done by the linker, not by BL instructions in the source.

### Step 7: JNI_OnLoad

```
After linker init completes, Java calls JNI_OnLoad (0x7d3600):

JNI_OnLoad(env):
  1. bl 0x7e484c               // Engine init
     - stores JNIEnv* globally
     - calls 0x3f9bc0 (log setup)
     - branches to 0x3fa8e0 (further init)
  2. bl 0x7856d0               // Quick env save
     - ldr x1, [got+0x78]
     - str x0, [x1]             // saves env ptr
  3. return JNI_VERSION_1_4
```

**JNI_OnLoad does not call setKey.** By this point, m_sKey is already initialized
(during Step 6).

### Step 8: Normal Execution (Lua Engine → MT Files)

```
1. Cocos2d-x engine initializes (on JNI callbacks)
2. Lua engine runs Lua scripts
3. Scripts try to load compressed assets (.mt files)
4. File system calls Data::decryptData(buffer, size)
5. decryptData calls CCCrypto::getKey()
   → loads m_sKey from 0x124eb50 (string)
   → returns the key bytes
6. AES/CBC decryption with the key
7. Decrypted asset returned to Lua
```

---

## Why setKey Has Zero Static Callers

The standard approach to find callers of a function:
```
capstone_disasm → search for BL 0xceca74
```

This fails because:

1. **The caller is not reached by BL from anywhere in .text** — the caller function is
   stored in .init_array and called by the linker at runtime through a function pointer.
   The linker doesn't use BL; it uses `BLR` (branch with link register, indirect) or
   equivalent with the address loaded from the array.

2. **The address of the caller function is an addend in RELA** — the only reference to
   the caller function is `r_addend = 0x3ff...` in a RELA entry. This is not a
   code-level reference that capstone can follow.

3. **Within the caller body, the BL to setKey is a normal direct call** — but since we
   don't know which of the 53 functions it is, we can't find it without scanning all
   53 function bodies.

### To Find The Caller

```python
# For each RELA addend in the .init_array range:
for addend in [0x3ff5a0, 0x3ff5cc, ..., 0x400e44]:
    # Disassemble function at base + addend
    # Search for BL 0xceca74
    # Also search for ADRP targeting page 0x11E4000
```

This was attempted and the result is **still zero** — suggesting either:
- The caller uses a more indirect mechanism (function pointer, vtable, etc.)
- Or the m_sKey is written directly (not through setKey) by one of the init functions
- Or the init function that calls setKey is reached through an intermediate dispatch

---

## Open Questions

1. **Does DT_INIT (0x1706b3) crash or return?** — Testing on actual device needed.
   If it crashes, libagame.so must be loaded through a custom loader (Hades_dlopen or similar).

2. **What is the actual key value?** — Can only be captured at runtime by breaking
   on setKey/decryptData.

3. **Which .init_array entry calls setKey?** — Requires runtime Frida hook on
   .init_array execution or deeper static analysis (trace 53 functions).

4. **Does libhades.so play a role in decrypting libagame.so?** — Currently appears
   independent, but Hades_dlopen might be the loading mechanism.

---

## Appendix: Key RELA Entries for .init_array

```
Offset (hex)  Addend (hex)  Virtual Function (base=0)
────────────  ────────────  ─────────────────────────
0x115d478     0x3ff5a0      init_func_0
0x115d480     0x3ff5cc      init_func_1
0x115d488     0x3ff6f4      init_func_2
0x115d490     0x3ff744      init_func_3
0x115d498     0x3ff7ac      init_func_4
0x115d4a0     0x3ff878      init_func_5
0x115d4a8     0x3ff8a0      init_func_6
0x115d4b0     0x3ff98c      init_func_7
0x115d4b8     0x3ffa2c      init_func_8
0x115d4c0     0x3ffb14      init_func_9
0x115d4c8     0x3ffb38      init_func_10
0x115d4d0     0x3ffb70      init_func_11
0x115d4d8     0x3ffbdc      init_func_12
0x115d4e0     0x3ffc28      init_func_13
0x115d4e8     0x3ffc60      init_func_14
0x115d4f0     0x3ffcc0      init_func_15
0x115d4f8     0x3ffd84      init_func_16
0x115d500     0x3ffda0      init_func_17
0x115d508     0x3ffe10      init_func_18
0x115d510     0x3ffe88      init_func_19
0x115d518     0x3ffea0      init_func_20
0x115d520     0x3ffefc      init_func_21
0x115d528     0x3fff68      init_func_22
0x115d530     0x3fffa4      init_func_23
0x115d538     0x400010      init_func_24
0x115d540     0x400074      init_func_25
0x115d548     0x4000ac      init_func_26
0x115d550     0x4000d0      init_func_27
0x115d558     0x400114      init_func_28
0x115d560     0x400140      init_func_29
0x115d568     0x4002b8      init_func_30
0x115d570     0x4002e8      init_func_31
0x115d578     0x400328      init_func_32
0x115d580     0x400360      init_func_33
0x115d588     0x400424      init_func_34
0x115d590     0x400624      init_func_35
0x115d598     0x400638      init_func_36
0x115d5a0     0x400898      init_func_37
0x115d5a8     0x4008f0      init_func_38
0x115d5b0     0x400938      init_func_39
0x115d5b8     0x400964      init_func_40
0x115d5c0     0x400988      init_func_41
0x115d5c8     0x400a24      init_func_42
0x115d5d0     0x400a48      init_func_43
0x115d5d8     0x400a80      init_func_44
0x115d5e0     0x400aac      init_func_45
0x115d5e8     0x400ae4      init_func_46
0x115d5f0     0x400b44      init_func_47
0x115d5f8     0x400b58      init_func_48
0x115d600     0x400ba0      init_func_49
0x115d608     0x400d24      init_func_50
0x115d610     0x400dd8      init_func_51
0x115d618     0x400e44      init_func_52
```
