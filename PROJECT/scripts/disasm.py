import struct
import os

# Check for capstone and pyelftools
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    print("capstone OK")
except ImportError:
    print("ERROR: capstone not installed")
    exit(1)

try:
    from elftools.elf.elffile import ELFFile
    print("pyelftools OK")
except ImportError:
    print("ERROR: pyelftools not installed. Install with: pip install pyelftools")
    exit(1)

filepath = r"C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so"

# Read ELF and find virtual address -> file offset mapping
with open(filepath, 'rb') as f:
    elffile = ELFFile(f)

    # Find the segment that contains our virtual addresses
    # Target virtual addresses
    targets = {
        0xcecd24: 0x400,  # CCCrypto::uncompressData
        0xcf292c: 0x200,  # decompress_init
        0xcf2100: 0x200,  # decompress_setup
        0xcf2110: 0x800,  # decompress_run
        0xcf2810: 0x200,  # decompress_cleanup
        0xcf2b2c: 0x200,  # main decompressor
    }

    for segment in elffile.iter_segments():
        if segment.header.p_type == 'PT_LOAD':
            vaddr = segment.header.p_vaddr
            filesz = segment.header.p_filesz
            offset = segment.header.p_offset
            memsz = segment.header.p_memsz
            print(f"LOAD segment: vaddr=0x{vaddr:x}, filesz=0x{filesz:x}, offset=0x{offset:x}, memsz=0x{memsz:x}")

    def va_to_offset(va):
        for segment in elffile.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                vaddr = segment.header.p_vaddr
                filesz = segment.header.p_filesz
                offset = segment.header.p_offset
                if vaddr <= va < vaddr + filesz:
                    return offset + (va - vaddr)
        return None

    # Now disassemble each function
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    for va, size in targets.items():
        file_off = va_to_offset(va)
        if file_off is None:
            print(f"\n{'='*80}")
            print(f"Function at VA 0x{va:x} (size 0x{size:x}):")
            print(f"  ERROR: Cannot map VA 0x{va:x} to file offset (not in any LOAD segment)")
            continue

        print(f"\n{'='*80}")
        # Try to determine function name
        fname = {
            0xcecd24: "CCCrypto::uncompressData",
            0xcf292c: "decompress_init",
            0xcf2100: "decompress_setup",
            0xcf2110: "decompress_run",
            0xcf2810: "decompress_cleanup",
            0xcf2b2c: "main_decompressor",
        }.get(va, f"unknown_0x{va:x}")

        print(f"Function: {fname}")
        print(f"Virtual Address: 0x{va:x}")
        print(f"File Offset: 0x{file_off:x}")
        print(f"Size: 0x{size:x}")
        print(f"{'='*80}")

        # Read the bytes
        f.seek(file_off)
        code = f.read(size)

        # Disassemble
        count = 0
        for insn in md.disasm(code, va):
            # Show bytes as hex
            bytes_hex = ' '.join(f'{b:02x}' for b in insn.bytes)
            print(f"0x{insn.address:x}:\t{bytes_hex:24s}\t{insn.mnemonic}\t{insn.op_str}")
            count += 1

        print(f"\n[Total instructions: {count}]")

print("\n\nDONE")
