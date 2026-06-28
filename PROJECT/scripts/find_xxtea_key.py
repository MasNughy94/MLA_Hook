import struct

data = open(r'H:\PROJECTMOD\OriginalAPK\lib\arm64-v8a\libagame.so', 'rb').read()

# Search .rodata for potential XXTEA keys
# The key is typically a string passed to setXXTEAKeyAndSign
# Let's search for the key near the AppDelegate initialization

# .mt string is at 0xdfc1f8
# Let's find ARM64 code that references this address
# In ARM64, references to a .rodata string use ADRP+ADD sequence
# ADRP loads the page, ADD adds the offset

# The string address in runtime = 0xdfc1f8
# ADRP encoding: 1xxxxxxxxxxxxx (bit 31=1 for ADRP)
# ADRP format: 
#   immhi = bits[23:5] of instruction
#   immlo = bits[30:29] of instruction
#   Rd = bits[4:0] of instruction
#   opc = bits[31] of instruction (=1 for ADRP)
# Actually ADRP opcode is: 1 0 0 0 0 (bits 31-27) + immhi + 0 0 0 0 0 (bits 23,22,21,20) + Rd

# Let's search for ADRP instructions that reference a page near 0xdfc1f8
# The page of 0xdfc1f8 is 0xdfc000

# ADRP Format for ARM64:
# 31|30 29|28 27 26 25 24|23             5|4      0|
#  1|immlo| 0  0  0  0 0|     immhi      |   Rd   |
# imm = immhi:immlo (sign-extended, shifted by 12)
# target_page = (PC & 0xFFF) + (imm << 12)

# Let me just directly search for ADRP instructions using the raw encoding
# ADRP encoding: bit[31]=1, bits[28:24]=00000
# So instruction & 0x9F000000 == 0x90000000

# For efficiency, search for patterns near function entries that reference 0xdfc1f8
# But this is complex. Let me try a different approach.

# Let me look at the data section near 0x11e8000 for the XXTEA key storage
data_section = data[0x11e8000:0x11e8000+94000]
print("Searching .data section for potential key strings...")

# Look for pointer pairs (key_ptr, key_len, sign_ptr, sign_len)
# In the Cocos2d-x source, the static members of LuaStack look like:
# static char* xxtea_key;
# static int xxtea_key_len;
# static char* xxtea_sign;
# static int xxtea_sign_len;

# In .data, these would be stored as 8-byte pointers and 4-byte ints
# Let's look for pointers into .rodata (which is at 0xdf6200-0xef0e40)
# A pointer to .rodata would be in range 0xdf6200 to 0xef0e40

# Search for 8-byte values that could be pointers into .rodata
rodata_start = 0xdf6200
rodata_end = 0xdf6200 + 1664064

for off in range(0, len(data_section)-8, 8):
    val = struct.unpack('<Q', data_section[off:off+8])[0]
    if rodata_start <= val < rodata_end:
        # Found a potential .rodata pointer
        # Check what string it points to
        str_off = val - 0xdf6200 + rodata_start
        # Wait, val is the runtime address but in the file the offset is the same
        if 0 < str_off < len(data):
            name_end = data.find(b'\x00', str_off)
            if name_end > str_off:
                s = data[str_off:name_end]
                if 8 <= len(s) <= 64 and all(0x20 <= b <= 0x7e for b in s):
                    actual_file_off = off + 0x11e8000
                    print(f'  .data+0x{off:x} -> .rodata+0x{val - rodata_start:x}: {s.decode("latin-1")}')

print("\nDone searching .data section")
