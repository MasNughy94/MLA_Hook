import re, os

base = "Dobby"

# Patch 1: os_arch_features.h - OSMemory circular include
path = os.path.join(base, "common", "os_arch_features.h")
with open(path, "r") as f:
    content = f.read()

content = re.sub(
    r'auto page = \(void \*\)ALIGN_FLOOR\(address, OSMemory::PageSize\(\)\);',
    'long page_size = sysconf(_SC_PAGESIZE);void *page = (void *)((uintptr_t)address & ~(page_size - 1));',
    content
)
content = content.replace(
    'if (!OSMemory::SetPermission(page, OSMemory::PageSize(), kReadExecute)) {',
    'mprotect(page, page_size, PROT_READ | PROT_EXEC);'
)
content = re.sub(r'^    return;\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^  }\n#endif', '#endif', content, flags=re.MULTILINE)
content = '#include <unistd.h>\n#include <sys/mman.h>\n' + content

with open(path, "w") as f:
    f.write(content)

print("1. Patched os_arch_features.h")

# Patch 2: closure_bridge_arm64.asm - use GOT relocation for weak inline symbol
path = os.path.join(base, "source", "TrampolineBridge", "ClosureTrampolineBridge", "arm64", "closure_bridge_arm64.asm")
with open(path, "r") as f:
    content = f.read()

old = 'adrp x17, cdecl(common_closure_bridge_handler)\nadd  x17, x17, :lo12:cdecl(common_closure_bridge_handler)'
new = 'adrp x17, :got:cdecl(common_closure_bridge_handler)\nldr x17, [x17, :got_lo12:cdecl(common_closure_bridge_handler)]'

if old in content:
    content = content.replace(old, new)
    print("2. Patched closure_bridge_arm64.asm (GOT-based relocation)")
else:
    print("2. Pattern NOT found in closure_bridge_arm64.asm - checking whitespace...")
    # Try with different whitespace
    for pattern_fix, repl_fix in [
        ('adrp x17, cdecl(common_closure_bridge_handler)\nadd\tx17, x17, :lo12:cdecl(common_closure_bridge_handler)', 
         'adrp x17, :got:cdecl(common_closure_bridge_handler)\nldr x17, [x17, :got_lo12:cdecl(common_closure_bridge_handler)]'),
        ('adrp x17, cdecl(common_closure_bridge_handler)\nadd x17, x17, :lo12:cdecl(common_closure_bridge_handler)', 
         'adrp x17, :got:cdecl(common_closure_bridge_handler)\nldr x17, [x17, :got_lo12:cdecl(common_closure_bridge_handler)]'),
    ]:
        if pattern_fix in content:
            content = content.replace(pattern_fix, repl_fix)
            print(f"2. Patched with alt whitespace")
            break
    else:
        # Show the surrounding lines for debugging
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'common_closure_bridge_handler' in line and 'adrp' in line:
                print(f"   Line {i+1}: {repr(line)}")
                print(f"   Line {i+2}: {repr(lines[i+1]) if i+1 < len(lines) else 'EOF'}")

with open(path, "w") as f:
    f.write(content)