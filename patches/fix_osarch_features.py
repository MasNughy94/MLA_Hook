import re

path = "Dobby/common/os_arch_features.h"

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

print("Patched os_arch_features.h successfully")