from elftools.elf.elffile import ELFFile
with open('C:/Users/NGEONG/Videos/MLA/libagame.so', 'rb') as f:
    elf = ELFFile(f)
    symtab = elf.get_section_by_name('.dynsym')
    if symtab:
        print('Lua binding functions for FileUtils:')
        for sym in symtab.iter_symbols():
            name = sym.name
            if 'FileUtils' in name and 'lua' in name.lower():
                print(f'  0x{sym.entry.st_value:x}: {name}')
        
        print('\nFunctions with getdata or getstring:')
        for sym in symtab.iter_symbols():
            name = sym.name
            if sym.entry.st_value > 0 and sym.entry.st_size > 0:
                lower = name.lower()
                if ('getdata' in lower or 'getstring' in lower) and 'fileutils' in lower:
                    print(f'  0x{sym.entry.st_value:x}: {name}')
        
        print('\nregister functions related to FileUtils:')
        for sym in symtab.iter_symbols():
            name = sym.name
            if 'register' in name and 'FileUtils' in name:
                print(f'  0x{sym.entry.st_value:x}: {name}')

        print('\nFunctions with "getData" or "getString" (any class):')
        for sym in symtab.iter_symbols():
            name = sym.name
            if sym.entry.st_value > 0 and sym.entry.st_size > 0:
                lower = name.lower()
                if 'getdata' in lower or 'getstring' in lower:
                    # Skip mangled C++ demangled would be too long, just print short ones
                    if len(name) < 120:
                        print(f'  0x{sym.entry.st_value:x}: {name}')
