import struct

so = open(r'C:\Users\ADMIN SERVICE\Videos\MLA\libagame.so', 'rb').read()

# Search for strings
searches = [
    b'ValueMap', b'writeToBinary', b'readFromBinary',
    b'__Dictionary', b'__Array', b'luaValueToDict',
    b'DictToLuaValue', b'binary', b'flag', b'header',
    b'serialize', b'deserialize',
    b'type', b'bool', b'float', b'double',
    b'int32', b'int64', b'uint32', b'uint16', b'uint8',
    b'string', b'map', b'vector', b'array',
]

print('Searching for relevant strings in libagame.so:')
for s in searches:
    off = so.find(s)
    if off != -1:
        end = so.find(b'\x00', off)
        if end != -1 and end - off < 50:
            val = so[off:end].decode(errors='replace')
        else:
            val = s.decode(errors='replace')
        print('  Found "{}" at 0x{:x}'.format(val, off))
        if off > 0x1100000:  # data section - might be important
            print('    (in data section)')
