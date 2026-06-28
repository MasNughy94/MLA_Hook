import struct

WORK=r'C:\Users\NGEONG\Videos\VSCODE\mt_dump'
aes=open(WORK+r'\intermediate\01_aes_output.bin','rb').read()
P=0x400;PM=0x800;PS_C=5;RB=11;RT=0x1000000

ds=struct.unpack_from('<I',aes,0x0A)[0]^0x3EA
cd=bytearray(aes)
for i in range(min(ds,16)):cd[0x0E+i]^=0xEC
cd=bytes(cd[0x0E:])
hdr=aes[:14]
flags=bytearray(5)
flags[0]=hdr[4];flags[1]=hdr[5];flags[2]=hdr[6];flags[3]=hdr[7]^5;flags[4]=hdr[8]
e=flags[0];ws=e//9;r9=e%9
ps=(ws*0xCCCCCCCD)>>34;r5=ws-ps*5
te=(0x300<<(r5+r9))+0x736;mk=(1<<ps)-1

# First, find exact range state at symbol 5's first tree bit
tbl=[P]*te;dp=5;h=0xFFFFFFFF
cd5=cd[:5];l=(cd5[1]<<24)|(cd5[2]<<16)|(cd5[3]<<8)|cd5[4]
ctx=[cd[0],cd[1],cd[2],cd[3],cd[4]];si=ctx[0]&0xF

def rn():
    global h,l,dp
    while h<RT:
        h=(h<<8)&0xFFFFFFFF
        if dp<len(cd):l=((l<<8)|cd[dp])&0xFFFFFFFF;dp+=1
        else:l=(l<<8)&0xFFFFFFFF

def db(pr):
    global h,l;rn();m=((h>>RB)*pr)&0xFFFFFFFF
    if l<m:h=m;return 0
    else:l=(l-m)&0xFFFFFFFF;h=(h-m)&0xFFFFFFFF;return 1

bc=0;pb=0;wm=4095;w=bytearray(4096);wp=0;out=bytearray()

# Decode symbols 0-4 and track state
for sn in range(5):
    ci=(si<<4)+(bc&mk)
    b=db(tbl[ci]);tbl[ci]=((PM-tbl[ci])>>PS_C) if b==0 else -(tbl[ci]>>PS_C)  # bit=0: p+(PM-p)>>5, bit=1: p-(p>>5)
    # Actually need to compute correctly
    if b==0:
        tbl[ci]=tbl[ci]+((PM-tbl[ci])>>PS_C)
    else:
        tbl[ci]=tbl[ci]-(tbl[ci]>>PS_C)
    tbl[ci]&=0xFFFF
    
    if b==0:
        tb=0x736+(pb>>5)*256
        ii=1
        while ii<=0xFF:
            pr=tbl[tb+ii];b2=db(pr)
            tbl[tb+ii]=tbl[tb+ii]+((PM-tbl[tb+ii])>>PS_C) if b2==0 else tbl[tb+ii]-(tbl[tb+ii]>>PS_C)
            tbl[tb+ii]&=0xFFFF
            ii=(ii<<1)|b2
        v=ii&0xFF
        out.append(v);w[wp&wm]=v;wp+=1;pb=v
        ctx[0],ctx[1],ctx[2],ctx[3],ctx[4]=ctx[1],ctx[2],ctx[3],ctx[4],v
        si=ctx[0]&0xF;bc+=1
    # Skip match - no matches in first 5 symbols for Lua header

# Now at symbol 5's MF
h_before_mf = h
l_before_mf = l
ci=(si<<4)+(bc&mk)
prob_mf = tbl[ci]
print(f"Symbol 5 MF context:")
print(f"  si={si}, bc={bc}, ci={ci}")
print(f"  h=0x{h:08X}, l=0x{l:08X}")
print(f"  prob_mf=0x{prob_mf:04X}")

# Decode MF bit
rn()
m=((h>>RB)*prob_mf)&0xFFFFFFFF
print(f"  mid=0x{m:08X}")
b_mf = 0 if l < m else 1
print(f"  MF bit: {b_mf} ({'literal' if b_mf==0 else 'match'})")

if b_mf == 0:
    h = m
    # Tree decode at symbol 5
    tb=0x736+(pb>>5)*256
    print(f"\nSymbol 5 literal tree at tb=0x{tb:04X}, pb=0x{pb:02X}")
    print(f"  h after MF=0x{h:08X}, l=0x{l:08X}")
    print(f"  Tree 0x936 entries used by symbol 2 (0x75):")
    for idx in range(0x937, 0x93F):
        print(f"    tbl[0x{idx:04X}] = 0x{tbl[idx]:04X}")

# Now compute what prob would be needed for bit=0 at each tree position
print("\nAnalyzing required probabilities for symbol 5 = 0x00:")
ii = 1
h_temp, l_temp = h, l
dp_temp = dp
for bit_pos in range(8):
    h_temp_save, l_temp_save = h_temp, l_temp
    prob = tbl[tb + ii]
    # Need l_temp < (h_temp >> 11) * prob for bit=0
    # prob > (l_temp << 11) / h_temp
    if h_temp > 0:
        needed = ((l_temp << 11) // h_temp) + 1
    else:
        needed = 0x800
    # Also check: what prob value makes it barely bit=0?
    mid_0 = ((h_temp >> RB) * needed) & 0xFFFFFFFF
    print(f"  Bit {bit_pos}: i=0x{ii:03X}, cur_prob=0x{prob:04X}, h=0x{h_temp:08X}, l=0x{l_temp:08X}, needed_prob>={needed:#06x} (mid={mid_0:#010x})")
    # Decode bit=0
    rn_check = False
    while h_temp < RT:
        h_temp = (h_temp << 8) & 0xFFFFFFFF
        if dp_temp < len(cd):
            l_temp = ((l_temp << 8) | cd[dp_temp]) & 0xFFFFFFFF
            dp_temp += 1
        else:
            l_temp = (l_temp << 8) & 0xFFFFFFFF
    m = ((h_temp >> RB) * prob) & 0xFFFFFFFF
    actual = 0 if l_temp < m else 1
    if actual == 0:
        h_temp = m
    else:
        l_temp = (l_temp - m) & 0xFFFFFFFF
        h_temp = (h_temp - m) & 0xFFFFFFFF
    ii = (ii << 1) | actual
    if actual == 0:
        prob_updated = prob + ((PM - prob) >> PS_C)
    else:
        prob_updated = prob - (prob >> PS_C)
    print(f"          actual_bit={actual} (need {'OK' if actual==0 else 'WRONG'}), prob->0x{prob_updated:04X}")
