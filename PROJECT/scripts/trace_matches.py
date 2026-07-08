import struct, os

WORK = r"C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump"
aes = open(os.path.join(WORK, "intermediate", "01_aes_output.bin"), 'rb').read()

PROB_INIT=0x400;PROB_MAX=0x800;PROB_SHIFT=5;RANGE_BITS=11;RENORM_THRESH=0x1000000

def upd(p,b):
    if b==0: p+=(PROB_MAX-p)>>PROB_SHIFT
    else: p-=p>>PROB_SHIFT
    return p&0xFFFF

def parse_hdr(d):
    f=bytearray(5);f[0],f[1],f[2]=d[4],d[5],d[6];f[3]=d[7]^5;f[4]=d[8]
    e=struct.unpack_from('<I',d,0x0A)[0];ds=e^0x3EA
    b=bytearray(d)
    for i in range(min(ds,16)):b[0x0E+i]^=0xEC
    return ds,bytes(f),bytes(b[0x0E:])

ds,flags,cd=parse_hdr(aes)

class BD:
    def __init__(s,d): s.data=d;s.pos=5;s.end=len(d);s.high=0xFFFFFFFF;s.low=0
    def init(s,seed): s.high=0xFFFFFFFF;s.low=seed&0xFFFFFFFF
    def ren(s):
        while s.high<RENORM_THRESH:
            s.high=(s.high<<8)&0xFFFFFFFF
            if s.pos<s.end: s.low=((s.low<<8)|s.data[s.pos])&0xFFFFFFFF;s.pos+=1
            else: s.low=(s.low<<8)&0xFFFFFFFF
    def db(s,p):
        s.ren();m=((s.high>>RANGE_BITS)*p)&0xFFFFFFFF
        if s.low<m: s.high=m;return 0
        else: s.low=(s.low-m)&0xFFFFFFFF;s.high=(s.high-m)&0xFFFFFFFF;return 1
    def dt(s,tbl,bi,mx):
        i=1
        while i<=mx:
            p=tbl[bi+i];b=s.db(p);tbl[bi+i]=upd(p,b);i=(i<<1)|b
        return i&0xFF

e=flags[0];ws=e//9;r9=e%9
ps=(ws*0xCCCCCCCD)>>34
f4=ws-ps*5;f0=r9
te=(0x300<<(f4+f0))+0x736
mk=(1<<ps)-1

LIT_SHIFT=3

tbl=[PROB_INIT]*te
bd=BD(cd)
s=cd[:5];seed=(s[1]<<24)|(s[2]<<16)|(s[3]<<8)|s[4]
bd.init(seed)
si=0;bc=0;pb=0;w=bytearray(4096);wm=4096-1;out=bytearray();wp=0

print("Symbol trace:")
for sn in range(25):
    ci=(si<<4)+(bc&mk)
    p=tbl[ci];b=bd.db(p);tbl[ci]=upd(p,b)
    
    if b==0:
        tb=0x736+(pb>>(8-LIT_SHIFT))*256
        v=bd.dt(tbl,tb,0xFF)
        out.append(v);w[wp&wm]=v;wp+=1
        pb=v;si=v&0xF;bc+=1
        c32=32<=v<127
        print(f"  {sn}: LITERAL byte={v:#04x} ({chr(v) if c32 else '?'}) pos={len(out)-1}")
    else:
        si2=si+0xC0
        bs=bd.db(tbl[si2]);tbl[si2]=upd(tbl[si2],bs)
        if bs==0: l=bd.dt(tbl,0x332,7)+3
        else:
            l=0
            for i in range(5):
                pp=tbl[(si<<4)+0xCC+i];bb=bd.db(pp)
                tbl[(si<<4)+0xCC+i]=upd(pp,bb);l=(l<<1)|bb
                if bb==0: break
            l+=3
        sc=min(l-3,3);sb=0x1B0+sc*64;sl=0
        for i in range(6):
            pp=tbl[sb+i];bb=bd.db(pp)
            tbl[sb+i]=upd(pp,bb);sl=(sl<<1)|bb
            if bb==0: break
        if sl<4: d=sl+1
        else:
            ex=(sl>>1)-1;d=((2+(sl&1))<<ex)+1
            for i in range(ex):
                pp=tbl[sb+6+i];bb=bd.db(pp)
                tbl[sb+6+i]=upd(pp,bb);d=(d<<1)|bb
        bc+=1
        # generate match
        match_bytes=bytearray()
        for i in range(l):
            src=wp-d
            if 0<=src<len(w): by=w[(src+i)&wm]
            else: by=0
            out.append(by);w[wp&wm]=by;wp+=1
            pb=by
            match_bytes.append(by)
        print(f"  {sn}: MATCH len={l} dist={d} -> {match_bytes.hex()} (pos {len(out)-l}-{len(out)-1})")

exp=bytes([0x1B,0x4C,0x75,0x61,0x53,0x00,0x01,0x04,0x08,0x04,0x08,0x00,0x19,0x93,0x0D,0x0A])
print(f"\nOut: {out[:32].hex()}")
print(f"Exp: {exp[:16].hex()}{' '*(32-16)}")
print(f"Match: {sum(1 for a,b in zip(out[:16],exp) if a==b)}/16")
