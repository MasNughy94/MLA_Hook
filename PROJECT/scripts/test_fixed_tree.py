import struct, math

WORK=r'C:\Users\ADMIN SERVICE\Videos\MLA\mt_dump'
aes=open(WORK+r'\intermediate\01_aes_output.bin','rb').read()
P=0x400;PM=0x800;PS_C=5;RB=11;RT=0x1000000
upd=lambda p,b:((p+((PM-p)>>PS_C))if b==0 else(p-(p>>PS_C)))&0xFFFF

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

tbl=[P]*te;dp=5;h=0xFFFFFFFF
cd5=cd[:5];l=(cd5[1]<<24)|(cd5[2]<<16)|(cd5[3]<<8)|cd5[4]
ctx=[cd[0],cd[1],cd[2],cd[3],cd[4]]
si=ctx[0]&0xF

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
exp=[0x1B,0x4C,0x6D,0x00,0x00,0x00,0x52,0x6F,0x6F,0x00,0x00,0x00]

for sn in range(50000):
    if len(out)>=ds:break
    ci=(si<<4)+(bc&mk)
    b=db(tbl[ci]);tbl[ci]=upd(tbl[ci],b)
    if b==0:
        # FIXED tree base - NO lit_ctx!
        tb=0x736
        ii=1
        while ii<=0xFF:
            pr=tbl[tb+ii];b2=db(pr);tbl[tb+ii]=upd(pr,b2);ii=(ii<<1)|b2
        v=ii&0xFF
        out.append(v);w[wp&wm]=v;wp+=1;pb=v
        ctx[0],ctx[1],ctx[2],ctx[3],ctx[4]=ctx[1],ctx[2],ctx[3],ctx[4],v
        si=ctx[0]&0xF;bc+=1
    else:
        si2=si+0xC0;bs=db(tbl[si2]);tbl[si2]=upd(tbl[si2],bs)
        if bs==0:
            ii=1
            while ii<=7:
                pr=tbl[0x332+ii];b2=db(pr);tbl[0x332+ii]=upd(pr,b2);ii=(ii<<1)|b2
            l2=(ii&0xFF)+3
        else:
            l2=0
            for i2 in range(5):
                pr=tbl[(si<<4)+0xCC+i2];b2=db(pr);tbl[(si<<4)+0xCC+i2]=upd(pr,b2);l2=(l2<<1)|b2
                if b2==0:break
            l2+=3
        sc=min(l2-3,3);sb=0x1B0+sc*64;sl=0
        for i2 in range(6):
            pr=tbl[sb+i2];b2=db(pr);tbl[sb+i2]=upd(pr,b2);sl=(sl<<1)|b2
            if b2==0:break
        if sl<4:d2=sl+1
        else:
            ex=(sl>>1)-1;d2=((2+(sl&1))<<ex)+1
            for i2 in range(ex):
                pr=tbl[sb+6+i2];b2=db(pr);tbl[sb+6+i2]=upd(pr,b2);d2=(d2<<1)|b2
        bc+=1
        for i2 in range(l2):
            src=wp-d2;by=w[(src+i2)&wm] if 0<=src<len(w) else 0
            out.append(by);w[wp&wm]=by;wp+=1;pb=by
            ctx[0],ctx[1],ctx[2],ctx[3],ctx[4]=ctx[1],ctx[2],ctx[3],ctx[4],by
            si=ctx[0]&0xF

freq=[0]*256
for b in out:freq[b]+=1
ent=-sum(f/sum(freq)*math.log2(f/sum(freq)) for f in freq if f>0) if sum(freq)>0 else 0
print(f'Output: {len(out)} bytes, entropy={ent:.2f}')
print(f'First 48: {out[:48].hex()}')
for i in range(min(len(out),20)):
    ok='OK' if i<len(exp) and out[i]==exp[i] else f'EXP={exp[i]:02x}' if i<len(exp) else '?'
    print(f'  [{i:2d}] 0x{out[i]:02x} {ok}')
