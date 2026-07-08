#!/usr/bin/env python3
"""
Batch decompile all .mt files preserving folder hierarchy.
Pipeline: .mt -> AES-128-CBC decrypt -> lmF@ decompress -> Roo parse -> text
"""
import struct, os, sys, time, json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mt_decoder import decrypt_aes, parse_lmf_header, decompress_lmf, LMF_MAGIC

SRC = r"C:\Users\ADMIN SERVICE\Videos\MLA\assets"
DST = r"C:\Users\ADMIN SERVICE\Videos\MLA\DEC-ASSET"
LOG_FILE = os.path.join(DST, "_decompile_log.txt")

HDR_SIZE = 69

def roo_to_readable(data: bytes) -> str:
    """Parse Roo binary into a human-readable text representation."""
    if len(data) < HDR_SIZE:
        return f"[INVALID: only {len(data)} bytes, need {HDR_SIZE} for header]\n"
    
    header = data[:HDR_SIZE]
    body = data[HDR_SIZE:]
    
    lines = []
    lines.append("=" * 70)
    lines.append("ROO BINARY FORMAT â€” DECOMPILED OUTPUT")
    lines.append("=" * 70)
    lines.append("")
    
    # Header info
    magic = header[0:4]
    roo_id = header[6:10] if len(header) > 9 else b''
    fmt_byte = header[68] if len(header) > 68 else 0
    lines.append(f"Header Magic:  {magic.hex()} ({magic})")
    lines.append(f"Roo ID:        {roo_id}")
    lines.append(f"Format Byte:   0x{fmt_byte:02x}")
    lines.append(f"Body Size:     {len(body)} bytes ({len(body)//3} raw triples)")
    lines.append("")
    
    # Parse records
    records = []
    for i in range(0, len(body) - 2, 3):
        tag, v1, v2 = body[i], body[i+1], body[i+2]
        if tag != 0:
            val = v1 | (v2 << 8)
            tc = chr(tag) if 32 <= tag < 127 else '.'
            tag_hex = f"0x{tag:02x}"
            records.append({'offset': i, 'tag': tag, 'val': val, 'tag_hex': tag_hex, 'tag_char': tc})
    
    lines.append(f"Non-zero records: {len(records)}")
    lines.append(f"Zero/null records: {len(body)//3 - len(records)} (filtered out)")
    lines.append("")
    
    if not records:
        lines.append("[NO NON-ZERO RECORDS FOUND]")
        lines.append("")
        return '\n'.join(lines)
    
    # Cluster into entries (gap = 30 bytes)
    entries = []
    if records:
        gap = 30
        cur = [records[0]]
        for r in records[1:]:
            if r['offset'] - cur[-1]['offset'] > gap:
                entries.append(cur)
                cur = [r]
            else:
                cur.append(r)
        if cur:
            entries.append(cur)
    
    lines.append(f"Total entries clustered: {len(entries)}")
    lines.append("")
    
    # Dump each entry
    for eidx, entry in enumerate(entries):
        sig = tuple(sorted(set(r['tag'] for r in entry)))
        sig_hex = ' '.join(f"0x{t:02x}" for t in sig)
        
        lines.append(f"--- Entry {eidx:5d} ({len(entry):3d} fields, signature: {sig_hex}) ---")
        
        for r in entry:
            # Determine value type hint
            hint = ''
            if r['val'] == 0:
                hint = ' (zero)'
            elif 1 <= r['val'] <= 5:
                hint = ' (enum:1-5)'
            elif 1 <= r['val'] <= 8:
                hint = ' (star:1-8)'
            elif 1000 <= r['val'] <= 9999:
                hint = ' (id:4-digit)'
            elif 50000 <= r['val']:
                hint = ' (ref:large)'
            
            lines.append(f"    [{r['tag_hex']}] ({r['tag_char']}) = {r['val']:5d}{hint}")
        
        lines.append("")
    
    # Tag frequency summary
    from collections import Counter
    tag_counts = Counter(r['tag'] for r in records)
    lines.append("--- TAG FREQUENCY SUMMARY ---")
    for tag, count in tag_counts.most_common(20):
        tc = chr(tag) if 32 <= tag < 127 else '.'
        lines.append(f"  0x{tag:02x} ({tc}): {count:5d} occurrences")
    lines.append("")
    
    return '\n'.join(lines)


def decompile_one(mt_path: str) -> tuple:
    """Decompile a single .mt file. Returns (decompressed, text_output, error)."""
    try:
        with open(mt_path, 'rb') as f:
            mt_data = f.read()
    except Exception as e:
        return None, None, f"Read error: {e}"
    
    # Check magic
    if len(mt_data) < 16:
        return None, None, f"Too small: {len(mt_data)} bytes"
    
    magic = struct.unpack_from('<I', mt_data, 0)[0]
    if magic != 0x6d746e41:
        return None, None, f"Bad magic: expected Antm got {mt_data[:4]}"
    
    # Stage 1: AES-128-CBC decrypt
    ct = mt_data[0x10:]
    ct_len = (len(ct) // 16) * 16
    if ct_len < 16:
        return None, None, f"Ciphertext too short: {len(ct)} bytes"
    ct = ct[:ct_len]
    
    try:
        decrypted = decrypt_aes(ct)
    except Exception as e:
        return None, None, f"AES decrypt error: {e}"
    
    # Check lmF@ magic
    if decrypted[:4] != LMF_MAGIC:
        return None, None, f"Bad lmF@ after decrypt: {decrypted[:4]}"
    
    # Stage 2: lmF@ decompress
    try:
        decomp_size, flags, comp_data = parse_lmf_header(decrypted)
    except Exception as e:
        return None, None, f"lmF@ header parse error: {e}"
    
    try:
        result = decompress_lmf(comp_data, decomp_size, flags)
    except Exception as e:
        return None, None, f"Decompression error: {e}"
    
    if result is None:
        return None, None, "Decompression returned None"
    
    # Stage 3: Roo to readable text
    try:
        text = roo_to_readable(result)
    except Exception as e:
        text = f"[PARSE ERROR: {e}]\nRaw hex dump available in .dec file"
    
    return result, text, None


def main():
    os.makedirs(DST, exist_ok=True)
    
    # Collect all .mt files recursively
    mt_files = []
    for root, dirs, files in os.walk(SRC):
        for f in files:
            if f.endswith('.mt'):
                rel_dir = os.path.relpath(root, SRC)
                mt_files.append((os.path.join(root, f), rel_dir, f))
    
    total = len(mt_files)
    print(f"Found {total} .mt files under {SRC}")
    print(f"Output: {DST}")
    print("=" * 60)
    
    log_entries = []
    log_entries.append(f"DECOMPILATION LOG â€” {datetime.now().isoformat()}")
    log_entries.append(f"Source: {SRC}")
    log_entries.append(f"Destination: {DST}")
    log_entries.append(f"Total files: {total}")
    log_entries.append("=" * 60)
    log_entries.append("")
    
    ok = errors = 0
    t0 = time.time()
    
    for i, (mt_path, rel_dir, fname) in enumerate(mt_files):
        # Build output path preserving hierarchy
        out_dir = os.path.join(DST, rel_dir)
        os.makedirs(out_dir, exist_ok=True)
        
        base = fname.replace('.mt', '')
        dec_path = os.path.join(out_dir, base + '.dec')
        txt_path = os.path.join(out_dir, base + '.txt')
        
        result, text, err = decompile_one(mt_path)
        
        if err:
            errors += 1
            entry = f"FAIL  [{i+1:3d}/{total:3d}] {rel_dir}/{fname}: {err}"
            print(entry)
            log_entries.append(entry)
            # Write error file
            err_path = os.path.join(out_dir, base + '.err')
            with open(err_path, 'w') as f:
                f.write(f"ERROR: {err}\n\nFile: {mt_path}\nTime: {datetime.now().isoformat()}\n")
        else:
            ok += 1
            # Save binary .dec
            with open(dec_path, 'wb') as f:
                f.write(result)
            # Save readable text
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(text)
            entry = f"OK    [{i+1:3d}/{total:3d}] {rel_dir}/{fname} -> {len(result)//1024}KB decompressed"
            print(entry)
            log_entries.append(entry)
        
        # Progress
        elapsed = time.time() - t0
        rate = (i + 1) / elapsed if elapsed > 0 else 0
        eta = (total - i - 1) / rate if rate > 0 else 0
        if (i+1) % 5 == 0 or i == total - 1:
            print(f"  PROGRESS: {i+1}/{total} | OK={ok} ERR={errors} | {elapsed:.0f}s | {rate:.1f} files/s | ETA={eta:.0f}s")
    
    # Summary
    t = time.time() - t0
    summary = f"\n{'=' * 60}\nSUMMARY: {ok} OK, {errors} FAILED in {t:.1f}s ({total/t:.1f} files/s)\n"
    print(summary)
    log_entries.append(summary)
    
    # Write log
    with open(LOG_FILE, 'w') as f:
        f.write('\n'.join(log_entries))
    
    print(f"Log written: {LOG_FILE}")
    
    # Print output tree
    print(f"\nOutput structure ({DST}):")
    for root, dirs, files in os.walk(DST):
        if files:
            rel = os.path.relpath(root, DST)
            if rel == '.':
                rel = '(root)'
            print(f"  {rel}/")
            for f in sorted(files):
                fpath = os.path.join(root, f)
                fsize = os.path.getsize(fpath)
                print(f"    {f} ({fsize//1024}KB)" if fsize > 1024 else f"    {f} ({fsize}B)")


if __name__ == '__main__':
    main()
