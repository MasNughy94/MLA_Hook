/*
 * frida_trace_bits.js - Trace every range decoder bit decision
 *
 * For each decoded bit, logs:
 *   step, offset, range, code, probability, bound, decoded_bit
 *
 * Output: JSON array to /storage/emulated/0/decoder_trace.json
 *
 * Usage:
 *   frida -U -n com.moonton.mobilehero -l frida_trace_bits.js
 *   # Play game to trigger decoding
 *   # Then: adb pull /storage/emulated/0/decoder_trace.json ./
 *
 * Or use frida-trace for live output:
 *   frida-trace -U -i '*range*' -i '*decode*' -i '*decompress*' -n libagame.so
 */

const libName = "libagame.so";

// Offsets from disassembly
const OFFSET_RANGE  = 0xCF0B04;  // range decoder bit function
const OFFSET_MAIN    = 0xCF2110;  // main decompressor driver
const OFFSET_INIT    = 0xCF2100;  // state init

const OUT_FILE = "/storage/emulated/0/decoder_trace.json";

let traceData = {
    metadata: {
        lib: libName,
        offsets: {
            range: "0x" + OFFSET_RANGE.toString(16),
            main:  "0x" + OFFSET_MAIN.toString(16),
            init:  "0x" + OFFSET_INIT.toString(16)
        },
        description: "Trace every bit decision in native range decoder",
        format: {
            step: "sequential bit decision counter",
            offset: "data pointer offset in compressed stream",
            range: "range register (h) before decision",
            code: "code register (l) before decision",
            probability: "probability value from table",
            bound: "computed bound (range >> 11) * probability",
            decoded_bit: "0 or 1"
        }
    },
    inits: [],
    bits: [],
    errors: []
};

let bitCount = 0;
let lastError = null;

function log(msg) {
    console.log("[TRACE] " + msg);
}

function ptrToNum(p) {
    return parseInt(p.toString(), 16);
}

// Write trace to file
function flushTrace() {
    try {
        const fn = new File(OUT_FILE, "w");
        fn.write(JSON.stringify(traceData, null, 2));
        fn.close();
        log("Trace flushed to " + OUT_FILE + " (" + traceData.bits.length + " bits)");
    } catch (e) {
        log("ERROR flushing: " + e);
    }
}

// ================================================================
// HOOK: sub_CF0B04 - range decoder bit decision
// This is the core function that does:
//   bound = (range >> 11) * probability
//   if (code < bound) { range = bound; bit = 0; }
//   else { code -= bound; range -= bound; bit = 1; }
// ================================================================
const baseAddr = Module.findBaseAddress(libName);
if (!baseAddr) {
    log("ERROR: libagame.so not found!");
    send({ type: "error", msg: "libagame.so not loaded" });
} else {
    log("libagame.so base: " + baseAddr);
    const rangeFnAddr = baseAddr.add(OFFSET_RANGE);
    log("Hooking range decoder at: " + rangeFnAddr);

    Interceptor.attach(rangeFnAddr, {
        onEnter: function(args) {
            // args[0] = state struct pointer
            // args[1] = probability table index OR direct probability value
            this.statePtr = args[0];

            try {
                const state = ptrToNum(this.statePtr);
                const prob_idx_or_val = ptrToNum(args[1]);

                // Read range and code from state struct
                // State struct layout (from disassembly):
                // 0x00: ?
                // 0x04: ?
                // 0x08: window_size_bits (e)
                // 0x0C: compressed_size
                // 0x10: prob_table pointer
                // 0x18: window pointer
                // 0x20: input pointer
                // 0x28: range (h)
                // 0x2C: code (l)
                // 0x30: output pointer
                // 0x38: ?
                // 0x3C: ?
                // 0x40: bc (byte counter)
                // 0x44: match_flag
                // 0x48: state (0-12)
                // 0x4C: ?
                // 0x50: ?
                // 0x54: ?

                const range_reg = this.statePtr.add(0x28).readU32();
                const code_reg  = this.statePtr.add(0x2C).readU32();
                const bc        = this.statePtr.add(0x40).readU32();
                const state_val = this.statePtr.add(0x48).readU32();
                const tbl_ptr   = this.statePtr.add(0x10).readPointer();
                const input_ptr = this.statePtr.add(0x20).readPointer();

                // Determine probability value
                let prob_val = prob_idx_or_val;

                // If probability looks like an index (0-7990), read from table
                if (prob_idx_or_val < 0x10000 && tbl_ptr) {
                    // Check if it looks like an index or direct value
                    // Native passes either table index or direct probability
                    if (prob_idx_or_val < 0x2000) {
                        // Likely a table index
                        prob_val = tbl_ptr.add(prob_idx_or_val * 2).readU16();
                    } else {
                        // Likely a direct probability value
                        prob_val = prob_idx_or_val;
                    }
                }

                // Compute bound: (range >> 11) * probability
                // range is 32-bit, shift right 11, multiply by prob (16-bit)
                const bound = ((range_reg >>> 11) * prob_val) >>> 0;

                this._range = range_reg;
                this._code  = code_reg;
                this._prob  = prob_val;
                this._bound = bound;
                this._bc    = bc;
                this._st    = state_val;
                this._tbl   = tbl_ptr;
            } catch (e) {
                lastError = "onEnter: " + e.toString();
                this._error = true;
            }
        },

        onLeave: function(retval) {
            if (this._error) {
                traceData.errors.push({ at: "range_onLeave", error: lastError });
                return;
            }

            try {
                const decoded_bit = parseInt(retval.toString()) & 0xFF;
                const range_after = this.statePtr.add(0x28).readU32();
                const code_after  = this.statePtr.add(0x2C).readU32();
                const bc_after    = this.statePtr.add(0x40).readU32();
                const state_after = this.statePtr.add(0x48).readU32();

                bitCount++;

                const entry = {
                    step: bitCount,
                    // State before decision
                    range_before: "0x" + this._range.toString(16).toUpperCase(),
                    code_before:  "0x" + this._code.toString(16).toUpperCase(),
                    // Decision parameters
                    probability: this._prob,
                    bound:       "0x" + this._bound.toString(16).toUpperCase(),
                    // Decision
                    decoded_bit: decoded_bit,
                    // State after decision
                    range_after: "0x" + range_after.toString(16).toUpperCase(),
                    code_after:  "0x" + code_after.toString(16).toUpperCase(),
                    // Context
                    bc_after:    bc_after,
                    state_after: state_after
                };

                traceData.bits.push(entry);

                // Log every 1000 bits
                if (bitCount % 1000 === 0) {
                    log("bits: " + bitCount + " last_bit=" + decoded_bit +
                        " range=" + this._range.toString(16) +
                        " code=" + this._code.toString(16) +
                        " prob=" + this._prob +
                        " bound=" + this._bound.toString(16) +
                        " -> " + decoded_bit);
                }

            } catch (e) {
                traceData.errors.push({ at: "range_onLeave", error: e.toString() });
            }
        }
    });

    // ================================================================
    // HOOK: sub_CF2100 - state initialization
    // Capture the initial range/code state from the compressed data
    // ================================================================
    const initFnAddr = baseAddr.add(OFFSET_INIT);
    log("Hooking init at: " + initFnAddr);

    Interceptor.attach(initFnAddr, {
        onEnter: function(args) {
            this.statePtr = args[0];
            this.dataPtr  = args[1];
            this.size     = args[2];
            log("=== sub_CF2100 ENTER ===");
            log("  state=" + this.statePtr);
            log("  data="  + this.dataPtr);
            log("  size="  + this.size);
            if (this.dataPtr) {
                log("  first 20 bytes: " + hexdump(this.dataPtr, {length: 20}));
            }
        },
        onLeave: function(retval) {
            try {
                const range = this.statePtr.add(0x28).readU32();
                const code  = this.statePtr.add(0x2C).readU32();
                const bc    = this.statePtr.add(0x40).readU32();
                const state = this.statePtr.add(0x48).readU32();
                const tbl   = this.statePtr.add(0x10).readPointer();

                traceData.inits.push({
                    function: "sub_CF2100",
                    return_value: retval ? retval.toString() : "void",
                    state: {
                        range: "0x" + range.toString(16).toUpperCase(),
                        code:  "0x" + code.toString(16).toUpperCase(),
                        bc:    bc,
                        state: state,
                        prob_table: tbl ? tbl.toString() : "null"
                    }
                });

                log("=== sub_CF2100 LEAVE ===");
                log("  range=0x" + range.toString(16) +
                    " code=0x" + code.toString(16) +
                    " bc=" + bc + " state=" + state);

                // Dump first 16 prob table entries
                if (tbl) {
                    let probs = [];
                    for (let i = 0; i < 16; i++) {
                        probs.push(tbl.add(i*2).readU16());
                    }
                    log("  ProbTable[0..15]: " + JSON.stringify(probs));
                }
            } catch (e) {
                traceData.errors.push({ at: "init_onLeave", error: e.toString() });
            }
        }
    });

    // ================================================================
    // Auto-flush periodically
    // ================================================================
    setInterval(() => {
        if (bitCount > 0) {
            flushTrace();
        }
    }, 10000);

    log("Frida trace script loaded! Hooked:");
    log("  sub_CF0B04 - range decoder bit decisions");
    log("  sub_CF2100 - state initialization");
    log("Output: " + OUT_FILE);
    log("Waiting for decompression to start...");
}
