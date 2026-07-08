/*
 * Frida script to dump the full decoder state from libagame.so
 * Hooks: sub_CF2B2C (outer), sub_CF2110 (main), sub_CF0B04 (range)
 * 
 * Usage:
 *   frida-inject -n com.moonton.mobilehero -s frida_dump_decoder.js -o dump.log
 *   frida -U com.moonton.mobilehero -l frida_dump_decoder.js
 */

// Configuration
const libName = "libagame.so";
const OUT_FILE = "/storage/emulated/0/REVERSED/decoder_dump.json";

// Offsets (from existing disassembly)
const OFFSET_OUTER = 0xCF2B2C;
const OFFSET_MAIN = 0xCF2110;
const OFFSET_RANGE = 0xCF0B04;
const OFFSET_INIT = 0xCF2100;
const OFFSET_TABLE_INIT = 0xCF2878;

let dumpData = {
    decodes: [],
    tables: [],
    stateTransitions: []
};

let decodeId = 0;

function log(msg) {
    console.log("[DECODER] " + msg);
}

// ========================================
// HOOK 1: Outer decompress function
// ========================================
Interceptor.attach(Module.findExportByName(libName, null) || 
    Module.findBaseAddress(libName).add(OFFSET_OUTER), {
    onEnter: function(args) {
        log("=== sub_CF2B2C ENTER ===");
        this.contextPtr = args[0];
        this.outputPtr = args[1];
        this.dataPtr = args[2];
        this.sizePtr = args[3];
        this.headerPtr = args[4];
        
        // Read the lmF@ header (should be at headerPtr)
        if (this.headerPtr) {
            log("Header: " + hexdump(this.headerPtr, {length: 14}));
        }
        if (this.dataPtr) {
            log("Input first 32: " + hexdump(this.dataPtr, {length: 32}));
        }
    },
    onLeave: function(retval) {
        log("=== sub_CF2B2C LEAVE ret=" + retval + " ===");
    }
});

// ========================================
// HOOK 2: Main decompression driver
// ========================================
Interceptor.attach(Module.findExportByName(libName, null) || 
    Module.findBaseAddress(libName).add(OFFSET_MAIN), {
    onEnter: function(args) {
        log("=== sub_CF2110 ENTER ===");
        this.statePtr = args[0];
        
        // Dump state struct
        if (this.statePtr) {
            let state = {
                field_00: this.statePtr.readU32(),
                field_04: this.statePtr.add(4).readU32(),
                window_size_bits: this.statePtr.add(8).readU32(),
                comp_size: this.statePtr.add(0xC).readU32(),
                prob_table: this.statePtr.add(0x10).readPointer(),
                window_ptr: this.statePtr.add(0x18).readPointer(),
                input_ptr: this.statePtr.add(0x20).readPointer(),
                range: this.statePtr.add(0x28).readU32(),
                code: this.statePtr.add(0x2C).readU32(),
                output_ptr: this.statePtr.add(0x30).readPointer(),
                field_38: this.statePtr.add(0x38).readPointer(),
                bc: this.statePtr.add(0x40).readU32(),
                match_flag: this.statePtr.add(0x44).readU32(),
                state_val: this.statePtr.add(0x48).readU32(),
                field_4C: this.statePtr.add(0x4C).readU32(),
                field_50: this.statePtr.add(0x50).readU32(),
                field_54: this.statePtr.add(0x54).readU32(),
                field_58: this.statePtr.add(0x58).readU32(),
            };
            log("State: field00=" + state.field_00 + " field04=" + state.field_04 +
                " ws=" + state.window_size_bits + " ds=" + state.comp_size +
                " range=0x" + state.range.toString(16) + 
                " code=0x" + state.code.toString(16) +
                " bc=" + state.bc + " state=" + state.state_val);
            
            // Dump probability table (first 32 entries)
            if (state.prob_table) {
                let tblData = [];
                for (let i = 0; i < 64; i++) {
                    tblData.push(state.prob_table.add(i*2).readU16());
                }
                log("ProbTable[0..63]: " + JSON.stringify(tblData));
            }
        }
    },
    onLeave: function(retval) {
        log("=== sub_CF2110 LEAVE ret=" + retval + " ===");
        // Dump state again after decoding
        if (this.statePtr) {
            log("After decode: range=0x" + this.statePtr.add(0x28).readU32().toString(16) +
                " code=0x" + this.statePtr.add(0x2C).readU32().toString(16) +
                " bc=" + this.statePtr.add(0x40).readU32() +
                " state=" + this.statePtr.add(0x48).readU32());
        }
    }
});

// ========================================
// HOOK 3: Range decoder (processes one symbol)
// ========================================
Interceptor.attach(Module.findExportByName(libName, null) || 
    Module.findBaseAddress(libName).add(OFFSET_RANGE), {
    onEnter: function(args) {
        this.statePtr = args[0];
        this.uncompSize = args[1];
        this.endDataPtr = args[2];
        
        if (this.statePtr) {
            let bc = this.statePtr.add(0x40).readU32();
            let st = this.statePtr.add(0x48).readU32();
            let range = this.statePtr.add(0x28).readU32();
            let code = this.statePtr.add(0x2C).readU32();
            
            log("  [RANGE] bc=" + bc + " state=" + st + 
                " range=0x" + range.toString(16) + " code=0x" + code.toString(16));
        }
    },
    onLeave: function(retval) {
        if (this.statePtr) {
            let bc = this.statePtr.add(0x40).readU32();
            let st = this.statePtr.add(0x48).readU32();
            let range = this.statePtr.add(0x28).readU32();
            let code = this.statePtr.add(0x2C).readU32();
            
            log("  [RANGE] LEAVE bc=" + bc + " state=" + st + 
                " range=0x" + range.toString(16) + " code=0x" + code.toString(16) +
                " ret=" + retval);
            
            // Dump probability table indices used
            let tbl = this.statePtr.add(0x10).readPointer();
            if (tbl) {
                // Read the main decision context index
                let ci = (st << 4) + (bc & 3);
                log("  [RANGE] ci=" + ci + " prob=" + tbl.add(ci*2).readU16());
            }
        }
    }
});

// ========================================
// HOOK 4: Init function
// ========================================
Interceptor.attach(Module.findExportByName(libName, null) || 
    Module.findBaseAddress(libName).add(OFFSET_INIT), {
    onEnter: function(args) {
        log("=== sub_CF2100 ENTER ===");
        this.statePtr = args[0];
        if (this.statePtr) {
            log("State before init: field00=" + this.statePtr.readU32() +
                " field04=" + this.statePtr.add(4).readU32() +
                " field08=" + this.statePtr.add(8).readU32());
        }
    },
    onLeave: function() {
        if (this.statePtr) {
            log("State after init: state=" + this.statePtr.add(0x48).readU32() +
                " bc=" + this.statePtr.add(0x40).readU32() +
                " field50=0x" + this.statePtr.add(0x50).readU32().toString(16));
        }
    }
});

// ========================================
// HOOK 5: Header parser (extracts field values)
// ========================================
Interceptor.attach(Module.findExportByName(libName, null) || 
    Module.findBaseAddress(libName).add(OFFSET_TABLE_INIT), {
    onEnter: function(args) {
        log("=== Header parser ENTER ===");
        log("  Output buffer: " + args[0]);
        log("  Input data: " + args[1]);
        log("  Size: " + args[2]);
        
        if (args[1]) {
            log("  Input hex: " + hexdump(args[1], {length: 14}));
        }
    },
    onLeave: function(retval) {
        // The output is stored in args[0]
        log("=== Header parser LEAVE ===");
    }
});

// Main: log when script loads
log("Frida decoder dump script loaded!");
log("Target lib: " + libName);
log("Offsets: outer=0x" + OFFSET_OUTER.toString(16) + 
    " main=0x" + OFFSET_MAIN.toString(16) + 
    " range=0x" + OFFSET_RANGE.toString(16));
