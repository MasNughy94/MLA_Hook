'use strict';

// =====================================================
// MLA IL2CPP FORMATION HUNT — Frida Gadget Script
// Target: libil2cpp.so via Frida Gadget
// Game:   com.moonton.mobilehero
// =====================================================
// Cara pakai:
//   1. Copy script ke /data/local/tmp/ di device
//   2. Set config gadget untuk load script ini
//   3. Jalankan game
// =====================================================

const FORMATION_KEYWORDS = [
    'Formation', 'formation', 'FORMATION',
    'Deploy', 'deploy', 'DEPLOY',
    'Slot', 'slot', 'SLOT',
    'Hero', 'hero', 'HERO',
    'Lineup', 'lineup', 'LINEUP',
    'Team', 'team', 'TEAM',
    'Position', 'position', 'POSITION',
    'Arrange', 'arrange', 'ARRANGE',
    'LineUp', 'lineUp'
];

const LIMIT_KEYWORDS = [
    'Limit', 'limit', 'LIMIT',
    'Max', 'max', 'MAX',
    'Count', 'count', 'COUNT',
    'Capacity', 'capacity', 'CAPACITY',
    'Restrict', 'restrict', 'RESTRICT',
    'Validate', 'validate', 'VALIDATE',
    'Check', 'check', 'CHECK',
    'CanAdd', 'canAdd', 'CAN_ADD',
    'IsValid', 'isValid', 'IS_VALID',
    'Enable', 'enable', 'ENABLE'
];

const BATTLE_KEYWORDS = [
    'Battle', 'battle', 'BATTLE',
    'Fight', 'fight', 'FIGHT',
    'Result', 'result', 'RESULT',
    'Win', 'win', 'WIN',
    'Victory', 'victory', 'VICTORY',
    'PvP', 'pvp', 'PVP',
    'Arena', 'arena', 'ARENA',
    'Campaign', 'campaign', 'CAMPAIGN',
    'Stage', 'stage', 'STAGE'
];

const EXCLUDE_MODULES = [
    'UnityEngine.', 'System.', 'Mono.',
    'mscorlib', 'Newtonsoft.', 'Vuforia.',
    'Google.', 'Firebase.', 'UniRx.',
    'UniTask.', 'DOTween.', 'LitJson.',
    'ICSharpCode.', 'TMPro.', 'Cinemachine.',
    'Facebook.', 'Oculus.'
];

function shouldExclude(name) {
    for (var i = 0; i < EXCLUDE_MODULES.length; i++) {
        if (name.indexOf(EXCLUDE_MODULES[i]) >= 0) return true;
    }
    return false;
}

function isNameMatch(name, keywords) {
    if (!name) return false;
    for (var i = 0; i < keywords.length; i++) {
        if (name.indexOf(keywords[i]) >= 0) return true;
    }
    return false;
}

var g_hookCount = 0;
var g_hookedMethods = [];

function tryHookMethod(method, reason) {
    try {
        var fn = method.implementation;
        if (!fn) return;

        var name = method.name || '<anon>';
        var klass = method.parent || {};
        var klassName = klass.fullName || klass.name || '?';

        // Prevent double-hook
        var key = klassName + '.' + name;
        if (g_hookedMethods.indexOf(key) >= 0) return;
        g_hookedMethods.push(key);

        Interceptor.attach(fn, {
            onEnter: function(args) {
                console.log('[MLA][' + reason + '] ' + key);
                // Log args
                for (var i = 0; i < Math.min(8, args.length); i++) {
                    try {
                        console.log('  [' + i + '] -> ' + args[i]);
                    } catch(e) {}
                }
            },
            onLeave: function(retval) {
                try {
                    if (isNameMatch(name, LIMIT_KEYWORDS) ||
                        isNameMatch(name, ['IsValid','CanAdd','Check'])) {
                        console.log('  RET=' + retval);
                    }
                } catch(e) {}
            }
        });

        g_hookCount++;
    } catch(e) {
        // Silently skip unhookable methods
    }
}

function scanImage(image) {
    if (!image) return;

    console.log('\n=== Scanning image: ' + (image.name || '?') + ' ===');

    image.classes.forEach(function(clazz) {
        try {
            var cn = clazz.fullName || clazz.name || '';
            if (shouldExclude(cn)) return;

            var isFormation = isNameMatch(cn, FORMATION_KEYWORDS);
            var isLimit = isNameMatch(cn, LIMIT_KEYWORDS);
            var isBattle = isNameMatch(cn, BATTLE_KEYWORDS);

            if (!isFormation && !isLimit && !isBattle) return;

            console.log('\n--- ' + cn + ' ---');

            clazz.methods.forEach(function(method) {
                var mn = method.name || '';

                try {
                    var params = method.parameterTypes || [];
                    var ret = method.returnType || '?';
                    var pstr = params.map(function(p) { return p.name || '?'; }).join(', ');
                    console.log('  ' + ret + ' ' + mn + '(' + pstr + ')');
                } catch(e) {
                    console.log('  ' + mn);
                }

                // Hook berdasarkan kategori
                if (isNameMatch(mn, FORMATION_KEYWORDS)) {
                    tryHookMethod(method, 'FORMATION');
                }
                if (isNameMatch(mn, LIMIT_KEYWORDS)) {
                    tryHookMethod(method, 'LIMIT');
                }
                if (isNameMatch(mn, BATTLE_KEYWORDS)) {
                    tryHookMethod(method, 'BATTLE');
                }
            });

        } catch(e) {
            // Skip class error
        }
    });
}

function main() {
    console.log('');
    console.log('========================================');
    console.log('  MLA IL2CPP FORMATION HUNT v1.0');
    console.log('  Target: libil2cpp.so');
    console.log('  Game: com.moonton.mobilehero');
    console.log('========================================');
    console.log('');

    if (typeof Il2Cpp === 'undefined') {
        console.log('[!] Il2Cpp module not available in this Frida version');
        console.log('[!] Switching to manual libil2cpp scan...');

        var lib = Module.findBaseAddress('libil2cpp.so');
        if (!lib) {
            console.log('[!] libil2cpp.so not loaded yet. Waiting...');
            var waitInterval = setInterval(function() {
                lib = Module.findBaseAddress('libil2cpp.so');
                if (lib) {
                    clearInterval(waitInterval);
                    console.log('[+] libil2cpp.so loaded at: ' + lib);
                    scanMemory(lib);
                }
            }, 500);
            return;
        }
        scanMemory(lib);
        return;
    }

    Il2Cpp.perform(function() {
        console.log('[+] Il2Cpp initialized: ' + Il2Cpp.applicationName);

        // Scan all assemblies
        Il2Cpp.Domain.assemblies.forEach(function(asm) {
            var asmName = asm.name || '?';
            if (asmName.indexOf('Assembly-CSharp') >= 0 ||
                asmName.indexOf('Assembly') >= 0 ||
                asmName.indexOf('Game') >= 0 ||
                asmName.indexOf('Logic') >= 0 ||
                asmName.indexOf('Script') >= 0) {
                try {
                    scanImage(asm.image);
                } catch(e) {
                    console.log('[ERR] ' + asmName + ': ' + e.message);
                }
            }
        });

        console.log('\n=== SCAN COMPLETE ===');
        console.log('Total hooked: ' + g_hookCount);

        if (g_hookCount === 0) {
            console.log('[!] No formation/limit methods found.');
            console.log('[!] Trying all assemblies (no filter)...');
            Il2Cpp.Domain.assemblies.forEach(function(asm) {
                try {
                    scanImage(asm.image);
                } catch(e) {}
            });
            console.log('\nTotal hooked (full scan): ' + g_hookCount);
        }
    });
}

// Manual scan fallback (for older Frida)
function scanMemory(libBase) {
    console.log('[+] Scanning libil2cpp.so memory for string references...');

    var keywords = FORMATION_KEYWORDS.concat(LIMIT_KEYWORDS).concat(BATTLE_KEYWORDS);
    var unique = {};
    keywords.forEach(function(k) { unique[k] = true; });

    var found = {};
    var total = 0;

    Object.keys(unique).forEach(function(kw) {
        try {
            var matches = Memory.scanSync(libBase, 0x8000000, kw, { short: true });
            if (matches.length > 0) {
                found[kw] = matches.length;
                total += matches.length;
                // Print some locations
                matches.slice(0, 3).forEach(function(m) {
                    console.log('  [STR] "' + kw + '" @ ' + m.address);
                });
            }
        } catch(e) {}
    });

    console.log('\n=== STRING SCAN RESULTS ===');
    console.log('Total string matches: ' + total);
    Object.keys(found).sort().forEach(function(kw) {
        console.log('  "' + kw + '": ' + found[kw] + ' hits');
    });
}

// Entry point
try {
    main();
} catch(e) {
    console.log('[FATAL] ' + e.message);
    console.log(e.stack);
}

console.log('\n[+] Script loaded. Waiting for game activity...');
