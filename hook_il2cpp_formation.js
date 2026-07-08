'use strict';

// =====================================================
// MLA IL2CPP FORMATION HOOK — Frida Script
// Target: libil2cpp.so (Unity IL2CPP)
// Game:   com.moonton.mobilehero
// =====================================================

const KEYWORDS = [
    'Formation', 'form', 'Deploy', 'deploy',
    'Slot', 'slot', 'Hero', 'hero',
    'Lineup', 'lineup', 'Battle', 'battle',
    'Fight', 'fight', 'Team', 'team',
    'Position', 'position', 'Arrange', 'arrange',
    'Limit', 'limit', 'Max', 'max',
    'Validate', 'validate', 'Check', 'check',
    'Result', 'result', 'Win', 'win',
    'Victory', 'victory'
];

const EXCLUDE_MODULES = [
    'UnityEngine', 'System', 'Mono.', 'mscorlib',
    'Newtonsoft', 'Vuforia', 'Google', 'Firebase',
    'UniRx', 'UniTask', 'DOTween'
];

function isExcluded(name) {
    for (var i = 0; i < EXCLUDE_MODULES.length; i++) {
        if (name.indexOf(EXCLUDE_MODULES[i]) >= 0) return true;
    }
    return false;
}

function matchesKeyword(name) {
    for (var i = 0; i < KEYWORDS.length; i++) {
        if (name.indexOf(KEYWORDS[i]) >= 0) return true;
    }
    return false;
}

function hookMethod(method, className) {
    try {
        var methodName = method.name || '<anon>';
        var fullName = className + '.' + methodName;

        var impl = method.implementation;
        if (!impl) return;

        Interceptor.attach(impl, {
            onEnter: function(args) {
                console.log('[CALL] ' + fullName);
                // Log first few args
                for (var i = 0; i < Math.min(4, args.length); i++) {
                    try {
                        console.log('  arg[' + i + '] = ' + args[i]);
                    } catch(e) {}
                }
            },
            onLeave: function(retval) {
                if (matchesKeyword(methodName)) {
                    try {
                        console.log('  => ' + retval);
                    } catch(e) {}
                }
            }
        });

        console.log('[HOOK] ' + fullName);
    } catch(e) {
        console.log('[ERR] hook ' + className + '.' + (method.name || '?') + ': ' + e.message);
    }
}

function enumerateAndHook(image) {
    if (!image) return;

    image.classes.forEach(function(clazz) {
        var cn = clazz.fullName || clazz.name || '';
        if (isExcluded(cn)) return;

        var matches = matchesKeyword(cn);
        if (!matches) return;

        console.log('\n[CLASS] ' + cn);

        // Enumerate methods
        try {
            clazz.methods.forEach(function(method) {
                var mn = method.name || '';
                hookMethod(method, cn);
            });
        } catch(e) {
            // Try direct method access
            console.log('  => (error enumerating methods: ' + e.message + ')');
        }
    });
}

function main() {
    console.log('[+] MLA IL2CPP Formation Hook v1.0');
    console.log('[+] Frida version: ' + (typeof Frida !== 'undefined' ? Frida.version : '?'));

    // Check if Il2Cpp module is available
    if (typeof Il2Cpp !== 'undefined') {
        console.log('[+] Il2Cpp module detected!');
        Il2Cpp.perform(function() {
            console.log('[+] Il2Cpp initialized successfully');
            console.log('[+] Application: ' + Il2Cpp.applicationName);

            try {
                var assemblies = Il2Cpp.Domain.assemblies;
                console.log('[+] Assemblies count: ' + assemblies.length);

                assemblies.forEach(function(asm) {
                    var asmName = asm.name || '<unnamed>';
                    if (asmName.indexOf('Assembly-CSharp') >= 0) {
                        console.log('\n=== Scanning: ' + asmName + ' ===');
                        var image = asm.image;
                        enumerateAndHook(image);
                    }
                });
            } catch(e) {
                console.log('[ERR] Il2Cpp enumeration error: ' + e.message);
                console.log('[ERR] Stack: ' + e.stack);
            }
        });
    } else {
        console.log('[!] Il2Cpp module NOT available');
        console.log('[!] Will try manual libil2cpp.so scan...');

        // Fallback: manual metadata scan
        var libil2cpp = Module.findBaseAddress('libil2cpp.so');
        if (libil2cpp) {
            console.log('[+] libil2cpp.so base: ' + libil2cpp);

            // Scan for string references in memory
            console.log('[+] Scanning for formation-related strings...');
            var patterns = [
                'formation', 'Formation', 'deploy', 'Deploy',
                'heroId', 'slot', 'Slot', 'posIndex',
                'maxTeam', 'maxHero', 'limit'
            ];

            patterns.forEach(function(p) {
                try {
                    var matches = Memory.scanSync(libil2cpp,
                        libil2cpp.add(Process.pointerSize * 1024 * 1024 * 10),
                        p,
                        { short: true });
                    console.log('[STR] \'' + p + '\' found ' + matches.length + ' times');
                } catch(e) {}
            });
        } else {
            console.log('[!] libil2cpp.so not loaded yet');
        }
    }
}

// Wait for the process to fully initialize
setTimeout(function() {
    try {
        main();
    } catch(e) {
        console.log('[FATAL] ' + e.message + '\n' + e.stack);
    }
}, 3000);
