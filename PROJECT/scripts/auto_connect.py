import frida, time, sys

js_hook = """
Java.perform(function() {
    console.log('[+] Frida-gadget active!');

    var CCCrypto = Java.use('com.moonton.mobilehero.plug.game.CCCrypto');
    if (CCCrypto) {
        console.log('[+] Found CCCrypto class');
        var aesDec = CCCrypto.aes_decrypt.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
        aesDec.implementation = function(key, data, iv) {
            console.log('[AES] key=' + key + ' data=' + data + ' iv=' + iv);
            var result = this.aes_decrypt(key, data, iv);
            console.log('[AES] result=' + result);
            return result;
        };
    }

    var System = Java.use('java.lang.System');
    System.loadLibrary.implementation = function(name) {
        console.log('[loadLibrary] ' + name);
        return this.loadLibrary(name);
    };
});

// Also hook native functions
var mod = Process.findModuleByName('libagame.so');
if (mod) {
    console.log('[+] libagame.so at ' + mod.base);

    Interceptor.attach(mod.base.add(0xCECA74), {
        onEnter: function(args) {
            console.log('[setKey] called');
            try {
                var ptr = args[0];
                var s = ptr.readCString();
                console.log('[KEY] ' + s);
            } catch(e) {}
        }
    });
}

// Keep alive
setTimeout(function() {
    console.log('[+] Gadget hook initialized!');
}, 2000);
"""

for attempt in range(120):
    try:
        device = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
        procs = device.enumerate_processes()
        target = None
        for p in procs:
            if 'mobilehero' in p.name.lower():
                target = p
                break
        if target:
            print(f'[+] Found game PID={target.pid}')
            session = device.attach(target.pid)
            print('[+] Attached!')

            def on_msg(msg, data):
                if msg['type'] == 'send':
                    print('[HOOK]', msg['payload'])
                elif msg['type'] == 'error':
                    print('[ERR]', msg)

            script = session.create_script(js_hook)
            script.on('message', on_msg)
            script.load()
            print('[+] Hook loaded!')

            # Keep alive
            last_check = time.time()
            while True:
                try:
                    time.sleep(1)
                    device.enumerate_processes()  # heartbeat
                except:
                    print('[-] Connection lost, reconnecting...')
                    break
            break

        print(f'[{attempt}] Found {len(procs)} procs, no game yet')
    except Exception as e:
        print(f'[{attempt}] {e}')

    time.sleep(0.5)
