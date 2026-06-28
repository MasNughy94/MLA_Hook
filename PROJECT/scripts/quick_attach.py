import frida, sys, time

# Try connecting to frida-gadget (listen mode on port 27042)
for attempt in range(30):
    try:
        device = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
        procs = device.enumerate_processes()
        for p in procs:
            if 'mobilehero' in p.name or 'Moonton' in p.name or 'ML' in p.name:
                print(f'[+] Found game process: PID={p.pid} name={p.name}')
                session = device.attach(p.pid)
                print('[+] ATTACHED!')
                
                js = """
                console.log('[+] Anti-bypass script loaded');
                // Hook System.loadLibrary to block library loading detection
                var Module = null;
                Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
                    onEnter: function(args) {
                        var name = args[0].readCString();
                        if (name && name.indexOf('frida') >= 0) {
                            console.log('[!] Blocking dlopen of: ' + name);
                        }
                        if (name && name.indexOf('Moonton') >= 0) {
                            console.log('[!] Moonton library loading: ' + name);
                        }
                    }
                });
                """
                
                script = session.create_script(js)
                script.on('message', lambda msg, data: print(msg.get('payload', '')))
                script.load()
                print('[+] Script injected!')
                
                # Keep alive
                while True:
                    time.sleep(1)
                sys.exit(0)
        
        print(f'[{attempt}] Game not found yet ({len(procs)} procs)')
    except Exception as e:
        print(f'[{attempt}] Not ready: {e}')
    
    time.sleep(1)

print('[-] Failed to attach within timeout')
