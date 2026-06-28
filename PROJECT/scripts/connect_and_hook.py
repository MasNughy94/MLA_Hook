import frida, sys, time, os

# Wait for gadget to start (25MB init takes time)
print('Waiting 60s for gadget to initialize...')
time.sleep(60)

for attempt in range(60):
    try:
        device = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
        procs = device.enumerate_processes()
        print(f'[+] Connected! {len(procs)} processes')
        
        target = None
        for p in procs:
            if 'mobilehero' in p.name.lower():
                target = p
                print(f'[+] Found game: PID={p.pid} name="{p.name}"')
                break
        
        if not target:
            print(f'[-] Game not found, waiting... ({len(procs)} procs)')
            time.sleep(1)
            continue
        
        # Attach
        session = device.attach(target.pid)
        print('[+] ATTACHED!')
        
        # Load the crypto hook script
        with open(r'C:\Users\NGEONG\Videos\MLA\hook_crypto.py', 'r') as f:
            content = f.read()
        
        # Extract the jscode from hook_crypto.py
        import ast
        # Find jscode variable
        lines = content.split('\n')
        in_js = False
        js_lines = []
        for line in lines:
            if line.strip().startswith('jscode = """'):
                in_js = True
                continue
            if in_js:
                if line.strip() == '"""':
                    break
                js_lines.append(line)
        
        jscode = '\n'.join(js_lines)
        
        # Also add a keep-alive and dump-on-call logic
        keep_alive = """
// Dump captured data
var capturedKeys = {};
var capturedData = {};

setInterval(function() {
    if (Object.keys(capturedKeys).length > 0) {
        var report = JSON.stringify({
            keys: capturedKeys,
            data: capturedData
        });
        console.log('[DUMP] ' + report);
        send(report);
    }
}, 5000);
"""
        jscode = keep_alive + jscode
        
        def on_msg(msg, data):
            if msg['type'] == 'send':
                print('[RECV]', msg['payload'])
                # Save to file
                with open(r'C:\Users\NGEONG\AppData\Local\Temp\opencode\captured_data.txt', 'a') as f:
                    f.write(str(msg['payload']) + '\n')
            elif msg['type'] == 'error':
                print('[ERR]', msg)
        
        script = session.create_script(jscode)
        script.on('message', on_msg)
        script.load()
        print('[+] Hook script injected! Waiting for crypto calls...')
        
        # Keep running
        while True:
            time.sleep(1)
            
    except Exception as e:
        print(f'[{attempt}] Not ready: {e}')
        time.sleep(2)

print('[-] Failed!')
