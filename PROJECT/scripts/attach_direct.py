import frida, time

# Grab the device and try to find the game PID from USB device first
usb = frida.get_usb_device()
procs = usb.enumerate_processes()
target_pid = None
for p in procs:
    if 'mobilehero' in p.name.lower():
        target_pid = p.pid
        print(f'Game PID via USB: {target_pid}')
        break

if not target_pid:
    print('Game not found via USB. Checking gadget...')
    # Try known PID from before
    known_pids = [15497, 31000, 30014]
    for pid in known_pids:
        try:
            session = usb.attach(pid)
            print(f'Attached to {pid}!')
            session.detach()
        except:
            pass
else:
    # Try gadget
    print(f'Game PID from USB: {target_pid}')

# Try gadget - quick connect
try:
    device = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    print('Gadget device obtained')
    
    # Try to use known PID or just attach by name
    session = device.attach('com.moonton.mobilehero')
    print('ATTACHED via gadget!')
    
    script = session.create_script("console.log('INJECTED!');")
    script.load()
    print('Script injected!')
    
    while True:
        time.sleep(1)
except Exception as e:
    print(f'Gadget error: {e}')
