import frida

device = frida.get_usb_device()

# Try to attach to the main process by PID 7478
pid = 7478
try:
    session = device.attach(pid)
    print(f'Attached to PID {pid}!')
    
    script_code = """
    console.log("[*] Script loaded");
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        console.log(modules[i].name + " @ 0x" + modules[i].base.toString(16));
    }
    """
    
    script = session.create_script(script_code)
    script.load()
    print('Script loaded and executed')
    session.detach()
except Exception as e:
    print(f'Error: {e}')
