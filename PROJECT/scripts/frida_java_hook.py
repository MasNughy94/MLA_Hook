"""
Try Frida Java-level hooking on the main process
"""
import frida
import time

jscode = """
console.log("[*] Java hook script loaded");

function log(msg) {
    console.log("[" + Date.now() + "] " + msg);
}

Java.perform(function() {
    log("Inside Java.perform()");
    
    // Try to list all loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("moonton") >= 0 || 
                className.indexOf("crypto") >= 0 || 
                className.indexOf("Crypto") >= 0 ||
                className.indexOf("asset") >= 0 ||
                className.indexOf("Asset") >= 0 ||
                className.indexOf("Antm") >= 0 ||
                className.indexOf("antm") >= 0 ||
                className.indexOf("file") >= 0 ||
                className.indexOf("File") >= 0) {
                log("Found: " + className);
            }
        },
        onComplete: function() {
            log("Java class enumeration complete");
        }
    });
    
    // Hook System.loadLibrary
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function(libName) {
        log("loadLibrary: " + libName);
        return this.loadLibrary(libName);
    };
    
    // Hook FileInputStream to capture file reads
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        var path = file.getAbsolutePath();
        if (path.indexOf(".mt") >= 0 || path.indexOf(".lua") >= 0) {
            log("FileInputStream opened: " + path);
        }
        return this.$init(file);
    };
    FileInputStream.$init.overload('java.lang.String').implementation = function(name) {
        if (name.indexOf(".mt") >= 0 || name.indexOf("Antm") >= 0) {
            log("FileInputStream opened (string): " + name);
        }
        return this.$init(name);
    };
    
    log("[*] Java hooks installed");
});

// Also try to access the runtime
setTimeout(function() {
    Java.perform(function() {
        log("Checking runtime...");
        var runtime = Java.use("java.lang.Runtime");
        log("Runtime: " + runtime);
    });
}, 5000);
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[!] Error: {message.get('description', '')}")

def main():
    # Check if game is running
    device = frida.get_usb_device()
    try:
        app = device.get_process("com.moonton.mobilehero")
        pid = app.pid
        print(f"Found PID: {pid}")
    except:
        print("Game not running, launch it first")
        # Try to get PID from adb
        import subprocess
        result = subprocess.run(
            ['C:\\LDPlayer\\LDPlayer9\\adb.exe', 'shell', 'ps', '-A'],
            capture_output=True, text=True
        )
        for line in result.stdout.split('\n'):
            if 'mobilehero' in line and 'muf' not in line:
                parts = line.split()
                pid = int(parts[1])
                print(f"Found PID from ps: {pid}")
                break
        else:
            print("Could not find game process")
            return
    
    try:
        session = device.attach(pid)
        print(f"Attached to PID {pid}")
        
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        
        print("[*] Running... Press Ctrl+C to stop")
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"Error attaching: {e}")

if __name__ == "__main__":
    main()
