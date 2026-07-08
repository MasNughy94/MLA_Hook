import frida, time, json

JS = """
var results = [];
var allProcs = Process.enumerateProcesses();
console.log('Total processes: ' + allProcs.length);
allProcs.forEach(function(p) {
    var n = p.name.toLowerCase();
    if (n.indexOf('ml') !== -1 || n.indexOf('mobilehero') !== -1 || n.indexOf('moonton') !== -1 || n.indexOf('game') !== -1 || n.indexOf('unity') !== -1) {
        console.log('[GAME-PROC] PID=' + p.pid + ' name=' + p.name);
        results.push({pid: p.pid, name: p.name});
    }
});
console.log('All processes:');
allProcs.forEach(function(p) {
    console.log('  ' + p.pid + ': ' + p.name);
});
send({game_procs: results, total: allProcs.length});
"""

def on_message(msg, data):
    payload = msg.get('payload')
    if isinstance(payload, str):
        d = json.loads(payload)
        print('Game processes:', json.dumps(d.get('game_procs', [])))
        print('Total:', d.get('total', '?'))

mgr = frida.get_device_manager()
device = mgr.add_remote_device('127.0.0.1')
session = device.attach(4703)
script = session.create_script(JS)
script.on('message', on_message)
script.load()
time.sleep(3)
session.detach()
