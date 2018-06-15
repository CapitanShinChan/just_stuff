import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(pid):
    session = frida.attach(pid)

    for x in session.enumerate_modules():
        print(x.name)

    script = session.create_script("""
        
        var baseAddr = Module.findBaseAddress('bcrypt.dll');
        console.log('bcrypt.dll baseAddr: ' + baseAddr);
        
        
    """)

    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()


if __name__ == "__main__":
    pid = sys.argv[1]
    main(pid)