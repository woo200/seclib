import subprocess
import platform
import argparse
import sockslib
import eftp

processes = []

if platform.system() == "Linux":
    from platforms.linux import *
elif platform.system() == "Windows":
    from platforms.windows import *
else:
    raise NotImplementedError("Unsupported platform")

def get_hostname():
    with open("hidden_service/hostname") as f:
        return f.read().strip()
    
def is_port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def main():
    args = argparse.ArgumentParser()
    args.add_argument("--client", type=str, help="Client mode, must specify the server address")
    args = args.parse_args()

    install_tor()
    generate_torrc(51827)

    # Start Tor
    if not is_port_in_use(9051):
        processes.append(subprocess.Popen([tor_binary, "-f", "torrc"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    
    if args.client:
        socket = sockslib.SocksSocket()
        socket.set_proxy(('127.0.0.1', 9051))
        print(f"Connecting to {args.client}...")
        socket.connect((args.client, 51827))

        print("Connected! Handshaking...")
        client = eftp.TransferClient(socket)
        client.connect()
        print("Handshake complete! Sending file...")
        client.send_file("test/test.txt")
        print("File sent!")

        return
    else:
        print(f"Server started at {get_hostname()}")
        server = eftp.TransferServer(('127.0.0.1', 51827))
        server.listen_forever()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        for process in processes:
            process.kill()