import threading
import argparse
import sockslib
import eftp
import tor

def recv_chat(sock):
    while True:
        data = sock.recvall()
        print(f"\rRemote: {data.decode()}                \n> ",end="")

def run_chat_server(sock, _):
    recv_thread = threading.Thread(target=recv_chat, args=(sock,), daemon=True)
    recv_thread.start()
    while True:
        data = input("> ")
        print(f"\rYou: {data}                ")
        sock.sendall(data.encode())

def main():
    args = argparse.ArgumentParser()
    args.add_argument("--client", type=str, help="Client mode, must specify the server address")
    args.add_argument("pks", type=str, help="PKS Dir")
    args = args.parse_args()

    with tor.TorController() as controller:
        if args.client:
            if not controller.running():
                controller.start()

            socket = controller.get_torsock()
            socket.connect((args.client, 51827))

            print("Connected! Handshaking...")
            client = eftp.TransferClient(socket, pks=args.pks, key_selection=0)
            sock = client.connect()
            print("Handshake complete!")
            run_chat_server(sock, None)

            return
        else:
            controller.add_hidden_service('127.0.0.1', 51827, 51827, 'hidden_service')
            controller.start()
            controller.wait_for_service(0)
            print(f"Server started at {controller.get_hidden_service(0).hostname}")

            server = eftp.TransferServer(('127.0.0.1', 51827), pks=args.pks, connect_handler=run_chat_server)
            server.listen_forever()

if __name__ == "__main__":
    main()
