import socket
import struct
import threading
import io
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes

class AESSock():
    def __init__(self, socket, key):
        self.key = key
        self.socket = socket
        self.buffer = io.BytesIO()
    
    def sendall(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        data = nonce + tag + ciphertext
        self.socket.sendall(struct.pack('!I', len(ciphertext)) + data)
    
    def recvall(self):
        ciphertext_length = struct.unpack('!I', self.socket.recv(4))[0]
        nonce, tag = self.socket.recv(16), self.socket.recv(16)
        ciphertext = self.socket.recv(ciphertext_length)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data

    def recv(self, num_bytes):
        # if there are enough bytes in the buffer, return them and dont block
        num_bytes_remaining = self.buffer.getbuffer().nbytes - self.buffer.tell()
        if num_bytes_remaining >= num_bytes:
            return self.buffer.read(num_bytes)
        
        # get the data and write it to the buffer
        data = self.recvall()
        writ_bytes = self.buffer.write(data)
        self.buffer.seek(-writ_bytes, io.SEEK_CUR)
        
        # if there are enough bytes in the buffer, return them
        if num_bytes_remaining + len(data) >= num_bytes:
            return self.buffer.read(num_bytes)
        
        # otherwise, read more data from the socket
        return self.recv(num_bytes)

class TransferServer:
    def __init__(self, bind_addr, **kwargs):
        self.args = {
            'pks': './pks_priv',
            'key_selection': 0,
            'handshake': 'RSA',
            'cipher_mode': AES.MODE_CBC,
            **kwargs
        }
        self.bind_addr = bind_addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_threads = []

        self.rsa = {}
        self.aes = {}

        self.__load_keys()
    
    def __load_keys(self):
        if self.args['handshake'] == 'RSA':
            priv_key_path = os.path.join(self.args['pks'], f'private_key_{self.args["key_selection"]}.pem')
            with open(priv_key_path, 'rb') as f:
                priv_key = f.read()
            self.rsa["priv_key"] = RSA.import_key(priv_key)
        elif self.args['handshake'] == 'AES':
            aes_key_path = os.path.join(self.args['pks'], f'aes_key_{self.args["key_selection"]}.key')
            with open(aes_key_path, 'rb') as f:
                aes_key = f.read()
            self.aes["key"] = aes_key

    def listen_forever(self):
        self.sock.bind(self.bind_addr)
        self.sock.listen(5)
        while True:
            client_sock, client_addr = self.sock.accept()
            client_thread = threading.Thread(
                target=self.__handle_client, 
                args=(client_sock, client_addr)
            )
            client_thread.start()
            self.client_threads.append(client_thread)
    
    def __handshake_rsa(self, client_sock, client_addr):
        v_token = get_random_bytes(16)
        v_token_hash = SHA256.new(v_token)
        v_token_signature = pss.new(self.rsa["priv_key"]).sign(v_token_hash)

        client_sock.sendall(v_token)
        client_sock.sendall(struct.pack('!H', len(v_token_signature)))
        client_sock.sendall(v_token_signature)

        cipher = PKCS1_OAEP.new(self.rsa["priv_key"])
        ciphertext_len = struct.unpack('!H', client_sock.recv(2))[0]
        ciphertext = client_sock.recv(ciphertext_len)
        aes_session_key = cipher.decrypt(ciphertext)
        aes_sock = AESSock(client_sock, aes_session_key)

        return aes_sock

    def __handle_client(self, client_sock, client_addr):
        if self.args['handshake'] == 'RSA':
            client_sock = self.__handshake_rsa(client_sock, client_addr)
        elif self.args['handshake'] == 'AES':
            aes_sock = AESSock(client_sock, self.aes["key"])
            client_sock = aes_sock
        else:
            raise ValueError("Invalid handshake method")
        
        file_size, = struct.unpack('!Q', client_sock.recv(8))
        file_name = client_sock.recvall().decode('utf-8')

        print(f"Receiving file {file_name} from {client_addr}")

        with open(file_name, 'wb') as f:
            while file_size > 0:
                data = client_sock.recvall()
                f.write(data)
                file_size -= len(data)

        client_sock.socket.close()
        print(f"Received file {file_name} from {client_addr}")