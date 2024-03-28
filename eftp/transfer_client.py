import socket
import struct
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.Random import get_random_bytes

from .transfer_server import AESSock

class TransferClient:
    def __init__(self, remote_addr, **kwargs):
        self.args = {
            'pks': './pks_pub',
            'key_selection': 0,
            'handshake': 'RSA',
            **kwargs
        }
        self.remote_addr = remote_addr

        if isinstance(remote_addr, socket.socket):
            self.sock = remote_addr
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.rsa = {}
        self.aes = {}

        self.__load_keys()
    
    def __load_keys(self):
        if self.args['handshake'] == 'RSA':
            pub_key_path = os.path.join(self.args['pks'], f'public_key_{self.args["key_selection"]}.pem')
            with open(pub_key_path, 'rb') as f:
                pub_key = f.read()
            self.rsa["pub_key"] = RSA.import_key(pub_key)
        elif self.args['handshake'] == 'AES':
            aes_key_path = os.path.join(self.args['pks'], f'aes_key_{self.args["key_selection"]}.key')
            with open(aes_key_path, 'rb') as f:
                aes_key = f.read()
            self.aes["key"] = aes_key
    
    def __handshake_rsa(self):
        v_token = self.sock.recv(16)
        v_token_signature_len, = struct.unpack('!H', self.sock.recv(2))
        v_token_signature = self.sock.recv(v_token_signature_len)

        v_token_hash = SHA256.new(v_token)
        rsa_pub_key = self.rsa["pub_key"]

        # Throws an exception if the signature is invalid
        pss.new(rsa_pub_key).verify(v_token_hash, v_token_signature)
        
        aes_session_key = get_random_bytes(16)
        cipher = PKCS1_OAEP.new(rsa_pub_key)
        ciphertext = cipher.encrypt(aes_session_key)
        self.sock.sendall(struct.pack('!H', len(ciphertext)))
        self.sock.sendall(ciphertext)

        aes_sock = AESSock(self.sock, aes_session_key)
        return aes_sock

    def connect(self):
        if not isinstance(self.remote_addr, socket.socket):
            self.sock.connect(self.remote_addr)

        if self.args['handshake'] == 'RSA':
            self.sock = self.__handshake_rsa()
        elif self.args['handshake'] == 'AES':
            self.sock = AESSock(self.sock, self.aes["key"])
        else:
            raise ValueError("Invalid handshake method")
        
        return self.sock