import random
import string
import socket
import sys
import time
import pickle
import crypt
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def main():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    pwd = "password"

    pempriv = private_key.private_bytes(
         encoding = serialization.Encoding.PEM,
         format = serialization.PrivateFormat.PKCS8,
         encryption_algorithm = serialization.BestAvailableEncryption( bytes(pwd, "utf-8"))
    )

    with open('private_key_test.pem', 'wb') as f:
        f.write(pempriv)


    with open("private_key_test.pem", "rb") as key_file:
        priv_key = serialization.load_pem_private_key(
            key_file.read(), 
            bytes( "password", "utf-8"),
            default_backend()
        )

    pub_key = priv_key.public_key()
    aux = "Hello"
    cipher = pub_key.encrypt(
        pickle.dumps(aux),
        padding.OAEP(
            padding.MGF1(algorithm=hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )
    print(aux)
    print(cipher)
    with open("private_key_test.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            bytes( "password", "utf-8"),
            backend = default_backend()
        )
    aux2 = private_key.decrypt(
        pickle.dumps(cipher),
        padding.OAEP(
            padding.MGF1(algorithm=hashes.SHA512()),
            hashes.SHA512(),
            None
        )
    )
    print(aux2)
main()