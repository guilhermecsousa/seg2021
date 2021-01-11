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

#  cipherDeck = []
          
#  key = os.urandom(16)
#  iv = os.urandom(16)
#  for i in range(0,len(self.game.deck.deck)):
#      cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
#      encryptor = cipher.encryptor()
#      ct = encryptor.update(pickle.dumps(self.game.deck.deck[i])) + encryptor.finalize()
#      cipherDeck.append(ct)
#        
#  for i in range(0,len(cipherDeck)):
#      cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
#      decryptor = cipher.decryptor()
#      temp = decryptor.update(cipherDeck[3]) + decryptor.finalize()
#      print(pickle.loads(temp))

class Server:

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )

    pwd = "password"

    pempriv = private_key.private_bytes(
         encoding = serialization.Encoding.PEM,
         format = serialization.PrivateFormat.PKCS8,
         encryption_algorithm = serialization.BestAvailableEncryption( bytes(pwd, "utf-8"))
    )

    with open('private_key.pem', 'wb') as f:
        f.write(pempriv)

    # pempub = public_key.public_bytes(
    #     encoding = serialization.Encoding.PEM,
    #     format = serialization.PublicFormat.SubjectPublicKeyInfo
    # )

    # with open('public_key.pem', 'wb') as f:
    #     f.write(pempub)

    def __init__(self):
    
        self.deck = []    
        self.nplayers = 3
        self.startpieces = 5
        self.players = []
        self.table = []
        self.conn = {}
        self.addr = {}

        if len(sys.argv) >= 2:
            self.nplayers = sys.argv[1]

        for i in range(7):
            for j in range(i,7):
                self.deck += [[i,j]]
                
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('localhost', 25565))
        
        print("Waiting for players...\n")
        
        while 1:
            s.listen(1)
            conn, addr = s.accept()
            data = pickle.loads(conn.recv(4096))
            if 'name' in data:
                name=data['name']
                print("Player",name,"connected.")
                self.players += [name]
                self.conn[name]=conn
                self.addr[name]=addr
            
            if len(self.players)==self.nplayers:
                print("Lobby is full")
                break
                
    def givePiece(self,player):
        if len(self.deck)>0:
            piece = self.deck.pop(random.randint(0,len(self.deck)-1))
            msg = {"piece": piece}
            self.conn[player].sendall(pickle.dumps(msg))
            print("Piece given.")
        else:
            msg = {'nopiece': 'nopiece'}
            self.conn[player].sendall(pickle.dumps(msg))
            print("No more pieces.")
        
    def startGame(self):
        
        print("deck ->",self.deck,"\n")

        with open("private_key.pem", "rb") as key_file:
            priv_key = serialization.load_pem_private_key(
                key_file.read(), 
                bytes( "password", "utf-8"),
                default_backend()
            )

        pub_key = priv_key.public_key()

        # maxLen = (pub_key_size // 8) - 2 * hashes.SHA256.digest_size - 2 
        # print(maxLen)
        
        cipherDeck = []
        # key = os.urandom(16)
        # iv = os.urandom(16)
        # for i in range(0,len(self.deck)):
        #     cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        #     encryptor = cipher.encryptor()
        #     ct = encryptor.update(pickle.dumps(self.deck[i])) + encryptor.finalize()
        #     cipherDeck.append(ct)
        
        for i in range(0,len(self.deck)):
            ciphertext = pub_key.encrypt(
                pickle.dumps(i),
                padding.OAEP(
                    padding.MGF1(
                        hashes.SHA256()
                    ),
                    hashes.SHA256(),
                    None
                )
            )
            
            cipherDeck.append(ciphertext)

        self.deck = cipherDeck    
            
        input("Press a key to START")
        
        for i in range(self.startpieces): 
            for player in self.players:
                self.givePiece(player)
                time.sleep(0.01)
                
        self.playGame()
                
    def playGame(self):
        
        running=1
        
        while running:
                
            passed=0
            
            for player in self.players:
           
                print("\n-----------------------")
                print("Table ->",self.table)
                print("Deck ->",self.deck)
                print("To play ->",player)
                msg={'play': self.table}
                self.conn[player].sendall(pickle.dumps(msg))
                data = pickle.loads(self.conn[player].recv(4096))
                
                if 'piece' in data:
                    self.givePiece(player)
                    data = pickle.loads(self.conn[player].recv(4096))
                    while 'piece' in data:
                        self.givePiece(player)
                        time.sleep(0.1)
                        data = pickle.loads(self.conn[player].recv(4096))
                    print("Deck ->",self.deck)
                if 'played' in data:
                    self.table=data['played']
                    print("Piece played.")
                    print("Table ->",self.table)    
                if 'pass' in data:
                    print("Passed.")
                    passed=passed+1
                if 'iwin' in data:
                    print("The winner is",player)
                    print("Game Ended.")                        
                    running = 0
                    exit()
                    
                time.sleep(0.1)
                        
            if passed==3:
                print("It's a DRAW")
                print("Game Ended")
                running = 0
                exit()
            
sv = Server()

sv.startGame()

#conn.close()