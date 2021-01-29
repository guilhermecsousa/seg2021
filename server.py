import random
import string
import socket
import sys
import time
import pickle
import crypt
import numpy as np
import os
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import base64
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Server:
    
    def __init__(self):
    
        self.deck = []    
        self.nplayers = 3
        self.startpieces = 5
        self.players = []
        self.table = []
        self.conn = {}
        self.addr = {}
        self.key = Fernet.generate_key()

        key = RSA.generate(4096)
        
        # symmetric key generation using the Fernet cipher
        # with open('secure.pem', 'wb') as new_key_file:
        #     new_key_file.write(key)

        if len(sys.argv) >= 2:
            self.nplayers = sys.argv[1]

        # cifra das peças
        for i in range(7):
            for j in range(i,7):
                msg = [i,j]
                print(msg)
                msg = str(msg).encode()

                # Fernet AES Encrypt
                f = Fernet(self.key)
                encrypted = base64.b64encode(msg)
                encrypted = f.encrypt(encrypted)
                # RSA Encrypt
                encryptor = PKCS1_OAEP.new(key)
                encrypted = encryptor.encrypt(encrypted)
                self.deck += [encrypted]

        #print(self.deck)


        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('localhost', 25567))
        
        print("Waiting for players...\n")
        
        while 1:
            self.s.listen(1)
            conn, addr = self.s.accept()
            data = pickle.loads(conn.recv(4096))
            if 'name' in data:
                name=data['name']
                print("Player",name,"connected with key: ",data['pubkey'])
                self.players += [name]
                self.conn[name]=conn
                self.addr[name]=addr
            
            if len(self.players)==self.nplayers:
                print("Lobby is full")
                break
                
    def givePiece(self,player):
        time.sleep(0.5)
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
        
        #print("deck ->",self.deck,"\n")
        input("Press a key to START")
        
        for i in range(self.startpieces): 
            for player in self.players:
                msg = {"key": self.key}
                self.conn[player].sendall(pickle.dumps(msg))

                self.givePiece(player)              
                

                time.sleep(0.2)
                
        self.playGame()
                
    def playGame(self):
        
        running=1
        
        while running:
                
            passed=0
            count = 0
            for player in self.players:
                for each in self.players:

                    count+=1
                    msg = {'isitok' : 'isitok', 'tableRefresh': self.table}
                    time.sleep(0.2)
                    self.conn[each].sendall(pickle.dumps(msg))
                    print("Is it ok?")

                    data = pickle.loads(self.conn[each].recv(4096))

                    if 'gamestate' in data:
                        if data['gamestate'] == 'iwin':
                            print("The winner is",each)
                            print("Game Ended.")                        
                            running = 0
                            self.s.close()
                            exit()
                        elif data['gamestate'] == 'batota':
                            print("Batota")
                            print("Game Ended.")                        
                            running = 0
                            self.s.close()
                            exit()
                        elif data['gamestate'] == 'ok':
                            print("Tudo Ok")
                        else:
                            print("Nothing hapened")   

                    if count == 3:
                        count = 0
                        break


                print("\n-----------------------")
                print("Table ->",self.table)
                #print("Deck ->",self.deck)
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
                
                if 'played' in data:
                    self.table=data['played']
                    print("Piece played.")
                    print("Table ->",self.table)

                if 'pass' in data:
                    print("Passed.")
                    passed=passed+1
                
                if 'pubkey' in data:
                    #RSA
                    encryptor = PKCS1_OAEP.new(data['pubkey'])
                    encrypted = encryptor.encrypt(encrypted)
                    print(encrypted)
                    
                time.sleep(0.1)
                        
            if passed==3:
                print("It's a DRAW")
                print("Game Ended")
                running = 0
                self.s.close()
                exit()
            
sv = Server()

sv.startGame()

#conn.close()