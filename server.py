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
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class Server:
    
    def __init__(self):
    
        self.deck = []    
        self.nplayers = 3
        self.startpieces = 5
        self.players = []
        self.table = []
        self.conn = {}
        self.addr = {}

        # symmetric key generation using the Fernet cipher
        print("Generating symmetric key...")
        self.key = Fernet.generate_key()
        print("Done")

        # # RSA to generate server public and private key
        # print("Generating private and public key...")
        # self.private_key = RSA.generate(4096)
        # self.public_key = self.private_key.publickey().export_key()
        # print("Done")        
        

        if len(sys.argv) >= 2:
            self.nplayers = sys.argv[1]

        # cifra das peças
        for i in range(7):
            for j in range(i,7):
                msg = [i,j]
                #print(msg)
                msg = str(msg).encode()

                # Fernet AES Encrypt
                f = Fernet(self.key)
                encrypted = base64.b64encode(msg)
                encrypted = f.encrypt(encrypted)
                
                # Signature: 
                # h = SHA256.new(encrypted)
                # signedPiece = pkcs1_15.new(self.private_key).sign(h)
                
                self.deck += [encrypted]

        #print(self.deck)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('localhost', 25566))
        
        print("Waiting for players...\n")
        
        allkeys = [self.key]
        while 1:
            self.s.listen(1)
            conn, addr = self.s.accept()
            data = pickle.loads(conn.recv(131072))
            
            # Append public keys of all players
            if 'key' in data:
                if data['key'] not in allkeys:
                    allkeys.append(data['key'])
                    
            if 'name' in data:
                name=data['name']
                key = data['key']
                print("Player",name, "connected with key: ",key)
                self.players += [name] #,data['pubkey']
                self.conn[name]=conn
                self.addr[name]=addr
            
            print("length players: ",len(self.players))
            
            if len(self.players)==self.nplayers:
                print("entrei")
                temp=0
                for each in self.players:
                    temp+=1
                    msg = {'player_keys': allkeys}
                    self.conn[each].sendall(pickle.dumps(msg))
                    data = pickle.loads(self.conn[each].recv(131072))                    



                    if temp == 0:
                        pass
                    else:
                        msg = {'shuffleEnc' : 'shuffleEnc', 'deck': self.deck}
                        #print(player_keys)

                        print("Gonna send deck to shuffle")

                        self.conn[each].sendall(pickle.dumps(msg))
                        
                        data = pickle.loads(self.conn[each].recv(131072))                    
                        print("Deck shuffled and encrypted by: ",each)
                        self.deck = data['deck']
                    

                print("Lobby is full")
                break
        if 'deck' in data:
            self.deck = data['deck']
                
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

                    data = pickle.loads(self.conn[each].recv(131072))

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
                data = pickle.loads(self.conn[player].recv(131072))
                                 
                if 'ask' in data:
                    tile = '[ : ]'
                    tiles = []
                    for x in self.deck:
                        tiles.append(tile)
                    print("TILEEEEEES: ", tiles)
                    if len(tiles) > 0 :
                        print('há peças')
                        msg = {'tiles' : tiles}
                        self.conn[player].sendall(pickle.dumps(msg))
                    else:
                        print('não há peças')
                        msg = {'notiles' : 'notiles'}
                        self.conn[player].sendall(pickle.dumps(msg))

                    # self.givePiece(player)
                    # time.sleep(0.1)
                    # data = pickle.loads(self.conn[player].recv(131072))
                
                if 'choose' in data:
                    print(data['choose'])
                    piece = self.deck.pop(data['choose'])
                    print('escolhi a peça', piece)
                    msg = {"piece": piece}
                    self.conn[player].sendall(pickle.dumps(msg))
                    print("Piece given.")

                if  'played' in data:
                    self.table=data['played']
                    print("Table ->",self.table)

                if 'pass' in data:
                    print("Passed.")
                    passed=passed+1
                                
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