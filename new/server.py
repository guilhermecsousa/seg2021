import random
import string
import socket
import sys
import time
import pickle
import crypt
import numpy as np
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Server:

    

    def __init__(self):
    
        key1 = RSA.generate(2048)
        
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
                msg = pickle.dumps([i,j])
                pubKey = RSA.import_key(open("public.pem").read())
                encryptor = PKCS1_OAEP.new(pubKey)
                encrypted = encryptor.encrypt(msg)
                self.deck += [encrypted]

        #print(self.deck)

        
            
                
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('localhost', 25566))
        
        print("Waiting for players...\n")
        
        while 1:
            self.s.listen(1)
            conn, addr = self.s.accept()
            data = pickle.loads(conn.recv(4096))
            if 'publica' in data:
                msg1 = data['publica']
                encryptor = PKCS1_OAEP.new(key1)
                encrypted = encryptor.encrypt(bytes(msg1))
                print("Encrypted:",encrypted)
                # aux = data['publica']
                # print(pickle.loads(aux))
                # encryptor1 = PKCS1_OAEP.new(aux)
                # encrypted1 = encryptor1.encrypt(key1)
                # print(encrypted1)
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
        
        #print("deck ->",self.deck,"\n")
        input("Press a key to START")
        
        for i in range(self.startpieces): 
            for player in self.players:
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
                    #print("Deck ->",self.deck)
                if 'played' in data:
                    self.table=data['played']
                    print("Piece played.")
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