import random
import string
import socket
import sys
import time
import pickle
import crypt
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def createKey(): 
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("public.pem", "wb")
    file_out.write(public_key)
    file_out.close()

class Server:

    createKey()

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
        cipherDeck = []
        for i in range(0,len(self.deck)):
            msg = pickle.dumps(self.deck[i])
            pubKey = RSA.import_key(open("public.pem").read())
            encryptor = PKCS1_OAEP.new(pubKey)
            encrypted = encryptor.encrypt(msg)
            cipherDeck.append(encrypted)
        self.deck = cipherDeck          

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
        
        print("START GAME deck ->",self.deck,"\n")
        input("Press a key to START")
        
        for i in range(self.startpieces): 
            for player in self.players:
                self.givePiece(player)
                time.sleep(0.1)
                
        self.playGame()
                
    def playGame(self):
        
        running=1
        
        while running:
                
            passed=0
            
            for player in self.players:
           
                print("\n-----------------------")
                print("Table ->",self.table)
                print("RUNNING Deck ->",self.deck)
                print("To play ->",player)
                msg={'play': self.table}
                self.conn[player].sendall(pickle.dumps(msg))
                data = pickle.loads(self.conn[player].recv(4096))
                print("are you here?")
                if 'piece' in data:
                    print("piece")
                    self.givePiece(player)
                    data = pickle.loads(self.conn[player].recv(4096))
                    # while 'piece' in data:
                    #     self.givePiece(player)
                    #     time.sleep(0.1)
                    #     data = pickle.loads(self.conn[player].recv(4096))
                    print("PIECE Deck ->",self.deck)
                if 'played' in data:
                    print("played")
                    self.table=data['played']
                    print("Piece played.")
                    print("Table ->",self.table)    
                if 'pass' in data:
                    print("pass")
                    print("Passed.")
                    passed=passed+1
                if 'iwin' in data:
                    print("iwin")
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