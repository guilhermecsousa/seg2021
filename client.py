import random
import string
import socket
import sys
import time
import pickle
import crypt
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
class Player:
  
    def __init__(self):
    
        self.hand=[]
        self.table=[]

        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
        else:
            self.name =''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 25565))
        msg = {"name": self.name}
        self.s.sendall(pickle.dumps(msg))
        print("You connected with name",self.name)
        
        while 1:
            print("\n-----------",self.name,"---------------")
            data = pickle.loads(self.s.recv(4096))
            # if 'isitok' in data:
            #     print("It is OK!")


            if 'piece' in data:
                print("My hand: ",self.hand)
                print("Table ->",self.table)
                #print(data['piece'])
                privateKey = RSA.import_key(open("private.pem").read())
                decryptor = PKCS1_OAEP.new(privateKey)
                decrypted = decryptor.decrypt(data['piece'])
                print('Decrypted:', pickle.loads(decrypted))
                
                self.hand+= [pickle.loads(decrypted)]
                print("Received a piece.")
                print("My hand: ",self.hand)
                print("Table ->",self.table)
            elif 'play' in data:
                self.table=data['play']
                print("My hand: ",self.hand)
                print("Table ->",self.table)
                print("I have to play a piece.")
                self.playPiece()
                msg={'played': self.table}
                self.s.sendall(pickle.dumps(msg))
                print("My hand: ",self.hand)
                print("Table ->",self.table)
                if len(self.hand)==0:
                    msg={'iwin': 'iwin'}
                    self.s.sendall(pickle.dumps(msg))
                    print("Winner winner chicken dinner.")
                                    
    def playPiece(self):
    
        played=0
        
        if self.table==[]:
            self.table += [self.hand.pop(random.randint(0,len(self.hand)-1))]
        else:
            first=self.table[0][0]
            last=self.table[len(self.table)-1][1]
            for piece in self.hand:
            
                if piece[0]==first:
                    self.hand.remove(piece)
                    self.table=[[piece[1],piece[0]]]+self.table
                    played=1
                elif piece[1]==first:
                    self.hand.remove(piece)
                    self.table=[piece]+self.table
                    played=1
                elif piece[0]==last:
                    self.hand.remove(piece)
                    self.table+=[piece]
                    played=1
                elif piece[1]==last:
                    self.hand.remove(piece)
                    self.table+=[[piece[1],piece[0]]]
                    played=1
                    
                if played:
                    print("Played a piece:",piece)
                    break
                    
            if not played:
                print("I don't have a piece to play.")
                msg={'piece': 'piece'}
                self.s.sendall(pickle.dumps(msg))
                data = pickle.loads(self.s.recv(4096))
                if 'piece' in data:
                    self.hand+=[data['piece']]
                    print("Received a piece.")
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)
                    self.playPiece()
                    
                if 'nopiece' in data:
                    msg={'pass': 'pass'}
                    self.s.sendall(pickle.dumps(msg))
                    print("Passed.")
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)
                    
p = Player()