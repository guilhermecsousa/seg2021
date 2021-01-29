import socket
import time
import sys
import random
import string
import pickle
import crypt
import collections
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pickle
from cryptography.fernet import Fernet
import base64
from base64 import b64encode, b64decode
import json
import time
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class Player:
  
    def __init__(self):
    
        self.hand=[]
        self.table=[]
        self.cheating = 100 #0-100%
        self.played=[]
        self.serverkey = None
        self.authenticated = False

        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
        else:
            self.name =''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 25563))

        if self.authenticated:
            pass

        else:
            # RSA
            print("Generating private and public key...")
            self.private_key = RSA.generate(4096)
            self.public_key = self.private_key.publickey().export_key()
            print("Done")

            msg = {"name": self.name, "pubkey": self.public_key}
            self.s.sendall(pickle.dumps(msg))
            print("You connected with name",self.name)
        
        while 1:
            print("\n-----------",self.name,"---------------")
            print("Esperando")
            data = pickle.loads(self.s.recv(16384))
            print(data)
            if 'key' in data:
                print("recebi chave")
                self.serverkey = data['key']
                print("chave: ",self.serverkey)

            print("Recebi")
            if 'piece' in data:
                start = time.time()
                print("Entrei")
                print("My hand: ",self.hand)
                print("Table ->",self.table)

                print("Entra decrypt")

                # AES Fernat Decrypt
                f = Fernet(self.serverkey)
                cipheredtext = data['piece']
                cleartext = f.decrypt(cipheredtext)
                undecodedtext = base64.b64decode(cleartext)
                finalPiece = json.loads(undecodedtext.decode())
                
                
                print("finalPiece: ", finalPiece)
                self.hand.append(finalPiece)

                print("Received a piece.")
                print("My hand: ",self.hand)
                print("Table ->",self.table)

                end = time.time()
                print(end - start)
            elif 'play' in data:
                print("Nao entrei")
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
                    msg={'gamestate': 'iwin'}
                    self.s.sendall(pickle.dumps(msg))
                    print("Winner winner chicken dinner.")

            elif 'isitok' in data:
                self.table=data['tableRefresh']
                print("tou no itisok")
                if self.detectCheating() == True:
                    print("It is not ok!")
                    msg = {'gamestate' : 'batota'}
                    self.s.sendall(pickle.dumps(msg))
                else:
                    print("It is ok!")
                    msg = {'gamestate' : 'ok'}
                    time.sleep(0.1)
                    self.s.sendall(pickle.dumps(msg))

            elif 'shuffleSign' in data:
                #Player will shuffle deck and sign with private
                shuffledSignedDeck = []
                for each in data['deck']:

                
                    # Signature: https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_v1_5.html
                    h = SHA256.new(each)
                    signedPiece = pkcs1_15.new(self.private_key).sign(h)
                
                    shuffledSignedDeck += [signedPiece]

                    print("everyday I'm shuffling")

                    random.shuffle(shuffledSignedDeck)

                    msg = {'shuffleSign' : 'shuffleSign', 'deck': shuffledSignedDeck}
                    self.s.sendall(pickle.dumps(msg))

            else:
                print("nothing happened")
                                    
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
                    self.played.append(piece)
                elif piece[1]==first:
                    self.hand.remove(piece)
                    self.table=[piece]+self.table
                    played=1
                    self.played.append(piece)
                elif piece[0]==last:
                    self.hand.remove(piece)
                    self.table+=[piece]
                    played=1
                    self.played.append(piece)
                elif piece[1]==last:
                    self.hand.remove(piece)
                    self.table+=[[piece[1],piece[0]]]
                    played=1
                    self.played.append(piece)

                #Here we are giving the player a random chance to possibly cheat    
                elif (piece == self.hand[-1]) and (random.randint(0, 100) < self.cheating):
                    print("I'm gonna cheat heheeeeeeeeeeeeeeeeee <-----------------------------------")
                    self.hand.remove(piece)
                    piece = [last, first]
                    self.table+=[piece]
                    played=1
                    self.played.append(piece)
                    
                if played:
                    print("Played a piece:",piece)
                    break
                    
            if not played:
                print("I don't have a piece to play.")
                msg={'piece': 'piece'}
                self.s.sendall(pickle.dumps(msg))
                data = pickle.loads(self.s.recv(16384))
                if 'piece' in data:
                    
                    print("Entra decrypt")
                    # RSA decrypt
                    privateKey = RSA.import_key(open("private.pem").read())
                    decryptor = PKCS1_OAEP.new(privateKey)
                    decrypted = decryptor.decrypt(data['piece'])
                    print('Decrypted:', pickle.loads(decrypted))
                    self.hand+= [pickle.loads(decrypted)]
                    
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
                    

    def detectCheating(self):       #Our function to detect cheating
        duplicates = []
        cheater = False
        knownTiles = self.table + self.hand
        #print("Known Tiles: ", knownTiles)
        for x in knownTiles:
            reverseX = [x[1],x[0]]          
            if((knownTiles.count(x) > 1 and x not in self.played) or (knownTiles.count(reverseX) > 1 and reverseX not in self.played)):
                duplicates.append(x)
                cheater = True
        if(len(duplicates)>0):
            print("CHEATEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEER")
            print("duplicates: ", duplicates)
            return True
        return False


                    
p = Player()