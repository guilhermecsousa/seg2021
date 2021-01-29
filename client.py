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
        self.cheating = 0 #0-100%
        self.played=[]
        self.authenticated = False
        self.allkeys = []

        # Fernet key generation
        print("Generating symmetric key...")
        self.key = Fernet.generate_key()
        print("Done")

        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
        else:
            self.name =''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 25566))

        if self.authenticated:
            pass

        else:
            
            msg = {"name": self.name, "key": self.key}
            self.s.sendall(pickle.dumps(msg))
            print("You connected with name",self.name)
        
        while 1:
            print("\n-----------",self.name,"---------------")
            print("Esperando")
            data = pickle.loads(self.s.recv(131072))

            # Public keys of all players
            if 'player_keys' in data:
                self.allkeys = data['player_keys']
                print(self.allkeys)
                msg={'Recebi': 'Recebi'}
                self.s.sendall(pickle.dumps(msg))

                
            if 'key' in data:
                print("recebi chave")
                self.serverkey = data['key']
                print("chave: ",self.serverkey)

            print("Recebi")
            if 'piece' in data:
                print(data)
                start = time.time()
                print("Entrei")
                print("My hand: ",self.hand)
                print("Table ->",self.table)

                print("Entra decrypt")
                

                # AES Fernat Decrypt
                cipheredtext = data['piece']
                for keys in reversed(self.allkeys[1:]):
                    print(keys)
                    f = Fernet(keys)
                    cleartext = f.decrypt(cipheredtext)
                    cipheredtext = cleartext
                    print("CipheredText = ",cipheredtext)  

                f = Fernet(self.allkeys[0])
                cleartext = f.decrypt(cipheredtext)
                cipheredtext = base64.b64decode(cleartext)
                #cipheredtext = cleartext
                cleartext = cleartext.decode()
                print("Cleartext = ", cleartext)


                # AES Fernat Decrypt

                
                # f = Fernet(self.allkeys[3])
                # cleartext = f.decrypt(cipheredtext)
                # cipheredtext = cleartext
                # print("CipheredText = ",cipheredtext)
                
                
                # f = Fernet(self.allkeys[2])
                # cleartext = f.decrypt(cipheredtext)
                # cipheredtext = cleartext
                # print("CipheredText = ",cipheredtext)

                
                # f = Fernet(self.allkeys[1])
                # cleartext = f.decrypt(cipheredtext)
                # cipheredtext = cleartext
                # print("CipheredText = ",cipheredtext)
                

                # f = Fernet(self.allkeys[0])
                # cleartext = f.decrypt(cipheredtext)
                # cipheredtext = base64.b64decode(cleartext)
                # #cipheredtext = cleartext
                # cleartext = cleartext.decode()
                # print("Cleartext = ", cleartext)
                


                finalPiece = json.loads(cipheredtext.decode())
                print(finalPiece)
                
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

            elif 'shuffleEnc' in data:
                #Player will shuffle deck and sign with private
                shuffledSignedDeck = []
                for each in data['deck']:
                   
                    # Fernet AES 
                    f = Fernet(self.key)
                    encrypted = f.encrypt(each)
                    shuffledSignedDeck += [encrypted]

                #print(shuffledSignedDeck)
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
                msg={'ask': 'ask'}
                self.s.sendall(pickle.dumps(msg))
                print('pedi uma peça')
                data = pickle.loads(self.s.recv(131072))
                if 'piece' in data:
                    # # Client asks for deck
                    # msg={'showdeck': 'showdeck'}
                    # self.s.sendall(pickle.dumps(msg))
                    print(data)
                    start = time.time()
                    print("Entrei")
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)

                    print("Entra decrypt")
                    # AES Fernat Decrypt
                    cipheredtext = data['piece']
                    for keys in reversed(self.allkeys[1:]):
                        print(keys)
                        f = Fernet(keys)
                        cleartext = f.decrypt(cipheredtext)
                        cipheredtext = cleartext
                        print("CipheredText = ",cipheredtext)  

                    f = Fernet(self.allkeys[0])
                    cleartext = f.decrypt(cipheredtext)
                    cipheredtext = base64.b64decode(cleartext)
                    cleartext = cleartext.decode()
                    print("Cleartext = ", cleartext)

                    finalPiece = json.loads(cipheredtext.decode())
                    print(finalPiece)
                    
                    print("finalPiece: ", finalPiece)
                    self.hand.append(finalPiece)

                    print("Received a piece.")
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)

                    end = time.time()
                    print(end - start)
                    
                if 'nopiece' in data:
                    msg = {'pass': 'pass'}
                    self.s.sendall(pickle.dumps(msg))
                    print("Passed.")
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)

                if 'tiles' in data:
                    print('ENTROU TILES')
                    print('Tiles -> ',data['tiles'])
                    index = random.randint(0,len(data['tiles'])-1)
                    print('INDEX: ', index)
                    msg = {'choose': index}
                    self.s.sendall(pickle.dumps(msg))
                    

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