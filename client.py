import socket
import time
import sys
import random
import string
import pickle
import crypt
import collections
import base64
import json
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP

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

        #Create name
        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
        else:
            self.name =''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
        # Connect to socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 25567))

        # CC Version
        if self.authenticated:
            pass

        # No CC Version
        else: 
            msg = {"name": self.name, "key": self.key}
            self.s.sendall(pickle.dumps(msg))
            print("You connected with name",self.name)
        
        while 1:
            print("\n-----------",self.name,"---------------")
            # Waiting for all the players to connect and the server starts the game
            print("Waiting...")
            data = pickle.loads(self.s.recv(131072))
          

            # Encrypt and shuffle deck 
            if 'shuffleEnc' in data:
                shuffleDeck = []
                for each in data['deck']:
                   
                    # Fernet AES Encryption
                    f = Fernet(self.key)
                    encrypted = f.encrypt(each)
                    shuffleDeck += [encrypted]

                # Shuffling
                print("I'm shuffling the deck")
                random.shuffle(shuffleDeck)

                # Sends shuffled deck
                msg = {'deck': shuffleDeck}
                self.s.sendall(pickle.dumps(msg))


            # Store the keys from other players and server, to decrypt 
            if 'player_keys' in data:
                self.allkeys = data['player_keys']
                msg={'GotAllKeys': 'GotAllKeys'}
                self.s.sendall(pickle.dumps(msg))
            
            # Inicial distribution
            # Decrypt first with players keys and then with server key
            if 'piece' in data:
                start = time.time()
                print("My hand: ",self.hand)
                print("Table ->",self.table)

                
                print("Received a piece:")
                # AES Fernet Decrypt (Players)
                cipheredtext = data['piece']
                for keys in reversed(self.allkeys[1:]):
                    f = Fernet(keys)
                    cleartext = f.decrypt(cipheredtext)
                    cipheredtext = cleartext

                # AES Fernet Decrypt (Server)
                f = Fernet(self.allkeys[0])
                cleartext = f.decrypt(cipheredtext)
                cipheredtext = base64.b64decode(cleartext)
                cleartext = cleartext.decode()

                # Appends decrypted piece to hand
                finalPiece = json.loads(cipheredtext.decode())
                self.hand.append(finalPiece)
                
                print(finalPiece)

                print("My hand: ",self.hand)
                print("Table ->",self.table)

                # Informes server if the piece was correctly received
                msg = {'gamestate' : 'ok', 'allok' : 'allok'}
                self.s.sendall(pickle.dumps(msg))
                
                end = time.time()

                if 'midgamePiece' in data:
                    first=self.table[0][0]
                    last=self.table[len(self.table)-1][1]
                    for piece in self.hand:
                        # Game nuances
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

                    msg={'played': self.table}
                    self.s.sendall(pickle.dumps(msg))
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)
                    # Winning condition
                    if len(self.hand)==0:
                        msg={'gamestate': 'iwin'}
                        self.s.sendall(pickle.dumps(msg))
                        print("Winner winner chicken dinner.")


                #print(end - start) # Decyphering time
            
            # Game
            if 'play' in data:
                self.table=data['play']
                print("My hand: ",self.hand)
                print("Table ->",self.table)
                self.playPiece()
                msg={'played': self.table}
                self.s.sendall(pickle.dumps(msg))
                print("My hand: ",self.hand)
                print("Table ->",self.table)
                # Winning condition
                if len(self.hand)==0:
                    msg={'gamestate': 'iwin'}
                    self.s.sendall(pickle.dumps(msg))
                    print("Winner winner chicken dinner.")

            # Check if cheating
            if 'isitok' in data:
                self.table=data['tableRefresh']
                if self.detectCheating() == True:
                    print("Malicious activity detected!")
                    msg = {'gamestate' : 'batota'}
                    self.s.sendall(pickle.dumps(msg))
                else:
                    print("Current table: ",self.table)
                    msg = {'gamestate' : 'ok'}
                    time.sleep(0.1)
                    self.s.sendall(pickle.dumps(msg))

            else:
                pass
                                    
    def playPiece(self):

        played=0
        
        if self.table==[]:
            self.table += [self.hand.pop(random.randint(0,len(self.hand)-1))]
        else:
            first=self.table[0][0]
            last=self.table[len(self.table)-1][1]
            for piece in self.hand:
                # Game nuances
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

                # Giving the player a random chance to possibly cheat    
                elif (piece == self.hand[-1]) and (random.randint(0, 100) < self.cheating):
                    print("I will try to cheat now")
                    self.hand.remove(piece)
                    piece = [last, first]
                    self.table+=[piece]
                    played=1
                    self.played.append(piece)
                    
                if played:
                    print("Played a piece:",piece)
                    break
                    
            if not played:
                # If does not have a piece, asks for one
                print("I don't have a piece to play.")
                msg={'ask': 'ask'}
                self.s.sendall(pickle.dumps(msg))
                data = pickle.loads(self.s.recv(131072))
                
                # If there is any, choose one
                if 'tiles' in data:
                    print('Tiles -> ',data['tiles'])
                    index = random.randint(0,len(data['tiles'])-1)
                    msg = {'choose': index}
                    self.s.sendall(pickle.dumps(msg))

                # If it does not exist,
                if 'notiles' in data:
                    msg = {'pass': 'pass'}
                    self.s.sendall(pickle.dumps(msg))
                    print("Passed.")
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)

                # When he receives a piece, decrypts it with others players and server public keys 
                # and appends it to the players hand
                if 'piece' in data:
                    start = time.time()
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)

                    # AES Fernat Decrypt (Players)
                    cipheredtext = data['piece']
                    for keys in reversed(self.allkeys[1:]):
                        print(keys)
                        f = Fernet(keys)
                        cleartext = f.decrypt(cipheredtext)
                        cipheredtext = cleartext
                        print("CipheredText = ",cipheredtext)  

                    # AES Fernat Decrypt (Server)
                    f = Fernet(self.allkeys[0])
                    cleartext = f.decrypt(cipheredtext)
                    cipheredtext = base64.b64decode(cleartext)
                    cleartext = cleartext.decode()
                    print("Cleartext = ", cleartext)
                    
                    # Appends decrypted piece to players hand
                    finalPiece = json.loads(cipheredtext.decode())
                    self.hand.append(finalPiece)

                    print("Received a piece.")
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)

                    # Informes server if the piece was correctly received
                    msg = {'allok': 'allok'}
                    self.s.sendall(pickle.dumps(msg))

                    end = time.time()
                    #print(end - start) # Time to decrypt
                            
    #Function to detect cheating
    def detectCheating(self):       
        duplicates = []
        cheater = False
        knownTiles = self.table + self.hand
        for x in knownTiles:
            reverseX = [x[1],x[0]]          
            if((knownTiles.count(x) > 1 and x not in self.played) or (knownTiles.count(reverseX) > 1 and reverseX not in self.played)):
                duplicates.append(x)
                cheater = True
        if(len(duplicates)>0):
            print("There is a CHEATER among us!")
            print("Proof: ", duplicates)
            return True
        return False

p = Player()