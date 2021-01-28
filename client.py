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

class Player:
  
    def __init__(self):
    
        self.hand=[]
        self.table=[]
        self.cheating = 100 #0-100%
        self.played=[]
        self.serverkey = None

        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
        else:
            self.name =''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 25567))
        msg = {"name": self.name}
        self.s.sendall(pickle.dumps(msg))
        print("You connected with name",self.name)
        
        while 1:
            print("\n-----------",self.name,"---------------")
            print("Esperando")
            data = pickle.loads(self.s.recv(4096))
            print(data)
            if 'key' in data:
                self.serverkey = data['key']

            print("Recebi")
            if 'piece' in data:
                print("Entrei")
                print("My hand: ",self.hand)
                print("Table ->",self.table)

                print("Entra decrypt")
                # with open('secure.pem', 'rb') as my_private_key:
                #     key = my_private_key.read()
        
                f = Fernet(self.serverkey)
                #cleartext = base64.urlsafe_ b64decode()
                cleartext = f.decrypt(data['piece'])
                cleartext = cleartext.decode()
                print(cleartext)
                
                # privateKey = RSA.import_key(open("private.pem").read())
                # decryptor = PKCS1_OAEP.new(privateKey)
                # decrypted = decryptor.decrypt(data['piece'])
                print('Decrypted:', pickle.loads(cleartext))
                
                self.hand+= [pickle.loads(decrypted)]

                print("Received a piece.")
                print("My hand: ",self.hand)
                print("Table ->",self.table)
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
                data = pickle.loads(self.s.recv(4096))
                if 'piece' in data:
                    
                    print("Entra decrypt")
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