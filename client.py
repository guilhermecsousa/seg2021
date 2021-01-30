import socket
import time
import sys
import random
import string
import pickle
import crypt
import platform
import collections
import base64
import json
import Crypto
import pprint
from PyKCS11 import *
from PyKCS11.LowLevel import *
from Crypto.Cipher import PKCS1_OAEP
from OpenSSL import crypto as openssl
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ( padding , rsa , utils)
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key, load_pem_public_key

class Player:
  
    def __init__(self):
    
        self.hand=[]
        self.table=[]
        self.cheating = 0 #0-100%
        self.played=[]
        self.allkeys = []
        self.rsa_private = None
        self.rsa_public = None 
        self.server_pubkey = None
        self.other_players = [] 
        self.aes_key = None
        self.bitCommit = []

        #Create name
        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
        else:
            self.name =''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
        # Connect to socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 25567))

        ############################################# BRUNO ##################################################################################

        # GENERATE RSA PUBLIC AND PRIVATE KEYS 
        self.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048) 
        self.rsa_public = self.rsa_private.public_key()

        #cc = str(input("Use Citizen Card? (y/n)"))
        cc = "n"
        
        if cc == "y":
        
            # certificate user... if somethings wrong about CC, exit program
            lib = '/usr/local/lib/libpteidpkcs11.so'
            if  platform.system() == "Darwin":
                lib = '/usr/local/lib/libpteidpkcs11.dylib'
        
            pkcs11 = PyKCS11.PyKCS11Lib() 
            pkcs11.load(lib)
            slots = pkcs11.getSlotList()
            classes = {
                CKO_PRIVATE_KEY : 'private key', 
                CKO_PUBLIC_KEY  : 'public key', 
                CKO_CERTIFICATE : 'certificate'
            }

            certlist = []
            
            for slot in slots:
                if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
                    session = pkcs11.openSession(slot)
                    objects = session.findObjects()
                    
                    for obj in objects:
                        l  = session.getAttributeValue(obj, [CKA_LABEL])[0]
                        c  = session.getAttributeValue(obj, [CKA_CLASS])[0]
                        cf = session.getAttributeValue(obj, [CKA_VALUE], True)[0]
                        
                        if classes[c] == 'certificate':
                            cert = openssl.load_certificate(openssl.FILETYPE_ASN1, bytes(cf)) # DER-Encoded -> OpenSSL
                            cert = openssl.dump_certificate(openssl.FILETYPE_PEM, cert) # OpenSSL -> PEM 
                            certlist += [cert]
            
            privKey = session.findObjects( [( CKA_CLASS , CKO_PRIVATE_KEY ) ,( CKA_LABEL , 'CITIZEN AUTHENTICATION KEY' )])[0] 

            msg = {
                "name": self.name, 
                "cc_auth" : True, 
                "certs" : certlist,
                "rsa_public" : self.rsa_public.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)   
            }
            msg.update({"sign" : bytes(session.sign(privKey, pickle.dumps(msg), Mechanism(CKM_SHA1_RSA_PKCS)))}) 
            self.s.sendall(pickle.dumps(msg))  

            d = []
            while 1:
                packet = self.s.recv(4096)
                d.append(packet)
                if len(packet) < 4096: break
            data = pickle.loads(b"".join(d))
            
            if "same_auth" in data:
                print(data['same_auth'])
                exit()
            
            if "verification_failed" in data:
                print(data['verification_failed'])
                exit()

            if "cert_not_trusted" in data:
                print(data["cert_not_trusted"])
                exit()

            if "server_pubkey" in data:
                self.server_pubkey = load_pem_public_key(data['server_pubkey'], default_backend())  
            
            try:
                self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                                         salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
            except:
                print("Signature error: Server is not trusted, exiting...")
                exit()   
            
            #generate AES key. 
            random_key = Fernet.generate_key() 

            # f = Fernet(random_key)
            # encrypted = f.encrypt(base64.b64encode(mensagem))
            # decrypted = f.decrypt(ciphertext)
            #undecode = base64.b64decode(decrypted)

            # send AES key
            msg = {
                "AESkey" : self.server_pubkey.encrypt(random_key, padding.PKCS1v15())    
            }
            msg.update({ 
                "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                  salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
            }) 
            self.s.sendall(pickle.dumps(msg)) 

            self.aes_key = random_key
        
        else :
            #send RSA to server 
            msg = {
                "name": self.name, 
                "cc_auth" : False,
                "rsa_public" : self.rsa_public.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)  
            } 
            msg.update({
                "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                  salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
            })

            self.s.sendall(pickle.dumps(msg))  

            #receive server RSA 
            d = []
            while 1:
                packet = self.s.recv(4096)
                d.append(packet)
                if len(packet) < 4096: break
            data = pickle.loads(b"".join(d)) 
            
            try:
                if "server_pubkey" in data:
                    self.server_pubkey = load_pem_public_key(data['server_pubkey'], default_backend())  
                self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                                              salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
            except:
                print("Signature error: Server is not trusted, exiting...")
                exit()
            
            #generate AES key. 
            random_key = Fernet.generate_key() 
 
            #send AES 
            msg = {
                "AESkey" : self.server_pubkey.encrypt(random_key, padding.PKCS1v15())  
            }
            msg.update({
                "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                  salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
            })
            self.s.sendall(pickle.dumps(msg))   

            self.aes_key = random_key

        print("You connected with name",self.name)

        #receive data players, name
        d = []
        while 1:
            packet = self.s.recv(4096)
            d.append(packet)
            if len(packet) < 4096: break
        data = pickle.loads(b"".join(d))  

        if 'other_players' in data:
            self.other_players = data['other_players']
    
        print(self.other_players)  

        ##################################################################################################################################################

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
                    f = Fernet(self.aes_key)
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

                
                self.bitCommit.append([data['piece']])
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
                print("Player that made an action: ",data['whoPlayed'])
                self.allPlays = data['allPlays']
                #for each in self.allPlays:
                    #print(each)
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

                #print("Data received after saying 'ask': ", data)
                
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
                
                if 'play' in data: 
                    print("I don't have a piece to play.")
                    msg={'ask': 'ask'}
                    self.s.sendall(pickle.dumps(msg))
                    data = pickle.loads(self.s.recv(131072))
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