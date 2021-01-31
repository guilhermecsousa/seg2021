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
from Crypto.Hash import SHA256
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
        self.lastBitCommit = None

        #Create name
        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
        else:
            self.name =''.join(random.choices(string.ascii_uppercase + string.digits, k=4)) 
    
        # Connect to socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 25565))

        # GENERATE RSA PUBLIC AND PRIVATE KEYS 
        self.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048) 
        self.rsa_public = self.rsa_private.public_key()

        cc = str(input("Use Citizen Card? (y/n)"))
        
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
            self.other_players = pickle.loads(Fernet(self.aes_key).decrypt(data['other_players'])) 
            try:
                self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            except:
                print("Verification other players FAILED. ")   


        # send message to player saying hello
        self.s.sendall(pickle.dumps({
                'to' : self.other_players[random.randrange(0, len(self.other_players))],  
                'from' : self.name,
                'msg' : 'Hello' 
            }))  


        while 1:
            print("\n-----------",self.name,"---------------")
            # Waiting for all the players to connect and the server starts the game
            #print("Waiting...")
            data = pickle.loads(self.s.recv(131072))
          
            if 'to' in data:
             print("Mensagem: ", data) 

            # Encrypt and shuffle deck 
            if 'shuffleEnc' in data:
                shuffleDeck = []
                decrypted_deck = []
                try:
                    decrypted_deck = data['deck']
                    self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                except:
                    print("******** verification of Deck failed **************")

                for each in decrypted_deck:  
                   
                    # Fernet AES Encryption
                    f = Fernet(self.aes_key)
                    encrypted = f.encrypt(each) 
                    shuffleDeck += [encrypted]

                # Shuffling
                print("I'm shuffling the deck")
                random.shuffle(shuffleDeck) 

                # Sends shuffled deck
                msg = {
                    'deck': shuffleDeck
                }
                msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})    
                self.s.sendall(pickle.dumps(msg))   
       

            # Store the keys from other players and server, to decrypt 
            if 'player_keys' in data:
                try:
                    self.allkeys = pickle.loads(Fernet(self.aes_key).decrypt(data['player_keys'])) 
                    self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                except:
                    print("******************* Verification player_keys failed ******************") 

                # msg={
                #     'GotAllKeys': Fernet(self.aes_key).encrypt(pickle.dumps('GotAllKeys'))      
                # } 
                # msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                #                                                                     salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})  
                # self.s.sendall(pickle.dumps(msg))   
                 
            if 'gameOver' in data:
                try:
                    decrypt_GameOveer = pickle.loads(Fernet(self.aes_key).decrypt(data['gameOver'])) 
                    self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
                except:
                    print("******************** verify of game over failed *******************") 
                #print(decrypt_GameOveer)    
 

            bitCommit = None

            # Decrypt first with players keys and then with server key
            if 'piece' in data and 'midgamePiece' not in data:  
                try:
                    self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                except:
                    print(" ******************** verification of piece failed. **********************") 

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
                
                hash_object = SHA256.new(bytes(finalPiece))
                bitCommit = hash_object.hexdigest()
                    
                #print("bitCommit :",bitCommit)
                self.lastBitCommit = bitCommit 

                print("My hand: ",self.hand)
                print("Table ->",self.table)

                # Informes server if the piece was correctly received
                msg = {
                    'gamestate' : Fernet(self.aes_key).encrypt(pickle.dumps('ok')), 
                    'allok' : Fernet(self.aes_key).encrypt(pickle.dumps('Player stated the piece was received')), 
                    'commit': Fernet(self.aes_key).encrypt(pickle.dumps(bitCommit))  
                }  
                msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())}) 
                self.s.sendall(pickle.dumps(msg))
                
                end = time.time()   

            if 'midgamePiece' in data and 'piece' in data:  
                start = time.time()
                cipheredtext = data['piece']
                for keys in reversed(self.allkeys[1:]):
                    f = Fernet(keys)
                    cleartext = f.decrypt(cipheredtext)
                    cipheredtext = cleartext

                # AES Fernat Decrypt (Server)
                f = Fernet(self.allkeys[0])
                cleartext = f.decrypt(cipheredtext)
                cipheredtext = base64.b64decode(cleartext)
                cleartext = cleartext.decode()
                
                # Appends decrypted piece to players hand
                finalPiece = json.loads(cipheredtext.decode())
                self.hand.append(finalPiece)

                hash_object = SHA256.new(bytes(finalPiece))
                bitCommit = hash_object.hexdigest()
                
                self.lastBitCommit = bitCommit

                print("Received a piece.")
                print("My hand: ",self.hand)

                # Informes server if the piece was correctly received
                msg = {
                    'gamestate' : Fernet(self.aes_key).encrypt(pickle.dumps('ok')), 
                    'allok': Fernet(self.aes_key).encrypt(pickle.dumps('Player stated the piece was received')), 
                    'commit' : Fernet(self.aes_key).encrypt(pickle.dumps(bitCommit))
                }  
                msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})  
                self.s.sendall(pickle.dumps(msg))

                end = time.time()
            
            # Game
            if 'play' in data:
                try:
                    self.table = pickle.loads(Fernet(self.aes_key).decrypt(data['play']))
                    print(self.table)
                    self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                except:
                    print("***************** verification of play failed *********************")   

                print("My hand: ",self.hand)  
                print("Table ->",self.table) 
                self.playPiece()
                msg = {
                    'played' : Fernet(self.aes_key).encrypt(pickle.dumps(self.table)),
                    'commit' : Fernet(self.aes_key).encrypt(pickle.dumps(self.lastBitCommit))   
                }    
                msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})  
                self.s.sendall(pickle.dumps(msg))  
                print("My hand: ",self.hand)
                print("Table ->",self.table)
                # Winning condition 
                if len(self.hand)==0:
                    msg={
                        'gamestate': Fernet(self.aes_key).encrypt(pickle.dumps('iwin')),
                        "WhatIPlayed" : Fernet(self.aes_key).encrypt(pickle.dumps(self.played))
                    }
                    msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})  
                    self.s.sendall(pickle.dumps(msg))  
                    print("I won.")

            # Check if cheating
            if 'isitok' in data:
                try:
                    decrypt_isitok = pickle.loads(Fernet(self.aes_key).decrypt(data['isitok']))
                    decrypt_tableRefresh = pickle.loads(Fernet(self.aes_key).decrypt(data['tableRefresh'])) 
                    decrypt_whoPlayed = pickle.loads(Fernet(self.aes_key).decrypt(data['whoPlayed']))
                    decrypt_allPlays = pickle.loads(Fernet(self.aes_key).decrypt(data['allPlays']))
                    self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                except:
                    print("******************** verification of isitok failed ********************")

                self.table=decrypt_tableRefresh
                print("Player that made an action: ",decrypt_whoPlayed)
                self.allPlays = decrypt_allPlays 
                    
                if len(self.hand)==0:
                    msg={
                        'gamestate': Fernet(self.aes_key).encrypt(pickle.dumps('iwin')), 
                        "WhatIPlayed" : Fernet(self.aes_key).encrypt(pickle.dumps(self.played)) 
                    }
                    msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})  
                    self.s.sendall(pickle.dumps(msg)) 
                if self.detectCheating() == True:
                    print("Malicious activity detected!")
                    msg = {
                        'gamestate' : Fernet(self.aes_key).encrypt(pickle.dumps('Cheat')),
                        'pad' : None
                    }
                    msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})    
                    self.s.sendall(pickle.dumps(msg)) 
                else:
                    print("Current table: ",self.table)
                    msg = {
                        'gamestate' : Fernet(self.aes_key).encrypt(pickle.dumps('ok'))
                    }
                    msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})     
                    time.sleep(0.1)
                    self.s.sendall(pickle.dumps(msg))    

            else:
                pass 
                                    
    def playPiece(self):

        played=0
        
        if self.table==[]:
            piece = self.hand.pop(random.randint(0,len(self.hand)-1))
            self.table += [piece]
            self.played.append(piece)

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
                msg={
                    'ask': Fernet(self.aes_key).encrypt(pickle.dumps('ask'))
                }
                msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})   
                self.s.sendall(pickle.dumps(msg))     
                
                time.sleep(0.2) 
                data = pickle.loads(self.s.recv(131072))  

                
                # If there is any, choose one
                if 'tiles' in data:
                    try:
                        decrypt_tiles1 = pickle.loads(Fernet(self.aes_key).decrypt(data['tiles']))
                        self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
                    except:
                        print("*************** verification of tiles faled *******************")

                    print('Tiles -> ',decrypt_tiles1) 
                    index = random.randint(0,len(decrypt_tiles1)-1)
                    msg = {
                        'choose': Fernet(self.aes_key).encrypt(pickle.dumps(index))
                    }
                    msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})   
                    time.sleep(0.2)
                    self.s.sendall(pickle.dumps(msg))  
                    
                # If it does not exist,
                if 'notiles' in data:
                    try:
                        self.server_pubkey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
                    except:
                        print("**************** verify of notiles failed *****************")  
                    
                    msg = {
                        'pass': Fernet(self.aes_key).encrypt(pickle.dumps('Passed.'))
                    }
                    msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})         
                    self.s.sendall(pickle.dumps(msg))   
                    print("Passed.")
                    print("My hand: ",self.hand)
                    print("Table ->",self.table)
                
                if 'play' in data: 
                    print("I don't have a piece to play.")
                    msg={
                        'ask' : Fernet(self.aes_key).encrypt(pickle.dumps('ask'))
                    }
                    msg.update({ "sign" : self.rsa_private.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())}) 
                    self.s.sendall(pickle.dumps(msg))
                    data = pickle.loads(self.s.recv(131072))
                
                            
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