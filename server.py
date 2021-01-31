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
import base64
import pprint
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class Server:
     
    def __init__(self):
    
        self.deck = []    
        self.nplayers = 3
        self.startpieces = 5
        self.players = {}
        self.table = []
        self.conn = {}
        self.winner = None
        self.cheat = None
        self.privkey = None
        self.pubkey = None
        self.allkeys = []
        self.allPlays = []
        self.allCommits = []
        self.games_history = {}
        self.games_counter = 0
        self.winnerPlayed = []

        # Deciding players number 
        if len(sys.argv) >= 2:
            self.nplayers = sys.argv[1]

        # Symmetric key generation using the Fernet cipher
        print("Generating symmetric key...")
        self.aes_key = Fernet.generate_key()
        self.allkeys.append(self.aes_key) 
        print("Done") 

        # Create channel for communication
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('localhost', 25565))
        print("Waiting for players...\n")

        #################################### BRUNO #############################################################################
        with open('server_privkey.pem', mode='rb') as f:
            key_data = f.read()
            self.privkey = load_pem_private_key(key_data, None, default_backend())

        with open('server_pubkey.pem', mode='rb') as f:
            key_data = f.read()
            self.pubkey = load_pem_public_key(key_data, default_backend()) 
        
        ########################################################################################################################
    def message(self):
        for name in self.players:
            d = []  
            while 1:
                packet = self.players[name]['conn'].recv(4096)
                d.append(packet)
                if len(packet) < 4096: break 
            data = pickle.loads(b"".join(d))

            print(data)

            # send message.
            if 'to' in data:
                self.players[data['to']]['conn'].sendall(pickle.dumps({
                    'to' : data['to'],
                    'from' : data['from'],
                    'msg' : data['msg']
                }))   
        
    def reset_configs(self):
        self.deck = []    
        self.allPlays = []
        self.allCommits = []
        self.startpieces = 5
        self.players = {}
        self.table = []
        self.conn = {}
        self.winner = None
        self.cheat = None
        self.allkeys = self.allkeys[:1]  

    def auth_players(self) :  
        # Initial communication loop for player acknowledgement and tiles preparation
        while 1:
            self.s.listen(1)
            conn, addr = self.s.accept()

            ############################################### BRUNO #########################################################################

            # receiving user data
            d = []
            while 1:
                packet = conn.recv(4096)
                d.append(packet)
                if len(packet) < 4096: break
            data = pickle.loads(b"".join(d))
            name_player = None
            flag_continue = True  

            if "cc_auth" in data: 

                # if user wants to sign in with cc
                if data["cc_auth"]:
                    pubKey = x509.load_pem_x509_certificate(data["certs"][0], default_backend()).public_key() #CITIZEN AUTHENTICATION CERTIFICATE   

                    #verify clients pubkey, if already exists in the game
                    for name in self.players:
                        if 'cc_pubkey' in self.players[name]:
                            if self.players[name]['cc_pubkey'].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)  \
                            == pubKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo):
                                msg = {
                                    "same_auth" : "There is already someone using the sabe authentication keys, disconnecting..."
                                }
                                msg.update({"sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})              
                                conn.sendall(pickle.dumps(msg))   
                                flag_continue = False
                    
                    try:
                        pubKey.verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}), padding.PKCS1v15(), hashes.SHA1())
                    except: 
                        msg = {
                            "verification_failed" : "Verification of your message failed, exiting..."
                        }
                        msg.update({"sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})             
                        conn.sendall(pickle.dumps(msg))
                        flag_continue = False 
                    
                    # Chain of Trust
                    subject_names = [x509.load_pem_x509_certificate(c, default_backend()).subject for c in data["certs"]]
                    validation1 = [False if x509.load_pem_x509_certificate(data['certs'][i], default_backend()).issuer not in subject_names[i+1:] else True for i in range(0, len(data['certs'])-1)] 
                    validation2 = [False if x509.load_pem_x509_certificate(data['certs'][-1], default_backend()).issuer != x509.load_pem_x509_certificate(data['certs'][-1], default_backend()).subject else True] 
                    if not all(validation1 + validation2): 
                        msg = {
                            "cert_not_trusted" : "Certification not trusted, exiting..."
                        }
                        msg.update({"sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})             
                        conn.sendall(pickle.dumps(msg))  
                        flag_continue = False   
                    
                    if flag_continue:  
                    
                        # save user after trusting... 
                        if 'name' in data:
                            name = data['name']
                            name_player = name
                            print("Player",name,"connected.")
                            self.players[name] = {'conn' : conn, "addr" : addr, "cc_pubkey" : pubKey, "rsa_public" : load_pem_public_key(data['rsa_public'], default_backend())}

                        # send server public key
                        msg = {
                            "server_pubkey" : self.pubkey.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
                        }
                        msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})
                        conn.sendall(pickle.dumps(msg))   
                    
                        #get AES from client
                        d = []  
                        while 1:
                            packet = conn.recv(4096)
                            d.append(packet)
                            if len(packet) < 4096: break 
                        data = pickle.loads(b"".join(d))

                        if "AESkey" in data:
                            try:
                                k = self.privkey.decrypt(data['AESkey'], padding.PKCS1v15())
                                self.players[name_player].update({'aes_key' : k}) 
                                if k not in self.allkeys:
                                    self.allkeys.append(k)
                                self.players[name_player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                            except: 
                                print("Verification of AESkey failed.")
                        
                        print("user registed")  
    
                else :
                    # save user 
                    if 'name' in data:
                        try:
                            name = data['name']
                            name_player = name
                            print("Player",name,"connected.")
                            self.players[name] = {'conn' : conn, "addr" : addr, "rsa_public" : load_pem_public_key(data['rsa_public'], default_backend())} 
                            self.players[name_player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                        salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                        except:
                            print("Verification of user {} failed".format(name_player))    
                    
                    # send server public key
                    msg = {
                        "server_pubkey" : self.pubkey.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    }
                    msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})
                    conn.sendall(pickle.dumps(msg))    
 
                    # receive AES 
                    #get AES from client
                    d = []  
                    while 1:
                        packet = conn.recv(4096)
                        d.append(packet)
                        if len(packet) < 4096: break 
                    data = pickle.loads(b"".join(d))

                    if "AESkey" in data:
                        try:
                            k = self.privkey.decrypt(data['AESkey'], padding.PKCS1v15())
                            self.players[name_player].update({'aes_key' : k}) 
                            if k not in self.allkeys:
                                self.allkeys.append(k)
                            self.players[name_player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                        except:  
                            print("Verification of AESkey failed.")
                    
                    print("user registed")    
        
            #####################################################################################################################################################################################################
            
            # Check if lobby is full
            if len(self.players)==self.nplayers:

                # send other_players to every player in game. 
                for name, values in self.players.items():
                    list_players = list(self.players.keys())
                    list_players.remove(name)
                    msg = {
                        "other_players" : Fernet(values['aes_key']).encrypt(pickle.dumps(list_players))   
                    }
                    msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})
                    values['conn'].sendall(pickle.dumps(msg))    
                
                self.message()

                # Create and encrypt pieces
                for i in range(7):
                    for j in range(i,7):
                        msg = [i,j]
                        msg = str(msg).encode()

                        # Fernet AES Encrypt
                        f = Fernet(self.aes_key)
                        encrypted = base64.b64encode(msg)
                        encrypted = f.encrypt(encrypted)
                        
                        #Add encrypted pieces to deck
                        self.deck += [encrypted] 

                temp=0

                # Going to rotate the deck so that all players can encrypt on top
                for each in self.players: 
                    #print(self.deck)
                    #Sending deck                    
                    msg = {
                        'shuffleEnc' : 'shuffleEnc', 
                        'deck': self.deck 
                    }
                    msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})   
                    print("Sending send deck to shuffle")
                    self.players[each]['conn'].sendall(pickle.dumps(msg))

                    #Receiving deck back    
                    d = []  
                    while 1:
                        packet = self.players[each]['conn'].recv(4096)
                        d.append(packet)
                        if len(packet) < 4096: break 
                    data = pickle.loads(b"".join(d))
                    try:
                        self.deck = data['deck']
                        print("Deck shuffled and encrypted by: ",each)
                        #print(decrypted_deck)
                        self.players[each]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                    except:
                        print("*************** Verification Receiving deck back failed ******************")  
                    
                    
                    #self.deck = data['deck']                                     

                    

                print("Lobby is full") 
                break  

    # startGame is called after the initial protocols are done
    def startGame(self):
        
        input("Press a key to START") 
        

        # Sends all players the server and players keys to decrypt
        for each in self.players:            
            msg = {
                'player_keys': Fernet(self.players[each]["aes_key"]).encrypt(pickle.dumps(self.allkeys))   
            }
            msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())}) 
            self.players[each]['conn'].sendall(pickle.dumps(msg))    

            #data = pickle.loads(self.players[each]['conn'].recv(131072))            

        # Distributing initial 5 tiles to each player
        for i in range(self.startpieces): 
            for player in self.players:
                self.givePiece(player)    

                

    # Pops a random piece from the deck and sends to a player
    def givePiece(self,player):
               
        if len(self.deck)>0:

            # Pop tile from deck
            piece = self.deck.pop(random.randint(0,len(self.deck)-1))
            msg = {
                "piece": piece # already chipered
            }  
            msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})   
            #Send tile
           
            self.players[player]['conn'].sendall(pickle.dumps(msg))  
            print("Piece given.")  
            

            d = []  
            while 1:
                packet = self.players[player]['conn'].recv(4096)
                d.append(packet)
                if len(packet) < 4096: break 
            data = pickle.loads(b"".join(d))   

            # Ask if everything was ok
            if 'allok' in data:
                try:
                    decrypt_allok = pickle.loads(Fernet(self.players[player]['aes_key']).decrypt(data["allok"])) 
                    decrypt_commit = pickle.loads(Fernet(self.players[player]['aes_key']).decrypt(data['commit']))
                    print(decrypt_allok) 
                    self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                except: 
                    print("******************** Verification of allok failed **********************") 
            else: 
                print("Something's wrong with the key distribution")

            self.allCommits.append([player, decrypt_commit])  
            #print("self.allCommits: ",self.allCommits)
            print("He commited the following: ", decrypt_commit)
            #msg = {"gotCommit": "gotCommit"}
            #self.players[player]['conn'].sendall(pickle.dumps(msg))   

                 

    # Game playing
    def playGame(self):
        
        running=1

        # Game loop
        while running:
                                
            passed=0
            for player in self.players:
                i=0
                #while i<1: 
                i = 1
                # Given that everything is okay, we keep the game loop

                print("\n-----------------------")
                #print("Table ->",self.table)
                print("To play ->",player)


                played = False
                while played == False:
                    
                    # Tell the correct player to play
                    msg={
                        'play': Fernet(self.players[player]['aes_key']).encrypt(pickle.dumps(self.table))
                    } 
                    msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})
                    self.players[player]['conn'].sendall(pickle.dumps(msg))       
                    
                    # Receive player action
                    d = []  
                    while 1:
                        packet = self.players[player]['conn'].recv(4096)
                        d.append(packet)
                        if len(packet) < 4096: break 
                    data = pickle.loads(b"".join(d))   


                    # Player is saying he played, and giving the new table after playing
                    if 'played' in data:
                        try:
                            decrypted_played = pickle.loads(Fernet(self.players[player]['aes_key']).decrypt(data['played']))
                            self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                        except:
                            print("************ Verification played failed ********************") 
                        
                        piecePlayed = [x for x in decrypted_played if x not in self.table]   
                        
                        if 'commit' in data:
                            self.allCommits.append([player,data['commit']])   

                        #piecePlayed = data['played'] - self.table
                        self.table=decrypted_played 
                        print("Table ->",self.table)
                        self.allPlays+= [[player,piecePlayed]] 
                        played = True  

                    # Player is asking for a piece 
                    if 'ask' in data:
                        try:
                            self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                            print("ASK RECEIVED") 
                        except:
                            print('**************** verify of ask failed ******************') 
                        # Force the loop to stay in the same player if he's asking for piece
                        i = 0

                        # Little visual input of pieces turned down
                        tile = '[ : ]'
                        tiles = []
                        for x in self.deck:
                            tiles.append(tile)
                        print("Tiles: ", tiles)

                        # Check if there are still pieces to give
                        if len(tiles) > 0 :                       
                            
                            # if yes, show him the tiles turned down and wait for him to choose
                            #print("Sending him msg with 'tiles'")
                            print(tiles) 
                            msg = {
                                'tiles' : Fernet(self.players[player]['aes_key']).encrypt(pickle.dumps(tiles))  
                            }
                            msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())}) 
                            #time.sleep(0.2) 
                            self.players[player]['conn'].sendall(pickle.dumps(msg))  
                            print("*************TILES SENT***************") 
                            d = []  
                            while 1:
                                packet = self.players[player]['conn'].recv(4096) 
                                d.append(packet)
                                if len(packet) < 4096: break 
                            data = pickle.loads(b"".join(d))  
                            
                            #print("Estou a mandar o 'tiles': ",msg)
                            #print("Aqui o player é suposto mandar choose mas manda: ",data)
 
                            # Receive message with index 
                            time.sleep(0.2) 
                            if 'choose' in data:
                                print("CHOOSE RECEIVED") 
                                try:
                                    decrypted_choose = pickle.loads(Fernet(self.players[player]['aes_key']).decrypt(data['choose']))
                                    
                                    
                                    self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                                except:
                                    print(' ******************** verify of choose failed *****************')
                                index =  decrypted_choose
                                print("INDEX", index)
                                piece = self.deck.pop(index) 
                                msg = { 
                                    "piece": piece, 
                                    "midgamePiece":'midgamePiece'
                                } 
                                msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})  
                                self.players[player]['conn'].sendall(pickle.dumps(msg))   
                                print("Piece given after player chose.")
                                                        
                                d = []  
                                while 1:
                                    packet = self.players[player]['conn'].recv(4096)
                                    d.append(packet)
                                    if len(packet) < 4096: break 
                                data = pickle.loads(b"".join(d))  
                                
                                if 'commit' in data:
                                    try:
                                        decrypt_commit = pickle.loads(Fernet(self.players[player]['aes_key']).decrypt(data['commit']))
                                        self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                                        self.allCommits.append([player,decrypt_commit])   

                                    except:
                                        print("@@****************** Verification of commit failed ****************")
                                    #print("self.allCommits: ",self.allCommits)
                                    #msg = {"gotCommit": "gotCommit"}
                                    #self.players[player]['conn'].sendall(pickle.dumps(msg))
                            

                        # if not, tell him there are no pieces left
                        else:
                            print('There are no pieces left')
                            msg = {
                                'notiles' : Fernet(self.players[player]['aes_key']).encrypt(pickle.dumps('notiles'))
                            }
                            msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})   
                            self.players[player]['conn'].sendall(pickle.dumps(msg)) 

                            # Wait for player confirmation to pass                                      
                            d = []  
                            while 1:
                                packet = self.players[player]['conn'].recv(4096)
                                d.append(packet)
                                if len(packet) < 4096: break 
                            data = pickle.loads(b"".join(d))  
                        
                            if 'pass' in data:
                                try:
                                    decrypt_passed = pickle.loads(Fernet(self.players[player]['aes_key']).decrypt(data['pass']))
                                    self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                                except:
                                    print("***************** verify of pass failed ********************") 
                                print("Passed.")
                                played = True
                                passed=passed+1 

                # We ask the players if everything is fine before we go to the next play to ensure
                # they have a chance to protest if necessary, or to say something is wrong

                for each in self.players:
                    
                    # Message sent with a refresh of the table
                    msg = {
                        'isitok' : Fernet(self.players[each]['aes_key']).encrypt(pickle.dumps('isitok')), 
                        'tableRefresh': Fernet(self.players[each]['aes_key']).encrypt(pickle.dumps(self.table)), 
                        'whoPlayed': Fernet(self.players[each]['aes_key']).encrypt(pickle.dumps(player)), 
                        'allPlays': Fernet(self.players[each]['aes_key']).encrypt(pickle.dumps(self.allPlays)) 
                    } 
                    msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})   
                    self.players[each]['conn'].sendall(pickle.dumps(msg)) 

                    #print("Asking if everything is ok to: ",each)
                    data = pickle.loads(self.players[each]['conn'].recv(131072))

                    # Players answer with the gamestate, stating if it's ok, if they won or if
                    # they detected cheating
                    if 'gamestate' in data and 'WhatIPlayed' in data:
                            try:
                                decrypted_WhatIPlayed = pickle.loads(Fernet(self.players[each]['aes_key']).decrypt(data['WhatIPlayed']))
                                decrypted_iwin = pickle.loads(Fernet(self.players[each]['aes_key']).decrypt(data['gamestate'])) 
                                self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                            except:
                                print("****************  verification of iwin failed *****************") 
                            self.winner = each
                            self.winnerPlayed = decrypted_WhatIPlayed

                        # Check if someone called for cheating
                    if 'gamestate' in data and 'pad' in data:
                            try:
                                decrypted_cheat= pickle.loads(Fernet(self.players[each]['aes_key']).decrypt(data['gamestate']))
                                self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                            except:
                                print("****************  verification of cheat failed *****************") 
                            self.cheat = decrypted_cheat
                            
                    # Check if ok
                    if 'gamestate' in data and 'test' in data:
                        print(data)
                        try:
                            decrypt_ok = pickle.loads(Fernet(self.players[player]['aes_key']).decrypt(data["ok"]))
                            self.players[player]['rsa_public'].verify(data['sign'], pickle.dumps({d : data[d] for d in list(data)[:-1]}),   padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                        except: 
                            print("******************** Verification of ok failed **********************")    
                    else: 
                        pass
                        #print("Nothing happened, which means something went wrong")   
  

                # If cheating has been called for
                if self.cheat != None:
                    print("Cheating has been detected, game closing.")                                         
                    running = 0
                    self.s.close()
                    exit()
                
                elif self.winner != None:
                    print("The winner is: ",self.winner)

                    msg = {
                        'giveMePlayed': 'giveMePlayed' #?????????????????? nao estao a receber no outro lado...
                    }
                    time.sleep(0.1)
                    self.players[self.winner]['conn'].sendall(pickle.dumps(msg))
                    time.sleep(0.1)
                    
                    print("Cards played by : ", self.winner)
                    print(self.winnerPlayed)

                    count=0
                    #Ask for bit commitment thingy
                    for tile in self.winnerPlayed:
                        hash_object = SHA256.new(bytes(tile))
                        hashedTile = hash_object.hexdigest()
                        #print("Tile: ",tile)
                        #print("Hashed tile: ",hashedTile)
                        
                        #print("Self.allcommits: ",self.allCommits)
                        
                        for one in self.allCommits:
                            if self.winner == one[0]:
                                if(hashedTile in one):
                                    #print(hashedTile)
                                    count = count+1
                                    break
                                    #print("true")
                                else: 
                                    #print("false")
                                    pass

                    print("count: ",count)
                    print("length of hand: ",len(self.winnerPlayed))
                    if count == len(self.winnerPlayed):
                        print("Bit commitment verifies!")
                        announcement = "The player " + str(self.winner) + " has won the game!"

                        f = open("account.txt", "a")
                        f.write("The player "+str(self.winner)+ " scored 3 points\n--------------------------------\n")
                        f.close()

                    else:
                        print("Bit commitment didn't verify")
                        print("The winner cheated!!!")
                        announcement = "The player cheated!!!!" 

                    for aPlayer in self.players: 
                        msg = {
                            'gameOver': Fernet(self.players[aPlayer]['aes_key']).encrypt(pickle.dumps(announcement)) 
                        }
                        msg.update({ "sign" : self.privkey.sign(pickle.dumps(msg), padding.PSS( mgf=padding.MGF1(hashes.SHA256()), 
                                                                                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())})  
                        self.players[aPlayer]['conn'].sendall(pickle.dumps(msg))
  

                    #AQUI METE-SE POSSÍVEL GUARDAR DE PONTOS

                    print("Congratulations! Game closing.")
                    running = 0
                    self.games_counter = self.games_counter + 1
                    self.games_history.update(
                        {
                            self.games_counter : {
                                "players" : self.players,
                                "winner" : self.winner,
                                "table" : self.table,
                                 "allkeys" : self.allkeys
                            }
                        }
                    ) 
                    #pprint.pprint(self.games_history) 
                    self.winner = None 
                    return "game_won"


            if passed==3:
                print("It's a DRAW")
                print("Game Ended")
                for res in self.players:
                    f = open("account.txt", "a")
                        f.write("The player "+str(res)+ " scored 3 points\n")
                        f.close()
                f = open("account.txt", "a")
                        f.write(" --------------------------------\n")
                        f.close()        
                running = 0
                return "game_draw"           



status_game = "init"  
sv = Server()
while(status_game != "exit_game"):
    sv.auth_players()
    sv.startGame()       
    status_game = sv.playGame()
    print(status_game) 
    sv.reset_configs()
self.s.close()   