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
from Crypto import Random
from Crypto.Cipher import AES
import base64
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class Server:
    
    def __init__(self):
    
        self.deck = []    
        self.nplayers = 3
        self.startpieces = 5
        self.players = []
        self.table = []
        self.conn = {}
        self.addr = {}
        self.allkeys = []
        self.winner = None
        self.cheat = None

        # Deciding players number 
        if len(sys.argv) >= 2:
            self.nplayers = sys.argv[1]

        # Symmetric key generation using the Fernet cipher
        print("Generating symmetric key...")
        self.key = Fernet.generate_key()
        self.allkeys.append(self.key)
        print("Done")      
        
        # Create and encrypt pieces
        for i in range(7):
            for j in range(i,7):
                msg = [i,j]
                msg = str(msg).encode()

                # Fernet AES Encrypt
                f = Fernet(self.key)
                encrypted = base64.b64encode(msg)
                encrypted = f.encrypt(encrypted)
                
                #Add encrypted pieces to deck
                self.deck += [encrypted]


        # Create channel for communication
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('localhost', 25567))
        print("Waiting for players...\n")
        

        # Initial communication loop for player acknowledgement and tiles preparation
        while 1:
            self.s.listen(1)
            conn, addr = self.s.accept()
            data = pickle.loads(conn.recv(131072))

            # Check if a player is logging in and adds his information, also receives his public key
            if 'name' in data:
                name=data['name']
                key = data['key']
                print("Player",name, "connected with key: ",key)
                self.players += [name]
                self.conn[name]=conn
                self.addr[name]=addr
                
                if data['key'] not in self.allkeys:
                    self.allkeys.append(data['key'])
            
            # Check if lobby is full
            if len(self.players)==self.nplayers:
                temp=0

                # Going to rotate the deck so that all players can encrypt on top
                for each in self.players:

                    #Sending deck                    
                    msg = {'shuffleEnc' : 'shuffleEnc', 'deck': self.deck}
                    print("Sending send deck to shuffle")
                    self.conn[each].sendall(pickle.dumps(msg))

                    #Receiving deck back                    
                    data = pickle.loads(self.conn[each].recv(131072))
                    print("Deck shuffled and encrypted by: ",each)
                    self.deck = data['deck']                                 

                print("Lobby is full")
                break

    # startGame is called after the initial protocols are done
    def startGame(self):
        
        input("Press a key to START")
        

        # Sends all players the server and players keys to decrypt
        for each in self.players:            
            msg = {'player_keys': self.allkeys}
            self.conn[each].sendall(pickle.dumps(msg))
            data = pickle.loads(self.conn[each].recv(131072))

        # Distributing initial 5 tiles to each player
        for i in range(self.startpieces): 
            for player in self.players:
                self.givePiece(player)

        # Starts the gameplay loop        
        self.playGame()
                

    # Pops a random piece from the deck and sends to a player
    def givePiece(self,player):
               
        if len(self.deck)>0:

            # Pop tile from deck
            piece = self.deck.pop(random.randint(0,len(self.deck)-1))
            msg = {"piece": piece}

            #Send tile
            self.conn[player].sendall(pickle.dumps(msg))
            print("Piece given.")

            data = pickle.loads(self.conn[player].recv(131072))

            # Ask if everything was ok
            if 'allok' in data:
                print("Player stated the piece was received")
            else: 
                print("Something's wrong with the key distribution")

    # Game playing
    def playGame(self):
        
        running=1

        # Game loop
        while running:
                
                
            passed=0
            for player in self.players:

                # First we ask the players if everything is fine before any play happens to ensure
                # they have a chance to protest if necessary, or to say something is wrong

                for each in self.players:
                    
                    # Message sent with a refresh of the table
                    msg = {'isitok' : 'isitok', 'tableRefresh': self.table}                    
                    self.conn[each].sendall(pickle.dumps(msg))

                    print("Asking if everything is ok to: ",each)
                    data = pickle.loads(self.conn[each].recv(131072))

                    # Players answer with the gamestate, stating if it's ok, if they won or if
                    # they detected cheating
                    if 'gamestate' in data:

                        # Check if someone won
                        if data['gamestate'] == 'iwin':
                            self.winner = each
                            print("The winner is",each)
                            print("Game Ended.")                        
                            running = 0
                            self.s.close()
                            exit()

                        # Check if someone called for cheating
                        elif data['gamestate'] == 'cheat':
                            self.cheat = "Cheat"
                            
                        # Check if ok
                        elif data['gamestate'] == 'ok':
                            print("Tudo Ok")
                        else:
                            print("Nothing happened, which means something went wrong") 


                # If cheating has been called for
                if self.cheat != None:
                    print("Cheating has been detected, game closing.")                                         
                    running = 0
                    self.s.close()
                    exit()
                
                elif self.winner != None:
                    print("The winner is: ",self.winner)

                    #AQUI METE-SE POSSÍVEL GUARDAR DE PONTOS

                    print("Congratulations! Game closing.")
                    running = 0
                    self.s.close()
                    exit()

                    
                # Given that everything is okay, we keep the game loop

                print("\n-----------------------")
                print("Table ->",self.table)
                print("To play ->",player)


                played = False
                while played == False:
                    
                    # Tell the correct player to play
                    msg={'play': self.table}
                    self.conn[player].sendall(pickle.dumps(msg))
                    
                    # Receive player action
                    data = pickle.loads(self.conn[player].recv(131072))

                    # Player is saying he played, and giving the new table after playing
                    if 'played' in data:
                        self.table=data['played']
                        print("Table ->",self.table)
                        played = True

                    # Player is asking for a piece 
                    if 'ask' in data:

                        # Little visual input of pieces turned down
                        tile = '[ : ]'
                        tiles = []
                        for x in self.deck:
                            tiles.append(tile)
                        print("Tiles: ", tiles)

                        # Check if there are still pieces to give
                        if len(tiles) > 0 :                       
                            
                            # if yes, show him the tiles turned down and wait for him to choose
                            msg = {'tiles' : tiles}
                            self.conn[player].sendall(pickle.dumps(msg))
                            data = pickle.loads(self.conn[player].recv(131072))

                            # Receive message with index
                            if 'choose' in data:
                                index =  data['choose']
                                piece = self.deck.pop(index)
                                msg = {"piece": piece, "midgamePiece":'midgamePiece'}
                                self.conn[player].sendall(pickle.dumps(msg))
                                print("Piece given.")

                        # if not, tell him there are no pieces left
                        else:
                            print('There are no pieces left')
                            msg = {'notiles' : 'notiles'}
                            self.conn[player].sendall(pickle.dumps(msg)) 

                            # Wait for player confirmation to pass                                      
                            data = pickle.loads(self.conn[player].recv(131072))
                        
                            if 'pass' in data:
                                print("Passed.")
                                played = True
                                passed=passed+1
                    

                        
            if passed==3:
                print("It's a DRAW")
                print("Game Ended")
                running = 0
                self.s.close()
                exit()
            
sv = Server()

sv.startGame()