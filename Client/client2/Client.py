import socket
import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import json
import datetime

sym_key = None

def loadServerKey():
    '''Load the server's public key from server_public.pem.
    Returns the RSA key object.'''
    try:
        with open("server_public.pem", "rb") as f:
            serverPublicKey = RSA.import_key(f.read())
        return serverPublicKey
    
    except FileNotFoundError:
        print("Error: server_public.pem not found")
        sys.exit(1)


def client():
    # Server Information
    serverName = input("Enter the server IP or name: ")
    serverPort = 13000
    
    # Create client socket using IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # if the client hangs, timeout the connection after 10 seconds.
        clientSocket.settimeout(10)
        clientSocket.connect((serverName,serverPort))
   
    
        try:
            # get the client's user/pass
            clientUsername = input("Enter your username: ")
            clientPassword = input("Enter your password: ")

            # load the client's private key
            with open(f"{clientUsername}_private.pem", "rb") as f:
                clientPrivateKey = RSA.import_key(f.read())

        except FileNotFoundError:
            print("Invalid username or password. Terminating connection")
            clientSocket.close()
            sys.exit(1)
        
        serverPublicKey = loadServerKey()
        
        # encrypt client credentials and send them to the server
        creds = f"{clientUsername}:{clientPassword}"
        cipherRSA = PKCS1_OAEP.new(serverPublicKey)
        encryptedCredentials = cipherRSA.encrypt(creds.encode())
        clientSocket.send(encryptedCredentials)
        
        
        # receive the server response
        response = clientSocket.recv(1024)
        
        
        # try to decrypt as sym_key
        cipherRSA = PKCS1_OAEP.new(clientPrivateKey)
        sym_key = cipherRSA.decrypt(response)
        
        
        # send the acknowledgement to the server
        cipherAES = AES.new(sym_key, AES.MODE_ECB)
        encryptedAck = cipherAES.encrypt("OK".encode().ljust(1024))
        clientSocket.send(encryptedAck)
        
        
        # main loop for client operations
        while True:
            # receive and decrypt the menu message
            encryptedMenu = clientSocket.recv(1024)
            menu = cipherAES.decrypt(encryptedMenu).strip(b'\x00').decode()
            print(menu, end='', flush=True)
            
            # get the client's choice and encrypt it
            choice = input()
            encryptedChoice = cipherAES.encrypt(choice.encode().ljust(1024))
            clientSocket.send(encryptedChoice)
            
            
            if choice == '1':
                pass
            
            elif choice == '2':
                pass
            
            elif choice == '3':
                pass
            
            # termination selection. Unsure if error checking for menu choices 
            # is required
            elif choice == '4':
                print("The connection is terminated with the server.")
                break
                
 

    except socket.error as e:
        print('A socket error has occured:',e)
        clientSocket.close()
        sys.exit(1)
    
    except Exception as e:
        print(f"Client error has occurred: {e}")
        clientSocket.close()
        sys.exit(1)

#----------
client()