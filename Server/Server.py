import socket
import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import json
import datetime
import glob


def loadUserCredentials():
    """Load the client's credentials from the user_pass.json file and return them as a dict"""
    try:
        with open("user_pass.json", "r") as f:
            userCredentials = json.load(f)
            return userCredentials
        
    except FileNotFoundError as e:
        print("Error: user_pass.json not found.")
        sys.exit(1)


def loadKeys():
    """Load the client's public key(s) and the server's private key
    from their respective files. Returns a dictionary of usernames as keys and RSA public keys as values.
    Also returns a cipher object used for RSA decryption."""
    try:
        # load the server private key
        with open("server_private.pem", "rb") as f:
            privateKey = RSA.import_key(f.read())

        # cipher object for RSA decryption, allows us to decrypt messages
        # received by clients that were encrypted with the server's public key
        cipherRSA = PKCS1_OAEP.new(privateKey)
        
        # load the client public key(s)
        clientPublicKeys = {}
        for keyFile in glob.glob("client*_public.pem"):
            clientUsername = keyFile.split('_')[0]
            with open(keyFile, "rb") as f:
                clientPublicKeys[clientUsername] = RSA.import_key(f.read())
        
        return clientPublicKeys, cipherRSA
    
    except FileNotFoundError as e:
        print(f"Error loading keys: {e}")
        sys.exit(1)



def verifyClientCredentials(username, password, userCredentials):
    '''Verify the client's given username and password with the loaded/retrieved 
    credentials from loadUserCredentials()'''
    return username in userCredentials and userCredentials[username] == password

def handleClient(connectionSocket, clientPublicKeys, cipherRSA, userCredentials):
    """Individual clients are handled in this function."""
    try:
        # receive the encrypted client credentials
        encryptedCreds = connectionSocket.recv(1024)
        decryptedCreds = cipherRSA.decrypt(encryptedCreds)
        username, password = decryptedCreds.decode().split(":")
        
        # verify the client's credentials
        if not verifyClientCredentials(username, password, userCredentials):
            connectionSocket.send("Invalid username or password".encode())
            print(f"The received client info: {username} is invalid (Connection Terminated).")
            return
        
        # generate and send the sym_key (symmetric key)
        sym_key = get_random_bytes(32) # 256-bit key, AES encryption
        clientPublicKey = clientPublicKeys[username]
        cipherRSAClient = PKCS1_OAEP.new(clientPublicKey)
        encrypedSymKey = cipherRSAClient.encrypt(sym_key)
        connectionSocket.send(encrypedSymKey)
        
        print(f"Connection Accepted and Symmetric key generated for client: {username}")
        
        
        # create AES cipher
        cipherAES = AES.new(sym_key, AES.MODE_ECB)
        
        # receive acknowledgement from the client
        encryptedAck = connectionSocket.recv(1024)
        decryptedAck = cipherAES.decrypt(encryptedAck).strip(b'\x00').decode()
        
        if decryptedAck != 'OK':
            return
        
        # main interaction loop with the client
        while True:
            # send the menu to the client
            menu = '''Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\n\n\tchoice: '''
            
            # ljust (left-justified string method) - we pad the menu message to 
            # a length of 1024 bytes. The padding/buffer is added to the right 
            # side of the menu string.
            # the reasoning is that AES encryption operates on fixed block sizes
            # so we should maintain consistency with the menu when sending/displaying it.
            encryptedMenu = cipherAES.encrypt(menu.encode().ljust(1024))
            connectionSocket.send(encryptedMenu)
            
            # get the choice from the client
            encryptedChoice = connectionSocket.recv(1024)
            # when decrypting, strip the padding from the message
            choice = cipherAES.decrypt(encryptedChoice).strip(b'\x00').decode()
            
            
            if choice == '1':
                pass
            
            
            elif choice == '2':
                pass
            
            elif choice == '3':
                pass
            
            else:
                print(f"Terminating connection with {username}.")
                break
        
    except Exception as e:
        print(f"Error handling client: {e}")
        connectionSocket.close()
    
    finally:
        connectionSocket.close()


def server():
    # Create server socket that uses IPv4 and TCP protocols 
    serverPort = 13000
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # fixes error 98 address already in use when killing the process and rerunning the server in a terminal.
        serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    # Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        

    # the server will listen to 5 connections simultaneously
    # side note: B7 - the server must serve all known clients simultaneously but 
    # am unsure if we have to account for new clients being added to the known-list?
    serverSocket.listen(5)
    print("The server is ready to accept connections.")
    
    clientPublicKeys, cipherRSA = loadKeys()
    userCredentials = loadUserCredentials()
    
    try:
        #Server accepts client connection
        connectionSocket, addr = serverSocket.accept()
        
        # Fork for each client connection
        pid = os.fork()
        
        # child process handling
        if pid == 0:
            connectionSocket.close() # close the parent's socket in the child process
            handleClient(connectionSocket, clientPublicKeys, cipherRSA, userCredentials)
            sys.exit(0)
        
        # parent process
        else:
            connectionSocket.close()
        

    except socket.error as e:
        print('A socket error has occured:', e)
        connectionSocket.close()
        serverSocket.close() 
        sys.exit(1)  
      
    except Exception as e:
        print('A server error has occured:', e)
        connectionSocket.close()
        serverSocket.close() 
        sys.exit(1)

    finally:
        if connectionSocket:
            connectionSocket.close()
  

#-------
server()