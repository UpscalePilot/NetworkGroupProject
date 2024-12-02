import socket
import sys
import os
import json
import datetime
import glob
from Crypto.PublicKey import RSA # type: ignore
from Crypto.Cipher import PKCS1_OAEP, AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore



def loadUserCredentials():
    """
    Load the client's credentials from the user_pass.json file and return them as a dictionary.
    user_pass.json contains the username-password pairs for authentication.
    They are provided by meskanas, but can be recreated with key_generator.py.    
    """
    try:
        serverDir = os.path.dirname(os.path.abspath(__file__))
        credentialsPath = os.path.join(serverDir, "user_pass.json")
        with open(credentialsPath, "r") as f:
            return json.load(f)
        
    except FileNotFoundError:
        print("Error: user_pass.json not found.")
        print("Run key_generator.py if no user_pass.json is present.")
        sys.exit(1)


def loadKeys():
    """
    Load the client's public key(s) and the server's private key for RSA en/decryption.
    The server private key is used to decrypt the date received from the client.
    The client's public key is used to send encrypted symmetric keys during the 
    handshaking process.
    
    Returns a tuple containing a dictionary of client public keys, and a cipher 
    OBJ for RSA de/encryption.
    """
    try:
        serverDir = os.path.dirname(os.path.abspath(__file__))
        # load the server private key
        with open(os.path.join(serverDir, "server_private.pem"), "rb") as f:
            serverPrivateKey = RSA.import_key(f.read())

        # cipher object for RSA decryption, allows us to decrypt messages
        # received by clients that were encrypted with the server's public key
        cipherRSA = PKCS1_OAEP.new(serverPrivateKey)
        
        # load the client public key(s)
        clientPublicKeys = {}
        for user in ['client1', 'client2', 'client3', 'client4', 'client5']:
            keyPath = os.path.join(serverDir, f"{user}_public.pem")
            with open(keyPath, 'rb') as f:
                clientPublicKeys[user] = RSA.import_key(f.read())
        
        return clientPublicKeys, cipherRSA
    
    except FileNotFoundError as e:
        print(f"Error loading keys: {e}")
        print("Run /Server/key_generator.py first if necessary.")
        sys.exit(1)


def verifyClientCredentials(username, password, userCredentials):
    '''
    Verify the client's given username and password with the loaded 
    credentials from loadUserCredentials()
    '''
    return username in userCredentials and userCredentials[username] == password


def sendEmailHandler(connectionSocket, cipherAES, sender):
    '''
    Recieves an email from the client, decrypts it and saves it to the recipients' inbox directory.
    '''
    connectionSocket.send(cipherAES.encrypt("Send the email".encode().ljust(1024)))
    
    # receive an email from the client and decrypt it
    encryptedEmail = connectionSocket.recv(1000000)
    emailContent = cipherAES.decrypt(encryptedEmail).strip(b'\x00').decode().strip()
    
    # parse the content of the email so we can print it to the terminal
    lines = emailContent.split('\n')
    destinations = lines[1].split(': ')[1].split(';')
    title = lines[2].split(': ')[1]
    contentLen = int(lines[3].split(': ')[1])
    
    # add a time stamp to the email
    timestamp = datetime.datetime.now()
    serverDir = os.path.dirname(os.path.abspath(__file__))
    
    # save the email for each recipients' inbox
    for d in destinations:
        d = d.strip()
        destinationDir = os.path.join(serverDir, d)
        if not os.path.exists(destinationDir):
            os.makedirs(destinationDir)
    
        fileName = os.path.join(destinationDir, f"{sender}_{title}.txt")
        with open(fileName, 'w') as f:
            f.write(f"From: {sender}\n")
            f.write(f"To: {';'.join(destinations)}\n")
            f.write(f"Time and Date: {timestamp}\n")
            f.write(emailContent[emailContent.index("Title:"):])
    
    print(f"An email from {sender} is sent to {';'.join(destinations)} has a content length of {contentLen}")


def inboxListHandler(connectionSocket, cipherAES, username):
    serverDir = os.path.dirname(os.path.abspath(__file__))
    inboxDir = os.path.join(serverDir, username)
    emails = []
    
    emailFiles = sorted(glob.glob(os.path.join(inboxDir, "*.txt")), key=os.path.getmtime)
    
    for email in emailFiles:
        with open(email, 'r') as f:
            lines = f.readlines()
            sender = lines[0].split(': ')[1].strip()
            timestamp = lines[2].split(': ')[1].strip()
            title = lines[3].split(': ')[1].strip()
            # emails.append(f"{len(emails)+1} {sender} {timestamp} {title}")
            emails.append(f"{len(emails)+1:<6} {sender:<8} {timestamp:<26} {title:<6}")
    
    inboxList = '\n'.join(emails)
    connectionSocket.send(cipherAES.encrypt(inboxList.encode().ljust(4096)))


def viewEmailHandler(connectionSocket, cipherAES, username):
    connectionSocket.send(cipherAES.encrypt("the server request email index".encode().ljust(1024)))
    
    encryptedIndex = connectionSocket.recv(1024)
    index = int(cipherAES.decrypt(encryptedIndex).decode().strip())
    
    serverDir = os.path.dirname(os.path.abspath(__file__))
    inboxDir = os.path.join(serverDir, username)
    emailFiles = sorted(glob.glob(os.path.join(inboxDir, "*.txt")), key=os.path.getmtime)
    
    # invalid index selection
    if not (1 <= index <= len(emailFiles)):
        errorMsg = 'Error: Selected email index does not exist.'
        connectionSocket.send(cipherAES.encrypt(errorMsg.encode().ljust(4096)))
        return
    
    # open the email, send it to the client.
    with open(emailFiles[index-1], 'r') as f:
        emailContent = f.read()
    connectionSocket.send(cipherAES.encrypt(emailContent.strip().encode().ljust(4096)))


def handleClient(connectionSocket, clientPublicKeys, cipherRSA, userCredentials):
    """Individual clients are handled in this function."""
    try:
        # receive the encrypted client's credentials
        encryptedCreds = connectionSocket.recv(1024)
        decryptedCreds = cipherRSA.decrypt(encryptedCreds)
        username, password = decryptedCreds.decode().split(":")
        
        # verify the client's credentials
        if not verifyClientCredentials(username, password, userCredentials):
            connectionSocket.send("Invalid username or password".encode())
            connectionSocket.close()
            print(f"The received client information: {username} is invalid (Connection Terminated).")
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
        decryptedAck = cipherAES.decrypt(encryptedAck).strip(b'\x00').decode().strip()
        
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
            choice = cipherAES.decrypt(encryptedChoice).strip(b'\x00').decode().strip()
            
            # send email
            if choice == '1':
                sendEmailHandler(connectionSocket, cipherAES, username)
            
            # inbox list
            elif choice == '2':
                inboxListHandler(connectionSocket, cipherAES, username)
            
            # view emails
            elif choice == '3':
                viewEmailHandler(connectionSocket, cipherAES, username)
            
            else:
                print(f"Terminating connection with {username}.")
                break
        
    except Exception as e:
        print(f"Error handling client: {e}")
        connectionSocket.close()
    
    finally:
        connectionSocket.close()


def server(cipherRSA, clientPublicKeys, userCredentials):
    # Create server socket that uses IPv4 and TCP protocols 
    serverPort = 13000
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # fixes error 98 address already in use when killing the process and rerunning the server in a terminal.
        serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as e:
        print('Error in server socket creation:', e)
        sys.exit(1)
    
    # Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:', e)
        sys.exit(1)        

    # the server will listen to 5 connections simultaneously
    # side note: B7 - the server must serve all known clients simultaneously but 
    # am unsure if we have to account for new clients being added to the known-list?
    serverSocket.listen(5)
    print("The server is ready to accept connections.")
    
    clientPublicKeys, cipherRSA = loadKeys()
    userCredentials = loadUserCredentials()
    
    while True:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            
            # Fork for each client connection
            pid = os.fork()
            
            # child process handling
            if pid == 0:
                serverSocket.close()        # close the parent's socket in the child process
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
def main():
    cipherRSA, clientPublicKeys = loadKeys()
    userCredentials = loadUserCredentials()
    server(cipherRSA, clientPublicKeys, userCredentials)

if __name__ == "__main__":
    main()