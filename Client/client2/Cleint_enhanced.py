import socket
import sys
import os
import json
import datetime
from Crypto.PublicKey import RSA # type: ignore
from Crypto.Cipher import PKCS1_OAEP, AES # type: ignore


def loadKeys():
    '''
    Load the server's public key from server_public.pem. 
    The server's public key encrypts the client credentials when communicating 
    with the server.
    
    Returns the RSA key object.
    '''
    try:
        # directory path formatting
        clientDir = os.path.dirname(os.path.abspath(__file__))
        
        # read the server's public key
        with open(os.path.join(clientDir, "server_public.pem"), 'rb') as f:
            serverPublicKey = RSA.import_key(f.read())    
 
        return serverPublicKey
    
    except FileNotFoundError:
        print(f"Error: server_public.pem not found.")
        print("Ensure that key_generator.py has been run and keys are in the correct directories.")
        sys.exit(1)


def loadPrivateKey(username):
    '''
    Loads the private RSA key for the client based on their given username.
    This private RSA key decrypts data received by the server (i.e symm_key)
    
    Returns the RSA key object of their private key
    '''
    try: # format the directory path, load the clients' private key
        clientDir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(clientDir, f"{username}_private.pem"), 'rb') as f:
            clientPrivateKey = RSA.import_key(f.read())
        return clientPrivateKey
    
    except FileNotFoundError:
        print("Invalid username or password.\nTerminating.")
        sys.exit(1)


def sendEmail(clientSocket, cipherAES, username):
    '''
    Gathers information of the written email and assembles it to be encrypted 
    and sent to the server.
    '''
    encryptedPrompt = clientSocket.recv(1024)
    prompt = cipherAES.decrypt(encryptedPrompt).strip(b'\x00').decode().strip()
    
    destinations = input("Enter destinations (separated by ;): ")
    title = input("Enter title: ")
    
    if len(title) > 100:
        print("Title is too long (max 100 characters)")
        # return client to menu, maintain connection protocol by submitting empty contents as an email
        emptyEmail = f"From: {username}\nTo: \nTitle: \nContent Length: 0\nContents:\n"
        clientSocket.send(cipherAES.encrypt(emptyEmail.encode().ljust(4096)))
        return
    
    content = ''
    if input("Would you like to load contents from a file?(Y/N) ").upper() == 'Y':
        fileName = input("Enter filename: ")
        try:
            with open(fileName, 'r') as f:
                content = f.read()
                
        except FileNotFoundError:
            print("File not found. Returning to menu.\n")
            # return client to menu, maintain connection protocol by submitting empty contents as an email
            emptyEmail = f"From: {username}\nTo: \nTitle: \nContent Length: 0\nContents:\n"
            clientSocket.send(cipherAES.encrypt(emptyEmail.encode().ljust(4096)))
            return
        
    else:
        content = input("Enter message contents: ")
    
    if len(content) > 1000000:
        print("Contents too long (max 1000000 characters)")
        # return client to menu, maintain connection protocol by submitting empty contents as an email
        emptyEmail = f"From: {username}\nTo: \nTitle: \nContent Length: 0\nContents:\n"
        clientSocket.send(cipherAES.encrypt(emptyEmail.encode().ljust(4096)))
        return
    
    email = f"From: {username}\n"
    email += f"To: {destinations}\n"
    email += f"Title: {title}\n"
    email += f"Content Length: {len(content)}\n"
    email += f"Contents:\n{content}"
    
    encryptedEmail = cipherAES.encrypt(email.encode().ljust(4096))
    clientSocket.send(encryptedEmail)
    print("The message is sent to the server.")


def viewInbox(clientSocket, cipherAES):
    '''
    Retrieves and displays the client's inbox list from the server.
    '''
    encryptedInbox = clientSocket.recv(4096)
    inboxList = cipherAES.decrypt(encryptedInbox).strip(b'\x00').decode().strip()
    # print("Index from DateTime Title")
    print(f"{'Index':<6} {'choice':<8} {'DateTime':<26} {'Title':<6}")
    print(inboxList)
    print("\n");
    
    # encryptedACK = cipherAES.encrypt("OK".encode().ljust(1024))
    # clientSocket.send(encryptedACK)


def viewEmail(clientSocket, cipherAES):
    '''
    Displays the content of an email from the client's inbox.
    '''
    encryptedRequest = clientSocket.recv(1024)
    request = cipherAES.decrypt(encryptedRequest).decode().strip()
    
    if request == "the server request email index":
        index = input("Enter the email index you wish to view: ")
        encryptedIndex = cipherAES.encrypt(index.encode().ljust(1024))
        clientSocket.send(encryptedIndex)
        
        encryptedEmail = clientSocket.recv(4096)
        email = cipherAES.decrypt(encryptedEmail).decode().strip()
        
        # check for the invalid index error msg
        if email.startswith("Error:"):
            print(email + '\n')
            return
        
        print(email + "\n")


def terminalOperationsHandler(clientSocket, cipherAES, username):
    '''
    The main loop for the terminal client and handling user choices
    for sending emails, checking their emails, and termination of the connection. 
    '''
    while True:
        # receive and decrypt the menu message
        encryptedMenu = clientSocket.recv(1024)
        menu = cipherAES.decrypt(encryptedMenu).strip(b'\x00').decode().strip()
        print(menu, end=' ', flush=True)
        
        # get the client's choice and encrypt it
        choice = input()
        encryptedChoice = cipherAES.encrypt(choice.encode().ljust(1024))
        clientSocket.send(encryptedChoice)
        
        
        if choice == '1':
            sendEmail(clientSocket, cipherAES, username)
        
        elif choice == '2':
            viewInbox(clientSocket, cipherAES)
        
        elif choice == '3':
            viewEmail(clientSocket, cipherAES)
        
        # termination selection. Unsure if error checking for menu choices is required
        elif choice == '4':
            print("The connection is terminated with the server.")
            break
    return


def client(serverPublicKey):
    '''
    Establishes a connection with the server and authentication of the client.
    '''
    # Server Information
    serverName = input("Enter the server IP or name: ")
    serverPort = 13000
    
    # default server name set to lab machine 5 - DELETE THIS before handing in
    if serverName == "":
        serverName = "cc5-212-14.macewan.ca";
    
    # Create client socket using IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # if the client hangs, timeout the connection after 10 seconds.
        clientSocket.settimeout(10)
        clientSocket.connect((serverName, serverPort))
        print("[Security] Connected to srever, awaiting challenge")
        
        challenge = clientSocket.recv(1024).decode()
        serverNonce, serverTimestamp = challenge.split(':')
        print("[Security] Receieved server challenge")

        # get the client's username/password
        clientUsername = input("Enter your username: ")
        clientPassword = input("Enter your password: ")
        
        # encrypt client credentials and send them to the server
        currTimestamp = datetime.datetime.now().timestamp()
        creds = f"{clientUsername}:{clientPassword}:{serverNonce}:{currTimestamp}"
        cipherRSA = PKCS1_OAEP.new(serverPublicKey)
        encryptedCredentials = cipherRSA.encrypt(creds.encode())
        
        # for testing purposes: save the encrypted credentials
        print("[Test] Saving encrypted credentials to capturedAuth.txt")
        with open('capturedAuth.txt', 'wb') as f:
            f.write(encryptedCredentials)
        
        clientSocket.send(encryptedCredentials)
        print("[Security] Sent authenticated credentials")
        
        # receive the server response
        response = clientSocket.recv(1024)
        
        # load the client's private key
        clientPrivateKey = loadPrivateKey(clientUsername)
        
        try:
            # try to decrypt as sym_key
            cipherRSA = PKCS1_OAEP.new(clientPrivateKey)
            decryptedData = cipherRSA.decrypt(response).decode()
            sym_key = cipherRSA.decrypt(response).decode()
            sessionID, sym_keyHex = decryptedData.split(":")
            sym_key = bytes.fromhex(sym_keyHex)
            print('[Security] Established secure session')
            
        
            # send the acknowledgement to the server
            cipherAES = AES.new(sym_key, AES.MODE_ECB)
            encryptedAck = cipherAES.encrypt("OK".encode().ljust(1024))
            clientSocket.send(encryptedAck)

            terminalOperationsHandler(clientSocket, cipherAES, clientUsername)
            return True
        
        except:
            print(response.decode())
            print("Terminating.")
            return False
        
        
    except socket.timeout:
        print("Connection timed out.")
        clientSocket.close()
        sys.exit(1)

    except socket.error as e:
        print('A socket error has occured:',e)
        clientSocket.close()
        sys.exit(1)
    
    except Exception as e:
        print(f"Client error has occurred: {e}")
        clientSocket.close()
        sys.exit(1)
        
    finally:
        if 'clientSocket' in locals():
            clientSocket.close()


#----------
def main():
    # Load the server's public key and then initiate the connection with the client
    serverPublicKey = loadKeys()
    client(serverPublicKey)

if __name__ == '__main__':
    main()