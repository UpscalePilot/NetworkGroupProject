import socket
import sys
import os

sym_key = None

def client():
    # Server Information
    serverName = input("Enter the server host name or IP: ")
    serverPort = 13000
    
    #Create client socket that using IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # if the client hangs, timeout the connection after 10 seconds.
        clientSocket.settimeout(10)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        # decode the welcome message received from the server
        message = clientSocket.recv(2048).decode('ascii')
        print(message, end='', flush=True)
        
        # get client user input and send the message to the server
        userInput = input()
        clientSocket.send(userInput.encode("ascii"))
        
        while True:
            try:
                # check that the message from the server isn't null
                message = clientSocket.recv(2048).decode('ascii')

                # no message received, assume the Server terminated 
                # the connection arbitrarily 
                if not message:
                    print("Server closed the connection")
                    clientSocket.close()
                    sys.exit(1)
                
            except socket.timeout:
                print('No response from server, timing out.')
                clientSocket.close()
                sys.exit(1)

    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)
    
    except Exception as e:
        print(f"Client error has occurred: {e}")
        clientSocket.close()
        sys.exit(1)

#----------
client()