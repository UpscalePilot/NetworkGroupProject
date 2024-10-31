import socket
import sys
import os
import json
from datetime import datetime

sym_key = None

def server():
    #Server port
    serverPort = 13000
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # fixes error 98 address already in use when killing the process and rerunning the server in a terminal.
        # serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        

    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(1)
    
    try:
        #Server accepts client connection
        connectionSocket, addr = serverSocket.accept()
        
        # send welcome message + input username message to client.
        welcomeMsg = 'Welcome to our system.\nEnter your username: '
        connectionSocket.send(welcomeMsg.encode('ascii'))
        
            
    except socket.error as e:
        print('An error occured:',e)
        connectionSocket.send("An error occurred on the server. Connection closing.".encode('ascii'))
        connectionSocket.close()
        serverSocket.close() 
        sys.exit(1)  
      
    except Exception as e:
        connectionSocket.close()
        serverSocket.close() 
        sys.exit(0)
            
        
#-------
server()