import socket
import sys

def testReplay():
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect(('localhost', 13000))
    
    # receive the server's challenge but we ignore it here
    temp = clientSocket.recv(1024)

    with open('capturedAuth.txt', 'rb') as f:
        capturedAuth = f.read()
    
    # tries to replay the captured authentication; capturedAuth is generated in client_enhanced.py in client()    
    clientSocket.send(capturedAuth)
    
    
    response = clientSocket.recv(1024).decode()
    print(f"Server Response: {response}")
    
    clientSocket.close()

if __name__ == '__main__':
    testReplay()