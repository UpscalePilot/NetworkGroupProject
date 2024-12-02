# NetworkGroupProject
Cmpt361 Group Project

## Overview
Our project has the following key features:
1. **Secure Communication**: The client and server communicate using RSA encryption for the initial handshake and AES encryption for the message exchange. This ensures the confidentiality of the communication
2. **User Authentication**: The servr verifies the client's username and password before allowing access to the email system.
3. **Email Functinoality**: The client can send emails, view their inbox, and read individual emails. The emails are stored on the server's file system.
4. **Scalability**: The server can handle multiple client connections simultaneously using a fork-based approach.
5. **Replay Attack Protection**: Enhanced program versions (Server_enhanced.py + Client_enhanced.py) include
protections against replay attacks using nonces and timestamps.

## Components
Our project consists of the following components:

1. **Server**:
- Handles client connections and authentication
- Supports five simultaneous client connections
- Generates and manages symmetric keys for encryption.
- Saves and retrieves emails from the file system.

2. **Client**:
- Establishes a connection with the server.
- Authenticates with the server using a username and password.
- Send emails, views the inbox, and reads individual emails.
- Handles file-based email content imports

3. **Key Generator**:
- Generates RSA key pairs for the server and clients.
- Saves the keys in the appropriate directories
- Generates user credentials file and directory structures if necessary

## Security Features
1. **Basic Security (Original)**:
- RSA encryption for authentication
- AES encryption for messages exchange
- Password-based authentication

2. **Enhanced Security**:
- Protection against replay attacks
- Nonce-based challenge-response implementation
- Timestamp verification
- Session tracking

## Usage 
1. Run the 'key_generator.py' script to generate the necessary keys.
2. Run either 'Server.py' or 'Server_enhanced.py' to start the email server.
3. Run either 'Client.py'or 'Client_enhanced.py' to connect to the server and use the email system.

## Error handling cases
- Invalid credentials detection
- File not found for email imports
- Invalid email indexing
- Connection timeouts

