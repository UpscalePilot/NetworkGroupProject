# NetworkGroupProject
Cmpt361 Group Project

## Overview
Our project has the following key features:
1. **Secure Communication**: The client and server communicate using RSA encryption for the initial handshake and AES encryption for the message excahnge. This ensures the confidentiality of the communication
2. **User Authentication**: The servr verifies the client's username and password before allowing access to the email system.
3. **Email Functinoality**: The client can send emails, view their inbox, and read individual emails. The emails are stored on the server's file system.
4. **Scalability**: The server can handle multiple client connections simultaneously using a fork-based approach.

## Components
Our project consists of the following components:

1. **Server**:
- Handles client connections and authentication
- Generates and manages symmetric keys for encryption.
- Saves and retrieves emails from the file system.

2. **Client**:
- Establishes a connection with the server.
- Authenticates with the server using a username and password.
- Send emails, views the inbox, and reads individual emails.

3. **Key Generator**:
- Generates RSA key pairs for the server and clients.
- Saves the keys in the appropriate directories

## Usage 
1. Run the 'key_generator.py' script to generate the necessary keys.
2. Run the 'Server.py' script to start the email server.
3. Run the 'Client.py' to connect to the server and use the email system.