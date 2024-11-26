import json
import os
from Crypto.PublicKey import RSA

def main():
    # Get the script's directory (Server)
    server_dir = os.path.dirname(os.path.abspath(__file__))
    # Get the parent directory and construct the path to "Client"
    parent_dir = os.path.dirname(server_dir)
    client_dir = os.path.join(parent_dir, "Client")
    
    print(f"Using Server directory: {server_dir}")
    print(f"Using Client directory: {client_dir}")
    
    # just in case we have no user_pass.json
    users = {
        "client1": "password1",
        "client2": "password2",
        "client3": "password3",
        "client4": "password4",
        "client5": "password5"
    }
    
    # Save user credentials in the Server directory
    with open(os.path.join(server_dir, "user_pass.json"), "w") as f:
        json.dump(users, f, indent=4)
    print("Created user_pass.json in Server directory")
    
    # Generate and save server keys
    key = RSA.generate(2048)
    server_private_key = key.export_key()
    server_public_key = key.publickey().export_key()
    
    with open(os.path.join(server_dir, "server_private.pem"), "wb") as f:
        f.write(server_private_key)
    print("server_private.pem wrote to Server directory")
    
    with open(os.path.join(server_dir, "server_public.pem"), "wb") as f:
        f.write(server_public_key)
    print("server_public.pem wrote to Server directory")

    # Write server public key to Client directory first before client1/2/3/4/5
    with open(os.path.join(client_dir, "server_public.pem"), "wb") as f:
        f.write(server_public_key)
    print("server_public.pem wrote to main \Client directory")
    
    for username in users.keys():
        print(f"\nProcessing {username}...")
        
        # Create client email directory in Server
        server_client_dir = os.path.join(server_dir, username)
        if not os.path.exists(server_client_dir):
            os.makedirs(server_client_dir)
            print(f"Created {username} email directory in Server")
        
        # Create client directory in Client folder
        client_specific_dir = os.path.join(client_dir, username)
        if not os.path.exists(client_specific_dir):
            os.makedirs(client_specific_dir)
            print(f"Created {username} directory in Client folder")
        
        # Generate client key pair
        client_key = RSA.generate(2048)
        client_private_key = client_key.export_key()
        client_public_key = client_key.publickey().export_key()
        
        # Save client's public key in Server directory
        with open(os.path.join(server_dir, f"{username}_public.pem"), "wb") as f:
            f.write(client_public_key)
        print(f"Created {username}_public.pem in Server")
        
        # Save client's private key in their Client directory
        with open(os.path.join(client_specific_dir, f"{username}_private.pem"), "wb") as f:
            f.write(client_private_key)
        print(f"Created {username}_private.pem in Client/{username}")
        
        # Save client's public key in their Client directory
        with open(os.path.join(client_specific_dir, f"{username}_public.pem"), "wb") as f:
            f.write(client_public_key)
        print(f"Created {username}_public.pem in Client/{username}")
        
        # Copy server's public key to the main client directory
        with open(os.path.join(client_specific_dir, "server_public.pem"), "wb") as f:
            f.write(server_public_key)
        print(f"Copied server_public.pem to Client/{username}")

    print("\nKey generation completed successfully!")
    print("\nCreated directory structure:")
    print(f"\n{server_dir}")
    print("├── key_generator.py")
    print("├── server_private.pem")
    print("├── server_public.pem")
    print("├── user_pass.json")
    for username in users.keys():
        print(f"├── {username}/ (email directory)")
        print(f"├── {username}_public.pem")
    
    print(f"\n{client_dir}")
    print("├── server_public.pem")
    for username in users.keys():
        print(f"├── {username}/")
        print(f"    ├── {username}_private.pem")
        print(f"    ├── {username}_public.pem")
        print(f"    └── server_public.pem")

if __name__ == "__main__":
    main()