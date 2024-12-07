import os
import shutil
import sys


def copy_client_script():
    '''copies over Client.py from mail Client directory into each client* subdirectory,
saves a few seconds for pasting the code into each subdirectory when we make changes.'''
    try:
        # Get the base Client directory path
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Path to source Client.py
        source_path = os.path.join(base_dir, "Client.py")
        source_path2 = os.path.join(base_dir, "Client_enhanced.py")
        
        # Verify source exists
        if not os.path.exists(source_path):
            print(f"Error: Could not find Client.py in {base_dir}")
            sys.exit(1)

        client_dirs = [f"client{i}" for i in range(1, 6)]
        
        # Copy to each client directory
        for client_dir in client_dirs:
            dest_dir = os.path.join(base_dir, client_dir)
            dest_path = os.path.join(dest_dir, "Client.py")
            dest_path2 = os.path.join(dest_dir, "Client_enhanced.py")
            
            if not os.path.exists(dest_dir):
                print(f"Warning: Directory {dest_dir} does not exist, creating it...")
                os.makedirs(dest_dir)
                
            try:
                shutil.copy2(source_path, dest_path)
                print(f"Successfully copied Client.py to /{client_dir}")
            except Exception as e:
                print(f"Error copying to {dest_dir}: {str(e)}")
                continue
            
            try:
                shutil.copy2(source_path2, dest_path2)
                print(f"Successfully copied Client_enhanced.py to /{client_dir}")
            except Exception as e:
                print(f"Error copying to {dest_dir}: {str(e)}")
                continue
    
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    copy_client_script()