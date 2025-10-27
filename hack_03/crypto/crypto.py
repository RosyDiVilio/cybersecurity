import os  # Module to interact with the operating system (for file/directory management)
from cryptography.fernet import Fernet  # Provides symmetric encryption using AES and HMAC
from cryptography.hazmat.primitives import hashes  # Cryptographic hash functions (e.g., SHA256)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # Password-based key derivation function
import base64  # For encoding and decoding binary data to base64 (required by Fernet)
import getpass  # Used to securely prompt the user for a password (input hidden)

def generate_key(password, salt):
    """
    Derives a secure 256-bit symmetric key from a password using PBKDF2 with SHA256.
    The key is encoded in base64 to be compatible with Fernet encryption.
    
    Parameters:
        password (str): The user-provided password
        salt (bytes): A random salt to prevent dictionary/rainbow attacks
    
    Returns:
        bytes: A base64-encoded key usable by Fernet
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 as the hashing function
        length=32,                  # Generate a 32-byte (256-bit) key
        salt=salt,                  # Salt must be random and unique per encryption
        iterations=100000           # Number of hash iterations (slows brute-force attacks)
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))  # Final Fernet key

def encrypt_file(file_path, key):
    """
    Encrypts a single file in-place using the given symmetric key.
    
    Parameters:
        file_path (str): Full path to the file to be encrypted
        key (bytes): Base64-encoded Fernet key
    """
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        data = file.read()  # Read original file content
    encrypted_data = fernet.encrypt(data)  # Encrypt the data
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)  # Overwrite the file with encrypted content

def decrypt_file(file_path, key):
    """
    Decrypts a single file in-place using the given symmetric key.
    
    Parameters:
        file_path (str): Full path to the file to be decrypted
        key (bytes): Base64-encoded Fernet key
    """
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()  # Read encrypted content
    decrypted_data = fernet.decrypt(encrypted_data)  # Decrypt it
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)  # Overwrite the file with the decrypted data

def encrypt_folder(folder_path):
    """
    Encrypts all files in a given folder (recursively) using a password-derived key.
    The encryption key is derived from a user-supplied password and a generated salt.
    The salt is saved to a file called 'salt.salt' inside the folder for later decryption.
    
    Parameters:
        folder_path (str): Path to the target folder
    """
    password = getpass.getpass("Enter a password for encryption: ")  # Prompt for password
    salt = os.urandom(16)  # Generate a 16-byte secure random salt
    key = generate_key(password, salt)  # Derive a Fernet-compatible key

    # Walk through the folder and encrypt every file
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            encrypt_file(file_path, key)

    # Save the salt to a file for future key derivation (needed during decryption)
    with open(os.path.join(folder_path, 'salt.salt'), 'wb') as salt_file:
        salt_file.write(salt)

    print("✅ Folder successfully encrypted.")

def decrypt_folder(folder_path):
    """
    Decrypts all files in a given folder using a password-derived key.
    The salt used for key derivation is read from the 'salt.salt' file.
    If the password is incorrect or any file is corrupted, the process stops.
    
    Parameters:
        folder_path (str): Path to the folder to be decrypted
    """
    salt_path = os.path.join(folder_path, 'salt.salt')

    # Attempt to load the salt from file
    try:
        with open(salt_path, 'rb') as salt_file:
            salt = salt_file.read()
    except FileNotFoundError:
        print("❌ Salt file not found. Cannot proceed with decryption.")
        return

    password = getpass.getpass("Enter the password for decryption: ")
    key = generate_key(password, salt)

    # Walk through the folder and decrypt each file except the salt file itself
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            if filename != 'salt.salt':
                file_path = os.path.join(root, filename)
                try:
                    decrypt_file(file_path, key)
                except Exception as e:
                    print(f"❌ Incorrect password or corrupted file. Decryption failed: {e}")
                    return  # Abort the process if any decryption error occurs

    # Remove the salt file after successful decryption
    os.remove(salt_path)
    print("✅ Folder successfully decrypted.")

if __name__ == "__main__":
    """
    Entry point of the script.
    Prompts the user for the folder path and the operation type (encrypt or decrypt).
    Executes the selected operation accordingly.
    """
    folder = input("Enter the full path of the folder to encrypt/decrypt: ").strip()

    if not os.path.isdir(folder):
        print("❌ The provided path is not a valid folder.")
    else:
        action = input("Do you want to encrypt or decrypt the folder? (encrypt/decrypt): ").lower()
        if action == "encrypt":
            encrypt_folder(folder)
        elif action == "decrypt":
            decrypt_folder(folder)
        else:
            print("❌ Invalid option. Please type 'encrypt' or 'decrypt'.")