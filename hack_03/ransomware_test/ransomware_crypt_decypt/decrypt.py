# Import necessary libraries
import os  # For interacting with the operating system, like file paths
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding # Core cryptography primitives
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding # For RSA asymmetric cryptography (specifically, the padding scheme)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # For AES symmetric decryption
from cryptography.hazmat.backends import default_backend # Specifies the cryptography backend to use

### 🔐 CONFIGURATION ###
# Define the path to the test directory where encrypted files are located.
# It's constructed relative to this script's location.
TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RANSOMWARE_SIMULATION_TEST")
# The filename of the RSA private key, needed to decrypt the AES key.
PRIVATE_KEY_FILE = "private_key.pem"
# The filename of the file containing the RSA-encrypted AES key.
ENCRYPTED_AES_KEY_FILE = "encrypted_aes_key.bin"

### 🔓 MAIN DECRYPTION FUNCTION ###
def decifra_tutti_file(): # "decrypt_all_files"
    """
    Finds and decrypts all ".encrypted" files in the test directory
    using the RSA private key to first unlock the symmetric AES key.
    """
    # --- Step 1: Load the RSA private key from its file ---
    try:
        private_key_path = os.path.join(TEST_DIR, PRIVATE_KEY_FILE)
        # Open the private key file in binary read mode.
        with open(private_key_path, "rb") as f:
            # Use the serialization module to load the PEM-formatted private key.
            # password=None because the key file was not encrypted with a password.
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        # If loading the key fails (e.g., file not found), print an error and stop.
        print(f"❌ Error loading private key: {e}")
        return

    # --- Step 2: Decrypt the symmetric (AES) key using the RSA private key ---
    try:
        encrypted_aes_key_path = os.path.join(TEST_DIR, ENCRYPTED_AES_KEY_FILE)
        # Open and read the binary file containing the encrypted AES key.
        with open(encrypted_aes_key_path, "rb") as f:
            encrypted_aes_key = f.read()

        # Use the loaded RSA private key to decrypt the AES key.
        # It is CRITICAL to use the exact same padding scheme (OAEP with SHA256)
        # that was used during encryption.
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        # If decrypting the AES key fails, print an error and stop.
        print(f"❌ Error decrypting AES key: {e}")
        return

    # --- Step 3: Find and decrypt each target file ---
    # Walk through the test directory to find all files.
    for root, _, files in os.walk(TEST_DIR):
        for file in files:
            # Check if the file has the ".encrypted" extension.
            if file.endswith(".encrypted"):
                file_path = os.path.join(root, file)
                # Determine the original filename by removing the ".encrypted" extension.
                output_path = file_path[:-10]
                print(f"🔓 Decrypting {file_path}...")

                try:
                    # Open the encrypted file to read its contents.
                    with open(file_path, "rb") as f:
                        # The first 16 bytes are the Initialization Vector (IV), which is required for CBC mode.
                        iv = f.read(16)
                        # The rest of the file is the actual ciphertext.
                        encrypted_data = f.read()

                    # Set up the AES cipher in CBC mode with the decrypted AES key and the IV from the file.
                    cipher = Cipher(
                        algorithms.AES(aes_key),
                        modes.CBC(iv),
                        backend=default_backend()
                    )
                    # Create a decryptor object.
                    decryptor = cipher.decryptor()

                    # Decrypt the data.
                    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

                    # The decrypted data still has the padding from encryption; it must be removed.
                    # Create a PKCS7 unpadder.
                    unpadder = sym_padding.PKCS7(128).unpadder()
                    # Remove the padding to get the original data.
                    original_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

                    # Write the fully restored, original data to the output file.
                    with open(output_path, "wb") as f:
                        f.write(original_data)

                    # After successful decryption, delete the now-redundant ".encrypted" file.
                    os.remove(file_path)
                    print(f"✅ Decrypted file saved as: {output_path}")

                except Exception as e:
                    # If an error occurs with a specific file, print it and continue to the next one.
                    print(f"❌ Error decrypting {file_path}: {e}")

# This block ensures the code runs only when the script is executed directly.
if __name__ == "__main__":
    print("=== RANSOMWARE SIMULATION DECRYPTOR ===")
    print("⚠️ EDUCATIONAL USE ONLY - NOT FOR REAL ATTACKS ⚠️\n")

    # Check if the target directory exists before trying to decrypt.
    if not os.path.exists(TEST_DIR):
        print(f"❌ Directory {TEST_DIR} not found!")
    else:
        # If the directory exists, call the main decryption function.
        decifra_tutti_file()
        print("\n🎉 Decryption complete!")