import os  # Used for file system operations
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding  # For key loading, hashing, and symmetric unpadding
from cryptography.hazmat.primitives.asymmetric import padding  # For RSA decryption padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES decryption
from cryptography.hazmat.backends import default_backend  # For cryptographic backend configuration


# Directory containing test files (adjusted to be relative to the script's location)
TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RANSOMWARE_SIMULATION_TEST")

# Filenames for the private key and the encrypted AES key
PRIVATE_KEY_FILE = "private_key.pem"                 # RSA private key used for decrypting the AES key
ENCRYPTED_AES_KEY_FILE = "encrypted_aes_key.bin"     # AES key previously encrypted with RSA public key

def decifra_tutti_file():
    """
    Decrypts all '.encrypted' files in the simulation folder using:
    - RSA for the AES key decryption
    - AES-CBC for the actual file decryption
    This simulates the decryption phase of a ransomware-like scenario.
    """

    # Step 1: Load the RSA private key from PEM file
    try:
        with open(os.path.join(TEST_DIR, PRIVATE_KEY_FILE), "rb") as f:
            chiave_privata = serialization.load_pem_private_key(
                f.read(),
                password=None,  # Use password=b"..." if the private key is password-protected
                backend=default_backend()
            )
    except Exception as e:
        print(f"❌ Error loading private key: {e}")
        return

    # Step 2: Decrypt the AES key using the RSA private key
    try:
        with open(os.path.join(TEST_DIR, ENCRYPTED_AES_KEY_FILE), "rb") as f:
            chiave_aes_cifrata = f.read()

        # RSA decryption with OAEP and SHA-256 padding
        chiave_aes = chiave_privata.decrypt(
            chiave_aes_cifrata,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function using SHA-256
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"❌ Error decrypting AES key: {e}")
        return

    # Step 3: Search for all files ending in ".encrypted" in the test directory
    for root, _, files in os.walk(TEST_DIR):
        for file in files:
            if file.endswith(".encrypted"):
                file_path = os.path.join(root, file)
                output_path = file_path[:-10]  # Remove ".encrypted" suffix
                print(f"🔓 Decrypting {file_path}...")

                try:
                    # Read the IV (first 16 bytes) and the encrypted file content
                    with open(file_path, "rb") as f:
                        iv = f.read(16)            # Initialization vector for AES-CBC
                        dati_cifrati = f.read()    # Remaining is the encrypted content

                    # Step 4: Set up AES-CBC decryption
                    cipher = Cipher(
                        algorithms.AES(chiave_aes),   # Use the decrypted AES key
                        modes.CBC(iv),                # Use the IV read from file
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()

                    # Step 5: Decrypt the data
                    dati_decifrati = decryptor.update(dati_cifrati) + decryptor.finalize()

                    # Step 6: Remove PKCS7 padding
                    unpadder = sym_padding.PKCS7(128).unpadder()  # 128-bit block size (16 bytes for AES)
                    dati_originali = unpadder.update(dati_decifrati) + unpadder.finalize()

                    # Step 7: Save the decrypted file with original name (removing ".encrypted")
                    with open(output_path, "wb") as f:
                        f.write(dati_originali)

                    # Delete the encrypted file after successful decryption
                    os.remove(file_path)
                    print(f"✅ Decrypted file saved as: {output_path}")

                except Exception as e:
                    print(f"❌ Error decrypting {file_path}: {e}")



if __name__ == "__main__":
    print("=== RANSOMWARE SIMULATION DECRYPTOR ===")
    print("⚠️ FOR EDUCATIONAL USE ONLY - NOT FOR MALICIOUS PURPOSES ⚠️\n")

    if not os.path.exists(TEST_DIR):
        print(f"❌ Folder not found: {TEST_DIR}")
    else:
        decifra_tutti_file()
        print("\n🎉 Decryption process completed!")