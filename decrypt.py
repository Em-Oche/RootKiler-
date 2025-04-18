# ⚠️ EDUCATIONAL LAB PROJECT ONLY ⚠️
# This is a decryption script for a ransomware simulation in an isolated lab.
# DO NOT use outside a controlled environment.

import os
import logging
from cryptography.fernet import Fernet

# Configuration
TARGET_DIR = "C:\\test_files"
ENCRYPTED_EXT = ".encrypted"
KEY_FILE = "decryption_key.txt"
LOG_FILE = "decryption_log.txt"

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def load_key():
    """Load the decryption key."""
    with open(KEY_FILE, "rb") as f:
        return f.read()

def decrypt_file(file_path, cipher):
    """Decrypt a single file and restore the original."""
    try:
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        original_path = file_path.replace(ENCRYPTED_EXT, "")
        with open(original_path, "wb") as f:
            f.write(decrypted_data)
        os.remove(file_path)
        logging.info(f"Decrypted: {file_path} -> {original_path}")
        return True
    except Exception as e:
        logging.error(f"Error decrypting {file_path}: {str(e)}")
        return False

def main():
    key = load_key()
    cipher = Fernet(key)
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            if file.endswith(ENCRYPTED_EXT):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, cipher)

if __name__ == "__main__":
    main()