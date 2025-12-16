from cryptography.fernet import Fernet
import os

KEY_FILE = "secret.key"
LOG_FILE = "secure_logs.enc"

def load_key(path=KEY_FILE):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Key file not found: {path}")
    with open(path, "rb") as f:
        return f.read()

def decrypt_logs(key_path=KEY_FILE, log_path=LOG_FILE):
    key = load_key(key_path)
    cipher = Fernet(key)

    if not os.path.exists(log_path):
        print(f"No log file found at: {log_path}")
        return

    with open(log_path, "rb") as f:
        lines = f.readlines()

    if not lines:
        print("Log file is empty.")
        return

    print("Decrypted logs:\n----------------")
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            plaintext = cipher.decrypt(line)
            print(f"{i}: {plaintext.decode()}")
        except Exception as e:
            print(f"{i}: [ERROR decrypting line] {e}")

if __name__ == "__main__":
    try:
        decrypt_logs()
    except Exception as ex:
        print(f"Error: {ex}")
