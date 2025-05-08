
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import getpass
import hashlib

def display_banner():
    print("\n==================================================")
    print("  E N J L E E Z  Encryptor Tool v1.1")
    print("==================================================")
    print("   Developed by: E N J L E E Z (@enjleez) ")
    print("   Facebook | Twitter | Instagram: @enjleez")
    print("==================================================")

def check_file_format(file_path):
    if not file_path.endswith(".zip"):
        print("\n[!] Error: Please provide a ZIP file to encrypt!")
        return False
    return True

def encrypt_file(file_path, password):
    print("\n[+] Encrypting file:", file_path)
    if not check_file_format(file_path):
        return

    with open(file_path, 'rb') as f:
        data = f.read()

    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()

    with open(file_path + ".enc", 'wb') as f:
        f.write(encrypted_data)

    print("[+] File encrypted successfully as:", file_path + ".enc")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    iv = data[:16]
    encrypted_data = data[16:]
    key = hashlib.sha256(password.encode()).digest()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    output_file = file_path.replace('.enc', '.decrypted.zip')
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print("[+] File decrypted successfully as:", output_file)

def main():
    display_banner()
    action = input("Would you like to (e)ncrypt or (d)ecrypt a file? ").lower()

    if action == 'e':
        file_path = input("Enter the full path of the file: ")
        password = getpass.getpass("Enter the password: ")
        encrypt_file(file_path, password)
    elif action == 'd':
        file_path = input("Enter the full path of the encrypted file: ")
        password = getpass.getpass("Enter the password: ")
        decrypt_file(file_path, password)
    else:
        print("[!] Invalid action. Exiting.")
        exit()

if __name__ == "__main__":
    main()
