import secrets
import string

def generate_secure_password(length=24):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(characters) for _ in range(length))

def main():
    print("==================================================")
    print("      E N J L E E Z   Password Generator v1.0    ")
    print("==================================================")
    print("   Developed by: E N J L E E Z (@enjleez)         ")
    print("==================================================\n")
    
    length_input = input("Enter password length [Default 24]: ").strip()
    length = int(length_input) if length_input.isdigit() else 24
    
    password = generate_secure_password(length)
    
    file_name = input("Enter output file name (e.g., my_pass.txt): ").strip()
    if not file_name:
        file_name = "enjleez_password.txt"
    
    if not file_name.endswith(".txt"):
        file_name += ".txt"
        
    try:
        with open(file_name, "w") as f:
            f.write(password)
        print(f"\n[+] Success! Secure password generated and saved to: {file_name}")
        print("[!] Note: Now you can encrypt this file using 'Enjleez Encryptor Tool' to secure it!")
    except Exception as e:
        print(f"[-] Error saving file: {e}")

if __name__ == "__main__":
    main()
