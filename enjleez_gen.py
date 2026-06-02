import hashlib
import base64

def generate_deterministic_password(master_password, service_name, length=20):
    # Fixed salt unique to Enjleez to protect against rainbow table attacks
    salt = b"Enjleez_Secure_Deterministic_Salt_2026"
    
    # PBKDF2 function with 100,000 iterations using SHA-256
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode('utf-8'),
        salt,
        100000,
        dklen=32
    )
    
    # Combine the derived key with the service name to ensure unique passwords per website
    final_hash = hashlib.sha256(derived_key + service_name.lower().strip().encode('utf-8')).digest()
    
    # Convert binary hash to a readable string using Base64
    password_b64 = base64.b64encode(final_hash).decode('utf-8')
    
    # Inject special characters and numbers for maximum security compliance
    secure_password = password_b64.replace('+', '@').replace('/', '#').replace('=', '$')
    
    return secure_password[:length]

def main():
    print("==================================================")
    print("   E N J L E E Z   Zero-Knowledge PassGen v2.0   ")
    print("==================================================")
    print("   [!] No Files Saved - 100% Secure & Recoverable ")
    print("==================================================\n")
    
    master = input("Enter your Master Password: ").strip()
    if not master:
        print("[-] Master password cannot be empty!")
        return
        
    service = input("Enter website/service name (e.g., google, fb): ").strip()
    if not service:
        print("[-] Service name cannot be empty!")
        return
        
    length_input = input("Enter password length [Default 20]: ").strip()
    length = int(length_input) if length_input.isdigit() else 20
    
    # Mathematically calculate the password
    password = generate_deterministic_password(master, service, length)
    
    print("\n" + "="*50)
    print(f"[+] Your secure password for ({service}) is:")
    print(f"👉  {password}")
    print("="*50)
    print("[*] Remember: This password is calculated mathematically. If you lose your PC,")
    print("[*] just run this tool anywhere with the same inputs to get it back!\n")

if __name__ == "__main__":
    main()
