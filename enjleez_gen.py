import hashlib
import base64
import os

# ألوان الـ ANSI القياسية للواجهة
G = '\033[92m'  # أخضر فسفوري
R = '\033[91m'  # أحمر دموي
Y = '\033[93m'  # أصفر تحذيري
C = '\033[96m'  # سماوي هكر
W = '\033[0m'   # إعادة اللون الافتراضي
BC = '\033[1m'  # خط عريض

def generate_strict_password(master_password, private_pepper, service_name, length=20):
    if length < 8:
        length = 8
        
    static_base = b"Enjleez_Core_Salt_v4.0_"
    dynamic_salt = hashlib.sha256(static_base + private_pepper.strip().encode('utf-8')).digest()
    
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode('utf-8'),
        dynamic_salt,
        100000,
        dklen=32
    )
    
    final_hash = hashlib.sha256(derived_key + service_name.lower().strip().encode('utf-8')).digest()
    password_b64 = base64.b64encode(final_hash).decode('utf-8')
    clean_base = password_b64.replace('+', '').replace('/', '').replace('=', '')
    
    mandatory_upper = chr(65 + (final_hash[0] % 26))
    mandatory_lower = chr(97 + (final_hash[1] % 26))
    mandatory_digit = chr(48 + (final_hash[2] % 10))
    
    special_chars = "@#$%!*&?"
    mandatory_special = special_chars[final_hash[3] % len(special_chars)]
    
    prefix = mandatory_upper + mandatory_lower + mandatory_digit + mandatory_special
    remaining_length = length - len(prefix)
    final_password = prefix + clean_base[:remaining_length]
    
    return final_password

def print_banner():
    os.system('clear') # تنظيف الشاشة لتنسيق الواجهة
    banner = f"""{G}{BC}
███████╗███╗   ██╗     ██████╗ ██╗     ███████╗███████╗███████╗
██╔════╝████╗  ██║     ╚══██║  ██║     ██╔════╝██╔════╝╚══███╔╝
█████╗  ██╔██╗ ██║        ██║  ██║     █████╗  █████╗    ███╔╝ 
██╔══╝  ██║╚██╗██║   ██   ██║  ██║     ██╔══╝  ██╔══╝   ███╔╝  
███████╗██║ ╚████║   ╚█████╔╝  ███████╗███████╗███████╗███████╗
╚══════╝╚═╝  ╚═══╝    ╚════╝   ╚══════╝╚══════╝╚══════╝╚══════╝
             [ P A S S W O R D   G E N E R A T O R ]
    """
    print(banner)
    print(f"{C}[+] Project: Enjleezect | Version: {G}v4.5 {C}| Status: {G}SECURE")
    print(f"{C}[+] Architecture: Zero-Knowledge & Recoverable Offline")
    print(f"{C}[+] Facebook: {W}https://facebook.com/enjleez")
    print(f"{G}--------------------------------------------------{W}\n")

def main():
    print_banner()
    
    master = input(f"{C}[?] Enter your Main Master Password: {W}").strip()
    if not master:
        print(f"{R}[- ] Error: Master password cannot be empty!{W}")
        return
        
    pepper = input(f"{C}[?] Enter your Secret Private Word: {W}").strip()
    if not pepper:
        print(f"{R}[- ] Error: Secret Private Word cannot be empty!{W}")
        return
        
    service = input(f"{C}[?] Enter website/service name (e.g., google): {W}").strip()
    if not service:
        print(f"{R}[- ] Error: Service name cannot be empty!{W}")
        return
        
    length_input = input(f"{C}[?] Enter password length [Default 20]: {W}").strip()
    length = int(length_input) if length_input.isdigit() else 20
    
    password = generate_strict_password(master, pepper, service, length)
    
    print("\n" + f"{G}="*50)
    print(f"{C}[+] Your strict secure password for ({G}{service}{C}) is:")
    print(f"{Y}👉  {BC}{password}{W}")
    print(f"{G}="*50)
    print(f"{C}[*] Complies with all website security requirements globally.{W}\n")

if __name__ == "__main__":
    main()
