import base64
import os
import sys

# ألوان الـ ANSI القياسية للواجهة
G = '\033[92m'  # أخضر فسفوري
R = '\033[91m'  # أحمر دموي
Y = '\033[93m'  # أصفر تحذيري
C = '\033[96m'  # سماوي هكر
W = '\033[0m'   # إعادة اللون الافتراضي
BC = '\033[1m'  # خط عريض

def print_banner():
    os.system('clear')
    banner = f"""{G}{BC}
███████╗███╗   ██╗     ██████╗ ██╗     ███████╗███████╗███████╗
██╔════╝████╗  ██║     ╚══██║  ██║     ██╔════╝██╔════╝╚══███╔╝
█████╗  ██╔██╗ ██║        ██║  ██║     █████╗  █████╗    ███╔╝ 
██╔══╝  ██║╚██╗██║   ██   ██║  ██║     ██╔══╝  ██╔══╝   ███╔╝  
███████╗██║ ╚████║   ╚█████╔╝  ███████╗███████╗███████╗███████╗
╚══════╝╚═╝  ╚═══╝    ╚════╝   ╚══════╝╚══════╝╚══════╝╚══════╝
         [ C O D E   O B F U S C A T O R   G E N ]
    """
    print(banner)
    print(f"{C}[+] Project: Enjleezect | Version: {G}v3.0 {C}| Status: {G}ACTIVE")
    print(f"{C}[+] Target: Safe Code Text Obfuscation (No Overwrite)")
    print(f"{C}[+] Facebook: {W}https://facebook.com")
    print(f"{G}--------------------------------------------------{W}\n")

def obfuscate_text(original_code):
    # تشفير الكود المدخل بـ Base64
    encoded_bytes = base64.b64encode(original_code.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')
    
    # بناء قالب التشغيل الذاتي في الذاكرة
    protected_stub = f"""# Protected by Enjleez Crypter
import base64
exec(base64.b64decode('{encoded_string}').decode('utf-8'))"""
    return protected_stub

def main():
    print_banner()
    
    print(f"{Y}[*] Choose input method:{W}")
    print(f" 1. Read from an existing file")
    print(f" 2. Paste code directly into terminal")
    choice = input(f"{C}[?] Select (1 or 2): {W}").strip()
    
    original_code = ""
    
    if choice == "1":
        file_name = input(f"{C}[?] Enter python file name to read (e.g., app.py): {W}").strip()
        if not os.path.exists(file_name):
            print(f"{R}[-] Error: File not found!{W}")
            return
        with open(file_name, 'r', encoding='utf-8') as f:
            original_code = f.read()
            
    elif choice == "2":
        print(f"{Y}[*] Paste your code below. When finished, press Ctrl+D (on a new line) to process:{W}\n")
        original_code = sys.stdin.read()
        
    else:
        print(f"{R}[-] Invalid choice.{W}")
        return

    if not original_code.strip():
        print(f"{R}[-] Error: Code is empty!{W}")
        return

    # توليد الكود المشفر
    crypted_result = obfuscate_text(original_code)
    
    print("\n" + f"{G}="*50)
    print(f"{C}[+] Your Obfuscated Code is ready!{W}")
    print(f"{G}="*50 + f"{W}\n")
    
    # طباعة الكود المشفر في الشاشة لنسخه طوالي
    print(f"{G}{crypted_result}{W}\n")
    print(f"{G}="*50)
    
    # خيار إضافي لحفظه في ملف منفصل إذا العميل عاير كدة
    save_choice = input(f"{C}[?] Do you want to save this text to a separate file? (y/n): {W}").strip().lower()
    if save_choice == 'y':
        out_name = input(f"{C}[?] Enter output file name (e.g., safe_code.py): {W}").strip()
        if out_name:
            with open(out_name, 'w', encoding='utf-8') as f:
                f.write(crypted_result)
            print(f"{G}[SUCCESS] Saved safely as: {out_name}{W}")

if __name__ == "__main__":
    main()
