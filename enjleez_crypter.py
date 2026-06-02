import base64
import os
import sys

# ألوان الـ ANSI القياسية لتزيين الواجهة بألوان الهكر
G = '\033[92m'  # أخضر فسفوري
R = '\033[91m'  # أحمر دموي
Y = '\033[93m'  # أصفر تحذيري
C = '\033[96m'  # سماوي هكر
W = '\033[0m'   # إعادة اللون الافتراضي
BC = '\033[1m'  # خط عريض

def print_banner():
    os.system('clear') # تنظيف الشاشة لتنسيق الواجهة
    banner = f"""{G}{BC}
███████╗███╗   ██╗     ██████╗ ██╗     ███████╗███████╗███████╗
██╔════╝████╗  ██║     ╚══██║  ██║     ██╔════╝██╔════╝╚══███╔╝
█████╗  ██╔██╗ ██║        ██║  ██║     █████╗  █████╗    ███╔╝ 
██╔══╝  ██║╚██╗██║   ██   ██║  ██║     ██╔══╝  ██╔══╝   ███╔╝  
███████╗██║ ╚████║   ╚█████╔╝  ███████╗███████╗███████╗███████╗
╚══════╝╚═╝  ╚═══╝    ╚════╝   ╚══════╝╚══════╝╚══════╝╚══════╝
             [ C R Y P T E R  &  O B F U S C A T O R ]
    """
    print(banner)
    print(f"{C}[+] Project: Enjleezect | Version: {G}v1.0 {C}| Status: {G}ACTIVE")
    print(f"{C}[+] Target: Python Source Code Obfuscation & Protection")
    print(f"{C}[+] Facebook: {W}https://facebook.com")
    print(f"{G}--------------------------------------------------{W}\n")

def encrypt_code(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"{R}[-] Error: Target file '{input_file}' not found!{W}")
        return

    try:
        # قراءة الكود الأصلي المراد حمايته تعميته
        with open(input_file, 'r', encoding='utf-8') as f:
            original_code = f.read()

        # تشفير الكود الأصلي باستخدام التشفير الطبقي الأساسي وتحويله لنص معزول
        encoded_bytes = base64.b64encode(original_code.encode('utf-8'))
        encoded_string = encoded_bytes.decode('utf-8')

        # بناء كود فك التشفير الذاتي (Stub) الذي سيقوم بفرش الكود في الذاكرة العشوائية وتشغيله
        # نستخدم دالة exec(base64.b64decode(...)) ليعمل الكود في الذاكرة دون تخزينه كملف مكشوف
        protected_stub = f"""# Protected by Enjleez Crypter v1.0
import base64
exec(base64.b64decode('{encoded_string}').decode('utf-8'))
"""

        # حفظ الملف المعمى الجديد
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(protected_stub)

        print(f"{G}[SUCCESS] Obfuscation process completed!{W}")
        print(f"{C}[+] Encrypted File Saved As: {Y}{output_file}{W}")
        print(f"{C}[*] Try opening the new file; the code is now complete gibberish.{W}\n")

    except Exception as e:
        print(f"{R}[-] An unexpected error occurred: {e}{W}")

def main():
    print_banner()
    
    input_target = input(f"{C}[?] Enter the name of the python file to encrypt (e.g., app.py): {W}").strip()
    if not input_target:
        print(f"{R}[- ] Error: Input file name cannot be empty!{W}")
        return

    output_target = input(f"{C}[?] Enter the output file name (e.g., crypted_app.py): {W}").strip()
    if not output_target:
        output_target = "crypted_" + input_target

    print(f"\n{Y}[*] Initiating code encryption layers...{W}")
    encrypt_code(input_target, output_target)

if __name__ == "__main__":
    main()
