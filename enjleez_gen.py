import hashlib
import base64

def generate_deterministic_password(master_password, service_name, length=20):
    # الملح (Salt) الثابت والخاص بك لزيادة الأمان ومنع هجمات جداول القوس قزح
    salt = b"Enjleez_Secure_Deterministic_Salt_2026"
    
    # استخدام خوارزمية PBKDF2 لعمل 100,000 دورة تشفير واشتقاق مفتاح قوي
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode('utf-8'),
        salt,
        100000,
        dklen=32
    )
    
    # دمج اسم الموقع لضمان أن كل موقع له كلمة مرور مختلفة تماماً
    final_hash = hashlib.sha256(derived_key + service_name.lower().strip().encode('utf-8')).digest()
    
    # تحويل التشفير إلى نص مقروء باستخدام Base64
    password_b64 = base64.b64encode(final_hash).decode('utf-8')
    
    # تنظيف النص وتعديله ليحتوي على رموز وأرقام وحروف، وقصه حسب الطول المطلوب
    # قمنا باستبدال بعض الحروف القياسية برموز خاصة لزيادة تعقيد كلمة المرور أمنياً
    secure_password = password_b64.replace('+', '@').replace('/', '#').replace('=', '$')
    
    return secure_password[:length]

def main():
    print("==================================================")
    print("   E N J L E E Z   Zero-Knowledge PassGen v2.0   ")
    print("==================================================")
    print("   [!] No Files Saved - 100% Secure & Recoverable ")
    print("==================================================\n")
    
    master = input("Enter your Master Password (كلمتك السرية الثابتة): ").strip()
    if not master:
        print("[-] Master password cannot be empty!")
        return
        
    service = input("Enter website/service name (e.g., google, facebook): ").strip()
    if not service:
        print("[-] Service name cannot be empty!")
        return
        
    length_input = input("Enter password length [Default 20]: ").strip()
    length = int(length_input) if length_input.isdigit() else 20
    
    # توليد كلمة المرور رياضياً
    password = generate_deterministic_password(master, service, length)
    
    print("\n" + "="*50)
    print(f"[+] Your secure password for ({service}) is:")
    print(f"👉  {password}")
    print("="*50)
    print("[*] Remember: This password is calculated mathematically. If you lose your PC,")
    print("[*] just run this tool anywhere with the same inputs to get it back!")

if __name__ == "__main__":
    main()
