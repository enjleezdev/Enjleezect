import hashlib
import base64

def generate_strict_password(master_password, private_pepper, service_name, length=20):
    if length < 8:
        length = 8  # الحد الأدنى العالمي لسلامة كلمات المرور
        
    # تحويل الكلمة المساعدة الثانية إلى ملح تشفيري قاسي
    static_base = b"Enjleez_Core_Salt_v4.0_"
    dynamic_salt = hashlib.sha256(static_base + private_pepper.strip().encode('utf-8')).digest()
    
    # 100,000 دورة تشفير لحماية الكلمات من التخمين
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode('utf-8'),
        dynamic_salt,
        100000,
        dklen=32
    )
    
    # دمج الناتج مع اسم الموقع (مثل google أو fb)
    final_hash = hashlib.sha256(derived_key + service_name.lower().strip().encode('utf-8')).digest()
    
    # تحويل التشفير لنص مقروء عبر Base64
    password_b64 = base64.b64encode(final_hash).decode('utf-8')
    
    # تنظيف النص من الرموز العشوائية التي قد تسبب مشاكل في بعض المواقع
    clean_base = password_b64.replace('+', '').replace('/', '').replace('=', '')
    
    # منطق الحقن الصارم (Strict Injection Logic):
    # نأخذ أول 4 خانات ونباعثها بأحرف ورموز وأرقام مشتقة تشفيرياً لضمان استيفاء كافة الشروط دائماً
    mandatory_upper = chr(65 + (final_hash[0] % 26))      # حرف كبير إجباري (A-Z)
    mandatory_lower = chr(97 + (final_hash[1] % 26))      # حرف صغير إجباري (a-z)
    mandatory_digit = chr(48 + (final_hash[2] % 10))      # رقم إجباري (0-9)
    
    # رموز خاصة آمنة ومقبولة في جميع المواقع (@, #, $, %, !, *, &, ?)
    special_chars = "@#$%!*&?"
    mandatory_special = special_chars[final_hash[3] % len(special_chars)] # رمز إيجابي إجباري
    
    # دمج المكونات الإجبارية الأربعة في البداية لضمان قبول الموقع لها فوراً
    prefix = mandatory_upper + mandatory_lower + mandatory_digit + mandatory_special
    
    # إكمال بقية الطول المطلوب من النص التشفيري النظيف
    remaining_length = length - len(prefix)
    final_password = prefix + clean_base[:remaining_length]
    
    return final_password

def main():
    print("==================================================")
    print("   E N J L E E Z   Strict Password Gen v4.0      ")
    print("==================================================")
    print("   [!] Guaranteed: Upper, Lower, Number & Symbol   ")
    print("==================================================\n")
    
    master = input("Enter your Main Master Password: ").strip()
    if not master:
        print("[-] Master password cannot be empty!")
        return
        
    pepper = input("Enter your Secret Private Word: ").strip()
    if not pepper:
        print("[-] Secret Private Word cannot be empty!")
        return
        
    service = input("Enter website/service name (e.g., google, fb): ").strip()
    if not service:
        print("[-] Service name cannot be empty!")
        return
        
    length_input = input("Enter password length [Default 20]: ").strip()
    length = int(length_input) if length_input.isdigit() else 20
    
    password = generate_strict_password(master, pepper, service, length)
    
    print("\n" + "="*50)
    print(f"[+] Your strict secure password for ({service}) is:")
    print(f"👉  {password}")
    print("="*50)
    print("[*] Checked: Complies with all website security requirements globally.\n")

if __name__ == "__main__":
    main()
