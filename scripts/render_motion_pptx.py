import os
import subprocess
import time
from pptx import Presentation
from pptx.util import Inches

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
HTML_PATH = r"c:\Users\imtah\OneDrive\Desktop\Waf\showcase\presentation_deck.html"
FRAMES_DIR = r"c:\Users\imtah\OneDrive\Desktop\Waf\presentation_assets\motion_slides"
OUTPUT_PPTX = r"C:\Users\imtah\OneDrive\Desktop\ROKH_WAF_PRESENTATION.pptx"

os.makedirs(FRAMES_DIR, exist_ok=True)

SPEAKER_NOTES = [
    # Slide 0
    "معرفی پروژه و اهداف معماری: سامانه رُخ با زبان Safe Rust بدون نشت حافظه، پردازش Zero-Copy با تاخیر 0.04 میلی‌ثانیه و خاتمه 0-RTT در لبه شبکه توسعه یافته است. طراح: طاها وزیری.",
    # Slide 1
    "خط لوله Deobfuscator و توکنایزیشن معنایی: شکستن انکودینگ‌های چندگانه URL، انتیتی‌های HTML5، کاراکترهای یونیکد NFKC و حذف کامنت‌های دیتابیس قبل از ورود به موتور تطبیق الگو.",
    # Slide 2
    "پایداری ریاضی موتور PikeVM / Lazy DFA: کریت regex راست از اتوماتای تامپسون بهره می‌برد که فاقد هرگونه الگوریتم Backtracking است و پیچیدگی زمانی خطی O(m·n) را از نظر ریاضی تضمین می‌کند.",
    # Slide 3
    "پدافند ضد دیداس و معمای اثبات کار: چالش HMAC-SHA256 امضاشده توسط سرور با پنجره اعتبار ۶۰ ثانیه‌ای و کش LRU جهت جلوگیری قطعی از Replay Attack. تحمیل هزینه پردازشی به کلاینت مهاجم.",
    # Slide 4
    "هوش مصنوعی و انتروپی داده شانون: استنتاج رگرسیون لجستیک L2 در 0.06ms بدون خطای Branch Misprediction درخت‌های تصمیم. مسدودسازی شل‌کدها در H(X) > 4.65. تفکیک متریک‌ها: ۸۵.۴٪ دقت ماکروی تست مجزا، ۹۲.۳۴٪ مهار کل WAF، ۱۰۰٪ پروب‌های SSTI.",
    # Slide 5
    "کارنامه بنچمارک چندلایه‌ای: ۷۹۶ پکت کل (۴۹۶ حمله + ۱۰۰ Evasion + ۲۰۰ مجاز). مهار ۴۵۸ از ۴۹۶ حمله کل (۹۲.۳۴٪). خطای مثبت کاذب ۰.۰۰٪. تبیین نرخ ۸۲٪ برای RCE به دلیل تنوع شل و حفظ تعادل False Positive.",
    # Slide 6
    "مقایسه زنده قبل و بعد (Before vs After) و دمو: اتصال مستقیم به پورت ۹۰۰۰ منجر به نفوذ ۲۰۰ می‌شود؛ درگاه ۸۰۸۰ در 0.04ms پاسخ ۴۰۳ می‌دهد. دستورات تست SQLi و XSS در ویندوز با کوتیشن صحیح.",
    # Slide 7
    "پاسخ‌های دندان‌شکن به سوالات چالشی داوران: دفاع از Lazy DFA، چرایی رگرسیون لجستیک بر XGBoost، تفکیک سه عدد آماری و جلوگیری از Replay Attack با HMAC و LRU.",
    # Slide 8
    "شناسنامه مهندسی و توسعه‌دهنده: طاها وزیری. استانداردهای OWASP Top 10، پروتکل RFC 7230 و TLS 1.3 0-RTT با هسته Rust 2024 و بدون هیچ بلاک Unsafe.",
    # Slide 9
    "پایان ارائه، تشکر از اساتید و داوران گرامی و اعلام آمادگی برای بررسی کدهای منبع و پاسخ به سوالات تکمیلی جلسه دفاع رسمی (پاییز ۲۰۲۶)."
]

print("=" * 70)
print(" [*] RENDERING FULL-BLEED 1920x1080 MOTION GRAPHIC SLIDES VIA CHROME")
print("=" * 70)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank_layout = prs.slide_layouts[6]

for i in range(10):
    img_path = os.path.join(FRAMES_DIR, f"slide_{i}.png")
    url = f"file:///{HTML_PATH.replace(os.sep, '/')}?snap=1&slide={i}"
    
    cmd = [
        CHROME_PATH,
        "--headless=new",
        "--hide-scrollbars",
        "--window-size=1920,1080",
        f"--screenshot={img_path}",
        url
    ]
    
    print(f" -> Capturing Motion Graphic Slide {i+1}/10...")
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    if os.path.exists(img_path):
        slide = prs.slides.add_slide(blank_layout)
        # Add full-bleed image fitting 16:9 exactly
        slide.shapes.add_picture(img_path, 0, 0, width=Inches(13.333), height=Inches(7.5))
        # Add Speaker Notes
        slide.notes_slide.notes_text_frame.text = SPEAKER_NOTES[i]
        print(f"    [+] Slide {i+1} embedded ({os.path.getsize(img_path)} bytes)")

prs.save(OUTPUT_PPTX)
print("=" * 70)
print(f" [SUCCESS] Master Motion Graphic PowerPoint saved to:")
print(f" {OUTPUT_PPTX}")
print("=" * 70)
