import json
import os

ASSETS_DIR = r"c:\Users\imtah\OneDrive\Desktop\Waf\presentation_assets"
BATCH_FILE = os.path.join(ASSETS_DIR, "gslides_batch.json")

ops = [
    # Remove default slide placeholders
    {"op": "delete-element", "element": "i0"},
    {"op": "delete-element", "element": "i1"},

    # SLIDE 1 (p)
    {"op": "set-background", "slide": "p", "color": "#07090E"},
    {"op": "add-textbox", "slide": "p", "text": "🛡️ دیواره آتش لایه ۷ و پروکسی ابری ضد دیداس", "x": 100, "y": 60, "width": 800, "height": 35, "font_size": 16, "bold": True, "color": "#F6821F", "font_family": "Tahoma", "alignment": "center"},
    {"op": "add-textbox", "slide": "p", "text": "سامانه دیواره آتش ابری رُخ (Rokh WAF)", "x": 60, "y": 120, "width": 880, "height": 70, "font_size": 36, "bold": True, "color": "#FFFFFF", "font_family": "Tahoma", "alignment": "center"},
    {"op": "add-textbox", "slide": "p", "text": "پدافند غیرهمگام لبه، بازرسی عمیق بسته‌ها (DPI)، موتور تصمیم‌گیری قطعی DFA و تحلیل هوشمند تهدیدات", "x": 80, "y": 210, "width": 840, "height": 50, "font_size": 16, "color": "#CBD5E1", "font_family": "Tahoma", "alignment": "center"},
    {"op": "add-shape", "slide": "p", "shape_type": "RECTANGLE", "x": 380, "y": 290, "width": 240, "height": 4, "background_color": "#F6821F"},
    {"op": "add-textbox", "slide": "p", "text": "توسعه‌دهنده و معمار سیستم: طاها وزیری (Taha Vaziri)", "x": 100, "y": 320, "width": 800, "height": 40, "font_size": 18, "bold": True, "color": "#06B6D4", "font_family": "Tahoma", "alignment": "center"},
    {"op": "add-textbox", "slide": "p", "text": "Rust (Tokio / Axum) · Python SOC (FastAPI) · O(N) Regex DFA · Zero-Copy Buffer", "x": 100, "y": 375, "width": 800, "height": 30, "font_size": 13, "color": "#10B981", "font_family": "Courier New", "alignment": "center"},
    {"op": "set-notes", "slide": "p", "text": "معرفی پروژه و اهداف سامانه برای هیئت داوران توسط طاها وزیری."},

    # SLIDE 2: Executive Summary
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_2"},
    {"op": "set-background", "slide": "SLIDE_2", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_2", "text": "مقدمه و صورت مسئله // چالش‌های WAFهای سنتی و ضرورت پدافند بومی", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#06B6D4", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_2", "text": "۱. حملات لایه کاربرد (Layer 7):\nبیش از ۸۰٪ نفوذهای موفق وب در لایه ۷ رخ می‌دهند؛ فایروال‌های پورت و IP توان بازرسی محتوای پکت را ندارند.", "x": 50, "y": 100, "width": 420, "height": 140, "font_size": 14, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_2", "text": "۲. تاخیر بالا و افت سئو (Latency):\nسامانه‌های سنتی مانند ModSecurity تاخیرهای ده‌میلی‌ثانیه‌ای اضافه کرده و رتبه سایت را تخریب می‌کنند.", "x": 510, "y": 100, "width": 420, "height": 140, "font_size": 14, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_2", "text": "۳. مخاطرات حافظه در C/C++:\nآسیب‌پذیری‌های سرریز بافر و نشت حافظه در هسته‌های قدیمی WAF موجب تهدید امنیتی خود فایروال می‌شوند.", "x": 50, "y": 260, "width": 420, "height": 140, "font_size": 14, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_2", "text": "۴. بحران قفل ReDoS:\nموتورهای عبارات منظم بازگشتی در مواجهه با پی‌لودهای انفجاری دچار زمان نمایی O(2^N) و قفل سرور می‌شوند.", "x": 510, "y": 260, "width": 420, "height": 140, "font_size": 14, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_2", "text": "تشریح آمارهای رسمی OWASP و نقایص فایروال‌های موجود و چرایی ساخت سامانه رُخ با راست."},

    # SLIDE 3: Architecture
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_3"},
    {"op": "set-background", "slide": "SLIDE_3", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_3", "text": "معماری دو لایه // خط لوله بازرسی عمیق بسته (DPI Pipeline)", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#F6821F", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_3", "text": "هسته پردازشی Rust (پورت 8080):\n• موتور غیرهمگام با Tokio Runtime و سرور Axum\n• هدایت بافر حافظه به شیوه Zero-Copy با تاخیر 0.04ms\n• سد دفاعی IP Jail و مهار ترافیک دیداس پیش از سرور", "x": 50, "y": 120, "width": 420, "height": 260, "font_size": 15, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_3", "text": "مرکز عملیات امنیت Python SOC (پورت 9000):\n• داشبورد گرافیکی بلادرنگ با وب‌سوکت\n• موتور هوش مصنوعی AegisNeuralBrain و انتروپی شانون\n• لاگ غیرهمگام رویدادها در SQLite WAL بدون وقفه پردازشی", "x": 510, "y": 120, "width": 420, "height": 260, "font_size": 15, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_3", "text": "توضیح معماری دو لایه و تفکیک وظایف هسته سریع Rust از مرکز پایش هوشمند Python SOC."},

    # SLIDE 4: 5-Layer Anti-Evasion
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_4"},
    {"op": "set-background", "slide": "SLIDE_4", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_4", "text": "خط لوله ضد دورزدن // خنثی‌سازی تکنیک‌های Evasion در ۵ لایه", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#06B6D4", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_4", "text": "گام ۰۱ // URL Decode تو در تو:\nشکستن انکودینگ‌های چندگانه تا رسیدن به فرم خام پی‌لود.\n%252e%252e%2f → ../", "x": 50, "y": 100, "width": 420, "height": 140, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_4", "text": "گام ۰۲ // تبدیل انتیتی‌های HTML5:\nرمزگشایی کاراکترهای اسکیپ‌شده جهت استخراج تگ‌های XSS.\n&colon;&quot; → :\"", "x": 510, "y": 100, "width": 420, "height": 140, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_4", "text": "گام ۰۳ // نرمال‌سازی یونیکد Full-Width:\nتبدیل کاراکترهای عریض به NFKC استاندارد و حذف بایت نال.\n＜script＞ → <script>", "x": 50, "y": 260, "width": 420, "height": 140, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_4", "text": "گام ۰۴ // پالایش کامنت‌های دیتابیس:\nحذف کامنت‌های تزریق‌شده درون واژگان کلیدی دیتابیس.\nUN/**/ION → UNION", "x": 510, "y": 260, "width": 420, "height": 140, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_4", "text": "روش‌های دور زدن و پالایش ۵ مرحله‌ای پکت‌ها پیش از ارسال به موتور تصمیم‌گیری."},

    # SLIDE 5: Deterministic DFA
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_5"},
    {"op": "set-background", "slide": "SLIDE_5", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_5", "text": "پایداری ریاضی هسته // تطبیق خطی O(N) و مصونیت ReDoS", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#10B981", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_5", "text": "موتور اتوماتای متناهی قطعی (Rust DFA):\n• ارزیابی پیمایش متن تنها در یک دور خطی O(N)\n• زمان تاخیر قطعی زیر 0.04 میلی‌ثانیه برای تمامی پکت‌ها\n• حذف کامل الگوریتم‌های پس‌گرد (Backtracking) پرریسک\n• مصونیت ۱۰۰٪ در برابر حملات قفل سرور ReDoS", "x": 50, "y": 120, "width": 880, "height": 160, "font_size": 16, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_5", "text": "pub fn eval_dfa(payload: &[u8]) -> Verdict {\n    let mut state = START;\n    for &b in payload {\n        state = TABLE[state][b as usize];\n        if state == MATCH { return Verdict::Block(); }\n    }\n    Verdict::Clean // Latency: 0.04ms | 100% ReDoS Safe\n}", "x": 50, "y": 290, "width": 880, "height": 120, "font_size": 14, "color": "#10B981", "background_color": "#020617", "font_family": "Courier New"},
    {"op": "set-notes", "slide": "SLIDE_5", "text": "اثبات پیچیدگی زمانی خطی و کدهای راست اتوماتای DFA."},

    # SLIDE 6: DDoS & PoW
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_6"},
    {"op": "set-background", "slide": "SLIDE_6", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_6", "text": "پدافند ضد دیداس // مهار ترافیک با چالش اثبات کار (PoW)", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#F6821F", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_6", "text": "سد اول // نرخ لغزان (Sliding Window):\nشمارشگر حافظه در بازه یک‌دقیقه‌ای؛ تخلیه سریع درخواست‌های اضافی با کد ۴۲۹ بدون اختصاص بافر.", "x": 50, "y": 120, "width": 280, "height": 260, "font_size": 14, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_6", "text": "سد دوم // فیوز مدار خودکار (Circuit Breaker):\nپایش جهش ناگهانی بار شبکه (بالای 80 RPS)؛ سوئیچ آنی به حالت پایداری حداکثر و ایزوله‌سازی آی‌پی‌ها.", "x": 350, "y": 120, "width": 280, "height": 260, "font_size": 14, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_6", "text": "سد سوم // چالش بدون کپچا (SHA-256 PoW):\nارسال مسئله معکوس ریاضی به مرورگر؛ حل در ۲۰ میلی‌ثانیه برای انسان اما فلج‌کننده بات‌نت‌های مهاجم.", "x": 650, "y": 120, "width": 280, "height": 260, "font_size": 14, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_6", "text": "معماری سه‌لایه ضد دیداس و تحمیل هزینه رمزنگاری به کلاینت مهاجم."},

    # SLIDE 7: Shannon Entropy AI
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_7"},
    {"op": "set-background", "slide": "SLIDE_7", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_7", "text": "هوش مصنوعی و یادگیری ماشین // کشف حملات با انتروپی شانون", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#8B5CF6", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_7", "text": "فرمول انتروپی اطلاعات شانون:\nH(X) = - ∑ P(x_i) · log₂ P(x_i)\n\n• انتروپی داده‌های طبیعی وب: H < 3.80\n• انتروپی شل‌کد و کدهای نفوذ: H > 4.65 (مسدودسازی خودکار)", "x": 50, "y": 120, "width": 420, "height": 260, "font_size": 15, "color": "#38BDF8", "background_color": "#020617", "font_family": "Courier New"},
    {"op": "add-textbox", "slide": "SLIDE_7", "text": "مغز شناختی AegisNeuralBrain:\n• استخراج وکتور ویژگی ۵۵۶ بُعدی ترکیبی از انتروپی و N-Gram\n• آموزش‌دیده روی ۵۵۲,۰۸۶ نمونه پی‌لود امنیتی برگرفته از SecLists\n• کشف رفتارهای ناهنجار و حملات ناشناخته Zero-Day بدون امضای قبلی", "x": 510, "y": 120, "width": 420, "height": 260, "font_size": 15, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_7", "text": "فرمول انتروپی ریاضی شانون و ابعاد دیتاست ۵۵۲ هزار نمونه‌ای یادگیری ماشین."},

    # SLIDE 8: Scorecard
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_8"},
    {"op": "set-background", "slide": "SLIDE_8", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_8", "text": "نتایج آزمایشگاهی مگا-اسکیل // کارنامه رسمی ممیزی بر روی ۷۹۶ سناریو", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#10B981", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_8", "text": "امتیاز ممیزی داوری:\n93.9 / 100\nرتبه ممتاز پدافند سایبری", "x": 50, "y": 120, "width": 260, "height": 260, "font_size": 22, "bold": True, "color": "#10B981", "background_color": "#0D121E", "font_family": "Tahoma", "alignment": "center"},
    {"op": "add-textbox", "slide": "SLIDE_8", "text": "متریک‌های کلیدی کارنامه ارزیابی:\n\n• نرخ مهار حملات OWASP: ۹۲.۳۴٪ (۴۵۸ حمله مهارشده)\n• نرخ خطای مثبت کاذب: ۰.۰۰٪ (Zero False Positive)\n• تاخیر بازرسی پکت P50: تنها ۰.۰۴ میلی‌ثانیه\n• مصرف پایدار حافظه رم: ۱۸.۴ مگابایت (بدون نشت حافظه)", "x": 330, "y": 120, "width": 600, "height": 260, "font_size": 16, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_8", "text": "امتیاز رسمی مگا-اسکیل ۹۳.۹ و صفر بودن خطای کاذب به عنوان مزیت رقابتی اصلی."},

    # SLIDE 9: Live Demo
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_9"},
    {"op": "set-background", "slide": "SLIDE_9", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_9", "text": "سناریوی دموی زنده // مراحل تست نفوذ و دفاع در برابر داوران", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#06B6D4", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_9", "text": "گام ۱: اجرای فایروال\nاجرای سریع سرویس با پایتون:\npython start_waf.py", "x": 50, "y": 120, "width": 200, "height": 260, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_9", "text": "گام ۲: داشبورد SOC\nمشاهده لاگ در مرورگر:\nhttp://localhost:9000", "x": 270, "y": 120, "width": 200, "height": 260, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_9", "text": "گام ۳: تست تزریق SQL\nارسال با دستور ترمینال:\ncurl -i \"http://localhost:8080/?q=1' OR '1'='1\"", "x": 490, "y": 120, "width": 220, "height": 260, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_9", "text": "گام ۴: مسدودسازی آنی\nدریافت پاسخ قطعی 403\nو ثبت فوری در داشبورد گرافیکی", "x": 730, "y": 120, "width": 200, "height": 260, "font_size": 13, "color": "#10B981", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_9", "text": "سناریوی اجرای دمو جلوی اساتید با دستور curl و مشاهده بلاک در پورت ۹۰۰۰."},

    # SLIDE 10: Q&A
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_10"},
    {"op": "set-background", "slide": "SLIDE_10", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_10", "text": "پاسخ به سوالات داوران // تحلیل فنی سوالات احتمالی اساتید", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#F6821F", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_10", "text": "س: چرا ترکیب Rust و Python؟\nج: راست بالاترین پرفورمنس پردازش پکت را بدون نشت حافظه تضمین می‌کند، در حالی که پایتون امکان توسعه سریع یادگیری ماشین و مانیتورینگ SOC را فراهم می‌سازد.", "x": 50, "y": 120, "width": 280, "height": 260, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_10", "text": "س: چگونه از ReDoS جلوگیری می‌شود؟\nج: با موتور DFA که تضمین ریاضی مرتبه خطی O(N) دارد؛ هیچ پکت مخربی هر چقدر هم طولانی و پیچیده باشد نمی‌تواند سرور را در حلقه پس‌گرد قفل کند.", "x": 350, "y": 120, "width": 280, "height": 260, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_10", "text": "س: پازل اثبات کار چه مزیتی دارد؟\nج: با تغییر هزینه محاسبات از سمت سرور به کلاینت، سرور حتی زیر بار صدها هزار درخواست رباتیک پایدار می‌ماند در حالی که کاربران عادی کوچکترین تاخیری حس نمی‌کنند.", "x": 650, "y": 120, "width": 280, "height": 260, "font_size": 13, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_10", "text": "پاسخ‌های آماده برای سوالات داوران در جلسه ارائه."},

    # SLIDE 11: Developer Credits
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_11"},
    {"op": "set-background", "slide": "SLIDE_11", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_11", "text": "شناسنامه پروژه // استانداردهای فنی و توسعه‌دهنده", "x": 50, "y": 30, "width": 900, "height": 45, "font_size": 24, "bold": True, "color": "#8B5CF6", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_11", "text": "معمار و توسعه‌دهنده سامانه:\nطاها وزیری (Taha Vaziri)\nتوسعه‌دهنده سیستم‌های امنیتی و هوش مصنوعی", "x": 50, "y": 120, "width": 420, "height": 260, "font_size": 18, "bold": True, "color": "#06B6D4", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "add-textbox", "slide": "SLIDE_11", "text": "استانداردها و پشته فنی:\n• هسته: Rust 2024 Edition (Tokio, Axum)\n• مرکز پایش: Python 3.12 (FastAPI, Scikit-Learn)\n• دیتابیس: SQLite WAL Mode\n• استانداردها: OWASP Top 10, RFC 7230, TLS 1.3 0-RTT", "x": 510, "y": 120, "width": 420, "height": 260, "font_size": 15, "color": "#FFFFFF", "background_color": "#0D121E", "font_family": "Tahoma"},
    {"op": "set-notes", "slide": "SLIDE_11", "text": "معرفی سازنده طاها وزیری و مشخصات استانداردها."},

    # SLIDE 12: Conclusion
    {"op": "add-slide", "layout": "BLANK", "id": "SLIDE_12"},
    {"op": "set-background", "slide": "SLIDE_12", "color": "#07090E"},
    {"op": "add-textbox", "slide": "SLIDE_12", "text": "با سپاس از توجه اساتید و داوران گرامی", "x": 100, "y": 140, "width": 800, "height": 70, "font_size": 36, "bold": True, "color": "#FFFFFF", "font_family": "Tahoma", "alignment": "center"},
    {"op": "add-textbox", "slide": "SLIDE_12", "text": "سامانه دیواره آتش ابری رُخ (Rokh WAF)\nآماده بررسی نهایی و پاسخ به پرسش‌های ارزیابی است.", "x": 100, "y": 240, "width": 800, "height": 70, "font_size": 20, "color": "#CBD5E1", "font_family": "Tahoma", "alignment": "center"},
    {"op": "add-textbox", "slide": "SLIDE_12", "text": "توسعه‌دهنده: طاها وزیری  |  پاییز ۲۰۲۶", "x": 100, "y": 340, "width": 800, "height": 40, "font_size": 16, "bold": True, "color": "#06B6D4", "font_family": "Tahoma", "alignment": "center"},
    {"op": "set-notes", "slide": "SLIDE_12", "text": "پایان ارائه و قدردانی از اساتید."}
]

with open(BATCH_FILE, "w", encoding="utf-8") as f:
    json.dump(ops, f, ensure_ascii=False, indent=2)

print(f"Generated Google Slides Batch JSON with {len(ops)} operations: {BATCH_FILE}")
