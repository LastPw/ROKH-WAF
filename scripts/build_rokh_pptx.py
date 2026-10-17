import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

OUTPUT_PPTX = r"C:\Users\imtah\OneDrive\Desktop\ROKH_WAF_PRESENTATION.pptx"
ASSETS_DIR = r"c:\Users\imtah\OneDrive\Desktop\Waf\presentation_assets"

# Colors
C_BG = RGBColor(7, 9, 14)          # Ultra dark #07090e
C_CARD = RGBColor(13, 18, 30)      # Dark card #0d121e
C_BORDER = RGBColor(30, 41, 59)    # Border #1e293b
C_ORANGE = RGBColor(246, 130, 31)  # Cloudflare orange #f6821f
C_CYAN = RGBColor(6, 182, 212)     # Tech cyan #06b6d4
C_EMERALD = RGBColor(16, 185, 129) # Tech emerald #10b981
C_VIOLET = RGBColor(139, 92, 246)  # Violet #8b5cf6
C_RED = RGBColor(239, 68, 68)      # Tech red #ef4444
C_WHITE = RGBColor(255, 255, 255)
C_TEXT_REG = RGBColor(203, 213, 225) # Slate 300
C_TEXT_MUTED = RGBColor(148, 163, 184) # Slate 400

FONT_NAME = "Segoe UI"
FONT_FA = "Tahoma"

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank_layout = prs.slide_layouts[6]

def create_base_slide():
    slide = prs.slides.add_slide(blank_layout)
    # Background
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
    bg.fill.solid()
    bg.fill.fore_color.rgb = C_BG
    bg.line.fill.background()
    return slide

def add_header(slide, badge_text, badge_color, title_text, highlight_text=""):
    # Badge
    badge_box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.4), Inches(4.5), Inches(0.38))
    badge_box.fill.solid()
    badge_box.fill.fore_color.rgb = RGBColor(15, 23, 42)
    badge_box.line.color.rgb = badge_color
    badge_box.line.width = Pt(1.5)
    tf = badge_box.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = f"●  {badge_text}"
    p.font.name = FONT_FA
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = badge_color
    p.alignment = PP_ALIGN.RIGHT

    # Main Headline
    tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.85), Inches(11.7), Inches(0.75))
    tf2 = tb.text_frame
    tf2.word_wrap = True
    p2 = tf2.paragraphs[0]
    p2.alignment = PP_ALIGN.RIGHT
    run1 = p2.add_run()
    run1.text = title_text + " "
    run1.font.name = FONT_FA
    run1.font.size = Pt(22)
    run1.font.bold = True
    run1.font.color.rgb = C_WHITE
    if highlight_text:
        run2 = p2.add_run()
        run2.text = highlight_text
        run2.font.name = FONT_FA
        run2.font.size = Pt(22)
        run2.font.bold = True
        run2.font.color.rgb = badge_color

def add_card(slide, left, top, width, height, title, body, border_color=C_BORDER, header_color=C_WHITE, tag=""):
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = C_CARD
    card.line.color.rgb = border_color
    card.line.width = Pt(1.5)
    
    tf = card.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.TOP
    tf.margin_left = Inches(0.2)
    tf.margin_right = Inches(0.2)
    tf.margin_top = Inches(0.18)

    if tag:
        p_tag = tf.paragraphs[0]
        p_tag.alignment = PP_ALIGN.RIGHT
        p_tag.text = tag
        p_tag.font.name = FONT_NAME
        p_tag.font.size = Pt(10)
        p_tag.font.bold = True
        p_tag.font.color.rgb = border_color
        p_title = tf.add_paragraph()
    else:
        p_title = tf.paragraphs[0]

    p_title.alignment = PP_ALIGN.RIGHT
    p_title.text = title
    p_title.font.name = FONT_FA
    p_title.font.size = Pt(15)
    p_title.font.bold = True
    p_title.font.color.rgb = header_color

    p_body = tf.add_paragraph()
    p_body.alignment = PP_ALIGN.RIGHT
    p_body.text = body
    p_body.font.name = FONT_FA
    p_body.font.size = Pt(11.5)
    p_body.font.color.rgb = C_TEXT_REG
    p_body.space_before = Pt(8)
    return card

# ==========================================
# SLIDE 1: TITLE SLIDE (Cover)
# ==========================================
s1 = create_base_slide()
# Add Shield Logo Image
logo_path = os.path.join(ASSETS_DIR, "shield_logo.png")
if os.path.exists(logo_path):
    s1.shapes.add_picture(logo_path, Inches(1.0), Inches(1.5), width=Inches(3.8))

# Title Texts (Right-Aligned)
tb = s1.shapes.add_textbox(Inches(5.0), Inches(1.4), Inches(7.5), Inches(4.8))
tf = tb.text_frame
tf.word_wrap = True

p_badge = tf.paragraphs[0]
p_badge.alignment = PP_ALIGN.RIGHT
r = p_badge.add_run()
r.text = "🛡️ دیواره آتش لایه ۷ و پروکسی ابری ضد دیداس"
r.font.name = FONT_FA
r.font.size = Pt(13)
r.font.bold = True
r.font.color.rgb = C_ORANGE

p_title = tf.add_paragraph()
p_title.alignment = PP_ALIGN.RIGHT
p_title.space_before = Pt(12)
r = p_title.add_run()
r.text = "سامانه دیواره آتش ابری رُخ\n(Rokh WAF)"
r.font.name = FONT_FA
r.font.size = Pt(36)
r.font.bold = True
r.font.color.rgb = C_WHITE

p_sub = tf.add_paragraph()
p_sub.alignment = PP_ALIGN.RIGHT
p_sub.space_before = Pt(14)
r = p_sub.add_run()
r.text = "پدافند غیرهمگام لبه، بازرسی عمیق بسته‌ها (DPI)، موتور تصمیم‌گیری قطعی DFA و تحلیل هوشمند تهدیدات"
r.font.name = FONT_FA
r.font.size = Pt(15)
r.font.color.rgb = C_TEXT_REG

p_dev = tf.add_paragraph()
p_dev.alignment = PP_ALIGN.RIGHT
p_dev.space_before = Pt(28)
r = p_dev.add_run()
r.text = "توسعه‌دهنده و معمار سیستم: "
r.font.name = FONT_FA
r.font.size = Pt(14)
r.font.color.rgb = C_TEXT_MUTED
r2 = p_dev.add_run()
r2.text = "طاها وزیری (Taha Vaziri)"
r2.font.name = FONT_FA
r2.font.size = Pt(16)
r2.font.bold = True
r2.font.color.rgb = C_CYAN

p_tech = tf.add_paragraph()
p_tech.alignment = PP_ALIGN.RIGHT
p_tech.space_before = Pt(10)
r = p_tech.add_run()
r.text = "Rust (Tokio / Axum)  ·  Python SOC (FastAPI)  ·  O(N) Regex DFA  ·  Zero-Copy Buffer"
r.font.name = FONT_NAME
r.font.size = Pt(12)
r.font.color.rgb = C_EMERALD

s1.notes_slide.notes_text_frame.text = "معرفی پروژه و اهداف سامانه برای هیئت داوران. خوش‌آمدگویی و اعلام مشخصات پروژه توسط طاها وزیری."

# ==========================================
# SLIDE 2: EXECUTIVE SUMMARY & MOTIVATION
# ==========================================
s2 = create_base_slide()
add_header(s2, "مقدمه و صورت مسئله", C_CYAN, "چالش‌های WAFهای سنتی و", "ضرورت پدافند عمیق بومی")

cards_data = [
    ("حملات لایه کاربرد (Layer 7)", "بیش از ۸۰٪ نفوذهای موفق سایبری در سطح HTTP/HTTPS رخ می‌دهند؛ جایی که فایروال‌های سنتی پورت و آی‌پی (iptables) توان بازرسی محتوای بسته‌ها را ندارند.", C_RED, "THREAT LANDSCAPE"),
    ("سربار تاخیر و کندی (Latency)", "سامانه‌های سنتی مانند ModSecurity تاخیر چند ده‌میلی‌ثانیه‌ای اضافه می‌کنند که منجر به افت رتبه سئو و کندی دسترسی کاربران مجاز می‌گردد.", C_ORANGE, "LATENCY CRISIS"),
    ("مخاطرات حافظه در C/C++", "بسیاری از نرم‌افزارهای فایروال سنتی به دلیل عدم ایمنی حافظه دچار خطاهای Buffer Overflow، Use-After-Free و نشت حافظه هستند.", C_VIOLET, "MEMORY VULNERABILITY"),
    ("بحران قفل پردازنده (ReDoS)", "موتورهای عبارات منظم بازگشتی (Backtracking) در مواجهه با پی‌لودهای انفجاری دچار زمان اجرای نمایی O(2^N) و از کارافتادگی سرور می‌شوند.", C_EMERALD, "REDOS RISK")
]

w, h = Inches(2.75), Inches(4.8)
for i, (title, body, border_c, tag) in enumerate(cards_data):
    left = Inches(0.8 + i * 2.95)
    add_card(s2, left, Inches(1.8), w, h, title, body, border_c, C_WHITE, tag)

s2.notes_slide.notes_text_frame.text = "تشریح آمارهای رسمی OWASP و نقایص فایروال‌های موجود و چرایی ساخت سامانه رُخ با راست."

# ==========================================
# SLIDE 3: HYBRID ARCHITECTURE PIPELINE
# ==========================================
s3 = create_base_slide()
add_header(s3, "معماری دو لایه", C_ORANGE, "خط لوله بازرسی بسته (DPI Pipeline) و", "معماری هیبریدی رُخ")

# Embed DPI Pipeline diagram
dpi_path = os.path.join(ASSETS_DIR, "dpi_pipeline.png")
if os.path.exists(dpi_path):
    s3.shapes.add_picture(dpi_path, Inches(0.8), Inches(1.8), width=Inches(11.7))

# Bottom Explanatory Cards
add_card(s3, Inches(0.8), Inches(4.7), Inches(5.7), Inches(2.2),
         "هسته پردازشی رُخ با زبان Rust (پورت 8080)",
         "بر پایه فریم‌ورک غیرهمگام Tokio و وب‌سرور Axum؛ پردازش بسته‌ها به روش Zero-Copy با زمان تاخیر میانگین 0.04 میلی‌ثانیه و بدون سربار بازتخصیص حافظه.",
         C_ORANGE, C_WHITE, "RUST ENGINE")

add_card(s3, Inches(6.8), Inches(4.7), Inches(5.7), Inches(2.2),
         "مرکز عملیات امنیت Python SOC (پورت 9000)",
         "ارائه داشبورد وب زنده، پایش لحظه‌ای ترافیک و رویدادهای مسدودسازی، ثبت وقایع به صورت غیرهمگام در پایگاه داده SQLite با حالت WAL بدون قفل شدن دیسک.",
         C_CYAN, C_WHITE, "SOC & DASHBOARD")

s3.notes_slide.notes_text_frame.text = "توضیح کامل جریان ترافیک ورودی، تفکیک وظایف هسته سریع Rust از مرکز پایش Python SOC."

# ==========================================
# SLIDE 4: 5-LAYER DEOBFUSCATOR (ANTI-EVASION)
# ==========================================
s4 = create_base_slide()
add_header(s4, "خط لوله ضد دورزدن", C_CYAN, "خنثی‌سازی تکنیک‌های Evasion و", "دیکودینگ بازگشتی ۵ لایه")

deob_steps = [
    ("شکستن انکودینگ تو در تو", "URL Decode چندمرحله‌ای تا رسیدن به فرم خام پی‌لود و کشف ریشه‌های مخفی حمله.", "%252e%252e%2f → ../", C_CYAN, "گام ۰۱ // URL DECODE"),
    ("تبدیل انتیتی‌های HTML5", "رمزگشایی کاراکترهای اسکیپ‌شده جهت استخراج و مهار تگ‌های تزریقی پنهان XSS.", "&colon;&quot; → :\"", C_ORANGE, "گام ۰۲ // HTML5 ENTITIES"),
    ("نرمال‌سازی یونیکد Full-Width", "تبدیل کاراکترهای با عرض کامل به فرم NFKC استاندارد و حذف بایت‌های نال مخرب.", "＜script＞ → <script>", C_EMERALD, "گام ۰۳ // UNICODE NFKC"),
    ("پالایش کامنت‌های تفرقه دیتابیس", "حذف خودکار کامنت‌های تزریق‌شده درون واژگان کلیدی دیتابیس پیش از ارزیابی.", "UN/**/ION → UNION", C_VIOLET, "گام ۰۴ // SQL COMMENTS")
]

w, h = Inches(2.75), Inches(4.8)
for i, (title, body, sample, border_c, tag) in enumerate(deob_steps):
    left = Inches(0.8 + i * 2.95)
    card = add_card(s4, left, Inches(1.8), w, h, title, f"{body}\n\nمثال عملی:\n{sample}", border_c, C_WHITE, tag)

s4.notes_slide.notes_text_frame.text = "مهاجمان با روش‌های Evasion فایروال‌های معمولی را فریب می‌دهند. رُخ در ۵ لایه پکت را نرمال می‌کند."

# ==========================================
# SLIDE 5: DETERMINISTIC DFA & REDOS IMMUNITY
# ==========================================
s5 = create_base_slide()
add_header(s5, "پایداری ریاضی هسته", C_EMERALD, "تطبیق خطی O(N) با", "مصونیت ۱۰۰٪ در برابر ReDoS")

# Left: Chart image
redos_path = os.path.join(ASSETS_DIR, "redos_chart.png")
if os.path.exists(redos_path):
    s5.shapes.add_picture(redos_path, Inches(0.8), Inches(1.8), width=Inches(5.6))

# Right: Code box and explanation
add_card(s5, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.8),
         "پیاده‌سازی اتوماتای متناهی قطعی (Rust DFA)",
         "موتور تصمیم‌گیری رُخ به جای الگوریتم‌های پس‌گرد (Backtracking)، متن ورودی را تنها در یک مرتبه پیمایش خطی O(N) ارزیابی می‌کند:\n\n"
         "• پیچیدگی زمانی قطعی: O(N) Strict\n"
         "• تاخیر ارزیابی: کمتر از 0.04ms برای بزرگترین پی‌لودها\n"
         "• بدون نشت حافظه و بدون سرریز پشته (Stack Overflow)\n"
         "• مقاومت کامل در برابر حملات ReDoS Catastrophic Backtracking",
         C_EMERALD, C_WHITE, "RUST DFA AUTOMATA")

s5.notes_slide.notes_text_frame.text = "توضیح تفاوت علمی DFA با NFA Backtracking و دلیل مصونیت مطلق رُخ از حملات قفل‌کننده پردازنده."

# ==========================================
# SLIDE 6: MULTI-TIER DDOS & PROOF-OF-WORK
# ==========================================
s6 = create_base_slide()
add_header(s6, "پدافند ضد دیداس ابری", C_ORANGE, "مهار ترافیک‌های طغیانی با", "معمای رمزنگاری اثبات کار (PoW)")

ddos_tiers = [
    ("پنجره زمانی لغزان (Sliding Window)", "پایش لحظه‌ای تعداد درخواست‌های هر آدرس آی‌پی در پنجره‌های ۶۰ ثانیه‌ای حافظه؛ پاسخ فوری 429 Too Many Requests بدون ایجاد بار بر سرور.", C_CYAN, "TIER 01 // RATE LIMIT"),
    ("فیوز مدار اضطراری (Circuit Breaker)", "تشخیص خودکار جهش ناگهانی بار شبکه (بالای 80 RPS)؛ سوئیچ خودکار سامانه به حالت پایداری حداکثر و ایزوله‌سازی آی‌پی‌های مهاجم.", C_ORANGE, "TIER 02 // BREAKER"),
    ("چالش رمزنگاری اثبات کار (PoW)", "ارسال مسئله معکوس SHA-256 به مرورگر؛ حل معما در ۲۰ میلی‌ثانیه برای انسان، اما غیرممکن برای حملات سیل‌آسای ربات‌ها بدون افت عملکرد.", C_EMERALD, "TIER 03 // CLIENT POW")
]

w, h = Inches(3.7), Inches(4.8)
for i, (title, body, border_c, tag) in enumerate(ddos_tiers):
    left = Inches(0.8 + i * 3.95)
    add_card(s6, left, Inches(1.8), w, h, title, body, border_c, C_WHITE, tag)

s6.notes_slide.notes_text_frame.text = "معماری مشابه کلادفلر: واگذاری هزینه پردازش دیداس به کلاینت مهاجم از طریق SHA-256 Proof of Work."

# ==========================================
# SLIDE 7: AI THREAT ENGINE & SHANNON ENTROPY
# ==========================================
s7 = create_base_slide()
add_header(s7, "هوش مصنوعی و یادگیری ماشین", C_VIOLET, "کشف حملات روز صفر بر پایه", "انتروپی اطلاعات شانون")

# Left: Shannon Formula Image
shannon_path = os.path.join(ASSETS_DIR, "shannon_formula.png")
if os.path.exists(shannon_path):
    s7.shapes.add_picture(shannon_path, Inches(0.8), Inches(1.8), width=Inches(5.6))

# Right: AI Details Card
add_card(s7, Inches(6.8), Inches(1.8), Inches(5.7), Inches(4.8),
         "مغز شناختی AegisNeuralBrain",
         "حملات روز-صفر و شل‌کدهای پنهان دارای امضای مشخص نیستند. سامانه رُخ با ترکیب نظریه اطلاعات شانون و یادگیری ماشین آنها را آشکار می‌سازد:\n\n"
         "• محاسبه آنی انتروپی کاراکتری و توزیع تصادفی بودن داده\n"
         "• وکتور ویژگی ۵۵۶ بُعدی ترکیبی از N-Gram و انتروپی شانون\n"
         "• آموزش دیده روی دیتاست رسمی ۵۵۲,۰۸۶ نمونه‌ای از SecLists\n"
         "• مسدودسازی آنی حملات SSTI، باینری و تزریق‌های ناشناخته در صورت H(X) > 4.65",
         C_VIOLET, C_WHITE, "NEURAL DETECTION")

s7.notes_slide.notes_text_frame.text = "فرمول ریاضی انتروپی شانون، تشخیص حملات zero-day و ابعاد بردار آموزش هوش مصنوعی."

# ==========================================
# SLIDE 8: EMPIRICAL BENCHMARK SCORECARD
# ==========================================
s8 = create_base_slide()
add_header(s8, "نتایج آزمایشگاهی مگا-اسکیل", C_EMERALD, "کارنامه رسمی ممیزی نفوذ در برابر", "۷۹۶ سناریوی حمله واقعی")

# Left: Scorecard Badge Image
score_path = os.path.join(ASSETS_DIR, "scorecard_badge.png")
if os.path.exists(score_path):
    s8.shapes.add_picture(score_path, Inches(0.8), Inches(2.0), width=Inches(5.0))

# Right: Native Table
table_shape = s8.shapes.add_table(6, 3, Inches(6.2), Inches(1.8), Inches(6.3), Inches(4.8))
table = table_shape.table

# Set Column Widths
table.columns[0].width = Inches(2.6)
table.columns[1].width = Inches(1.8)
table.columns[2].width = Inches(1.9)

headers = ["شاخص ارزیابی (Metric)", "سامانه رُخ (Rokh WAF)", "فایروال‌های سنتی"]
rows = [
    ("نمره کل داوری (Audit Score)", "93.9 / 100", "74.0 / 100"),
    ("نرخ مهار بردارهای OWASP", "92.34% (۴۵۸ مسدود)", "81.20%"),
    ("نرخ خطای کاذب (False Positive)", "0.00% (صفر خطا)", "3.40%"),
    ("تاخیر بازرسی پکت (P50 Latency)", "0.04 میلی‌ثانیه", "22.50 میلی‌ثانیه"),
    ("مصرف پایدار حافظه رم (RSS)", "18.4 مگابایت (ثابت)", "> 250 مگابایت")
]

for col_idx, h_text in enumerate(headers):
    cell = table.cell(0, col_idx)
    cell.fill.solid()
    cell.fill.fore_color.rgb = RGBColor(15, 23, 42)
    p = cell.text_frame.paragraphs[0]
    p.text = h_text
    p.font.name = FONT_FA
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_CYAN
    p.alignment = PP_ALIGN.CENTER

for row_idx, (m, r_val, t_val) in enumerate(rows, start=1):
    c0 = table.cell(row_idx, 0)
    c0.fill.solid()
    c0.fill.fore_color.rgb = C_CARD
    p = c0.text_frame.paragraphs[0]
    p.text = m
    p.font.name = FONT_FA
    p.font.size = Pt(11)
    p.font.bold = True
    p.font.color.rgb = C_WHITE

    c1 = table.cell(row_idx, 1)
    c1.fill.solid()
    c1.fill.fore_color.rgb = C_CARD
    p = c1.text_frame.paragraphs[0]
    p.text = r_val
    p.font.name = FONT_FA
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = C_EMERALD
    p.alignment = PP_ALIGN.CENTER

    c2 = table.cell(row_idx, 2)
    c2.fill.solid()
    c2.fill.fore_color.rgb = C_CARD
    p = c2.text_frame.paragraphs[0]
    p.text = t_val
    p.font.name = FONT_FA
    p.font.size = Pt(11)
    p.font.color.rgb = C_TEXT_MUTED
    p.alignment = PP_ALIGN.CENTER

s8.notes_slide.notes_text_frame.text = "بررسی کارنامه ممیزی و دفاع از مزیت رقابتی 0.00% خطای مثبت کاذب و تاخیر ناچیز 0.04 میلی‌ثانیه."

# ==========================================
# SLIDE 9: LIVE DEMONSTRATION SCRIPT
# ==========================================
s9 = create_base_slide()
add_header(s9, "سناریوی اجرای زنده", C_CYAN, "مراحل تست زنده نفوذ و دفاع در", "برابر اساتید داور")

demo_steps = [
    ("گام ۱: اجرای سامانه", "اجرای کل اکوسیستم WAF و SOC با یک دستور پایدار در ترمینال:\n\npython start_waf.py", C_CYAN, "STEP 01 // START"),
    ("گام ۲: پایش در داشبورد", "مشاهده رابط گرافیکی SOC و نمودارهای لحظه‌ای در مرورگر:\n\nhttp://localhost:9000", C_ORANGE, "STEP 02 // SOC VIEW"),
    ("گام ۳: شبیه‌سازی حمله", "ارسال پی‌لود تزریق SQL از طریق یک ترمینال دیگر:\n\ncurl -i \"http://localhost:8080/?q=1' OR '1'='1\"", C_RED, "STEP 03 // LIVE ATTACK"),
    ("گام ۴: مسدودسازی آنی", "دریافت پاسخ قطعی 403 Forbidden و نمایش بلافاصله گزارش امنیتی مسدودسازی در داشبورد.", C_EMERALD, "STEP 04 // 403 BLOCKED")
]

w, h = Inches(2.75), Inches(4.8)
for i, (title, body, border_c, tag) in enumerate(demo_steps):
    left = Inches(0.8 + i * 2.95)
    add_card(s9, left, Inches(1.8), w, h, title, body, border_c, C_WHITE, tag)

s9.notes_slide.notes_text_frame.text = "راهنمای اجرای دمو: نحوه زدن دستور curl در حین باز بودن داشبورد برای نمایش زنده بلاک شدن به استاد."

# ==========================================
# SLIDE 10: DEFENSE Q&A CHEAT SHEET
# ==========================================
s10 = create_base_slide()
add_header(s10, "پاسخ به سوالات داوران", C_ORANGE, "پاسخ‌های دندان‌شکن به ۵ پرسش", "تخصصی و چالشی جلسه دفاع")

qa_cards = [
    ("چرا معماری هیبریدی Rust و Python؟", "برای دستیابی به سرعت در حد C و ایمنی بدون نشت حافظه در خط مقدم بازرسی پکت‌ها (Rust)، در کنار بهره‌مندی از اکوسیستم قدرتمند هوش مصنوعی و دشبوردهای وب (Python).", C_ORANGE, "معماری سیستم"),
    ("چگونه از ReDoS جلوگیری می‌شود؟", "با اتکای ریاضی بر اتوماتای متناهی قطعی (DFA) که زمان پردازش خطی O(N) را تضمین کرده و الگوریتم‌های پرریسک پس‌گرد (Backtracking) را کاملاً حذف می‌کند.", C_EMERALD, "امنیت هسته"),
    ("نقش پازل اثبات کار در برابر بات‌نت‌ها چیست؟", "در حملات سنگین دیداس، هزینه پردازش هر درخواست با هش معکوس SHA-256 به کلاینت تحمیل می‌شود؛ در نتیجه حمله به شدت غیراقتصادی شده و سرور آزاد می‌ماند.", C_CYAN, "پدافند ضد دیداس")
]

w, h = Inches(3.7), Inches(4.8)
for i, (title, body, border_c, tag) in enumerate(qa_cards):
    left = Inches(0.8 + i * 3.95)
    add_card(s10, left, Inches(1.8), w, h, title, body, border_c, C_WHITE, tag)

s10.notes_slide.notes_text_frame.text = "پاسخ به سوالات فنی اساتید در خصوص دلایل مهندسی، معماری و الگوریتم‌های انتخاب‌شده."

# ==========================================
# SLIDE 11: DEVELOPER CREDITS & ARCHITECTURE
# ==========================================
s11 = create_base_slide()
add_header(s11, "شناسنامه پروژه", C_VIOLET, "مشخصات فنی، استانداردها و", "شناسنامه توسعه‌دهنده")

# Left: Developer Badge Image
dev_path = os.path.join(ASSETS_DIR, "dev_badge.png")
if os.path.exists(dev_path):
    s11.shapes.add_picture(dev_path, Inches(0.8), Inches(2.2), width=Inches(5.2))

# Right: Project Specifications
add_card(s11, Inches(6.4), Inches(1.8), Inches(6.1), Inches(4.8),
         "اطلاعات سازمانی و دستاوردهای مهندسی سامانه رُخ",
         "• توسعه‌دهنده و معمار نرم‌افزار: طاها وزیری (Taha Vaziri)\n\n"
         "• استانداردهای پوشش‌داده‌شده:\n"
         "  - لیست ده تهدید برتر وب (OWASP Top 10)\n"
         "  - پروتکل‌های استاندارد وب و پراکسی معکوس RFC 7230\n"
         "  - پروتکل‌های تبادل کلید TLS 1.3 0-RTT\n\n"
         "• پشته نرم‌افزاری (Tech Stack):\n"
         "  - هسته: Rust 2024 (Tokio Async Runtime, Axum HTTP)\n"
         "  - مانیتورینگ و یادگیری ماشین: Python 3.12 (FastAPI, Scikit-Learn)\n"
         "  - ذخیره‌سازی داده: SQLite در حالت Write-Ahead Logging (WAL)",
         C_VIOLET, C_WHITE, "TECHNICAL SPEC")

s11.notes_slide.notes_text_frame.text = "معرفی رسمی سازنده (طاها وزیری) و پشته فناوری‌های نوین به‌کاررفته در پروژه."

# ==========================================
# SLIDE 12: CONCLUSION & THANK YOU
# ==========================================
s12 = create_base_slide()

# Center Logo
if os.path.exists(logo_path):
    s12.shapes.add_picture(logo_path, Inches(5.1), Inches(1.1), width=Inches(3.1))

tb = s12.shapes.add_textbox(Inches(1.5), Inches(4.5), Inches(10.3), Inches(2.2))
tf = tb.text_frame
tf.word_wrap = True

p1 = tf.paragraphs[0]
p1.alignment = PP_ALIGN.CENTER
r = p1.add_run()
r.text = "با سپاس از توجه اساتید و داوران گرامی"
r.font.name = FONT_FA
r.font.size = Pt(32)
r.font.bold = True
r.font.color.rgb = C_WHITE

p2 = tf.add_paragraph()
p2.alignment = PP_ALIGN.CENTER
p2.space_before = Pt(12)
r = p2.add_run()
r.text = "سامانه دیواره آتش ابری رُخ (Rokh WAF) آماده پاسخگویی به پرسش‌ها و بررسی نهایی است."
r.font.name = FONT_FA
r.font.size = Pt(16)
r.font.color.rgb = C_TEXT_REG

p3 = tf.add_paragraph()
p3.alignment = PP_ALIGN.CENTER
p3.space_before = Pt(16)
r = p3.add_run()
r.text = "توسعه‌دهنده: طاها وزیری  |  پاییز ۲۰۲۶"
r.font.name = FONT_FA
r.font.size = Pt(14)
r.font.bold = True
r.font.color.rgb = C_CYAN

s12.notes_slide.notes_text_frame.text = "پایان ارائه، قدردانی از داوران و اعلام آمادگی برای پاسخ به سوالات ارزیابی نهایی."

# Save presentation
prs.save(OUTPUT_PPTX)
print(f"PowerPoint Presentation successfully saved to: {OUTPUT_PPTX}")
