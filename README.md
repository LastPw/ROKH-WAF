# 🛡️ ROKH WAF (دیواره آتش رُخ)

<div align="center">

[![Rust Edition](https://img.shields.io/badge/Rust-2021%20Edition-dea584.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Tokio](https://img.shields.io/badge/Runtime-Tokio%20Async-000000.svg?style=flat-square&logo=tokio)](https://tokio.rs/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab.svg?style=flat-square&logo=python)](https://python.org/)
[![FastAPI](https://img.shields.io/badge/SOC-FastAPI%20Telemetry-009688.svg?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![OWASP CRS](https://img.shields.io/badge/Ruleset-OWASP%20CRS%204.0-ff6f00.svg?style=flat-square)](https://coreruleset.org/)
[![Latency P99](https://img.shields.io/badge/P99%20Latency-0.12%20ms-success.svg?style=flat-square)](#-empirical-benchmarks)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

**سامانه جامع دیواره آتش لایه ۷، پروکسی معکوس بلادرنگ و مرکز عملیات امنیت (SOC)**  
*High-Performance Hybrid Web Application Firewall, Reverse Proxy & Security Operations Center*

**طراح و توسعه‌دهنده اصلی: طاها وزیری (Taha Vaziri)**

[ویژگی‌های کلیدی](#-key-capabilities) •
[معماری سیستم](#-system-architecture) •
[درخت ساختار پروژه](#-repository-structure) •
[نتایج بنچمارک](#-empirical-benchmarks) •
[راهنمای راه‌اندازی](#-quick-start-guide) •
[آزمون‌های امنیتی](#-automated-security-verification)

</div>

---

## 📖 معرفی پروژه (Overview)

سامانه **ROKH WAF (دیواره آتش رُخ)** یک دیواره آتش نرم‌افزاری هیبریدی در تراز صنعتی است که با تلفیق توان پردازشی و ایمنی حافظه زبان **Rust (موتور هسته و پروکسی غیرهمگام)** و انعطاف‌پذیری تحلیلی **Python (مرکز مانیتورینگ SOC و هوش مصنوعی تشخیص تهدیدات)** طراحی شده است.

این سامانه به صورت یک **پروکسی معکوس با دسترسی لبه (Anycast Reverse Proxy)** در ورودی شبکه مستقر شده، درخواست‌های ورودی پروتکل HTTP/HTTPS را با کمترین تاخیر پردازشی ممکن بازرسی کرده، و ترافیک مخرب (حملات OWASP Top 10، ربات‌های مهاجم، دیداس‌های حجمی و بارهای مشکوک صفر-روزه) را پیش از رسیدن به سرور مبدا خنثی می‌کند.

---

## ⚡ ویژگی‌های شاخص فنی (Key Capabilities)

### ۱. موتور پروکسی فوق سریع Rust با بافر Zero-Copy
- پیاده‌سازی‌شده بر پایه **Tokio** و **Axum** جهت تضمین همزمانی بیش از ۱۰۰٬۰۰۰ سوکت فعال بدون مسدودسازی نخ‌های پردازنده.
- خاتمه پروتکل رمزنگاری TLS 1.3 با پروتکل 0-RTT و انتقال مستقیم بافر حافظه بدون بار مضاعف روی سخت‌افزار.

### ۲. خط لوله بازگشتی رمزگشایی در ۵ لایه (5-Stage Deobfuscation Pipeline)
پیش از اعمال قوانین، کلیه رشته‌های ورودی نرمال‌سازی می‌شوند تا تکنیک‌های دور زدن (Evasion) بی‌اثر شوند:
- **Pass 1 (URL Decoding):** شکستن انکودینگ‌های تو در تو (Nested `%252e%252e%2f` $\rightarrow$ `../`).
- **Pass 2 (HTML5 Entities):** تبدیل انتیتی‌های یونیکد و وب (`&colon;&quot;` $\rightarrow$ `:"`).
- **Pass 3 (Full-Width Unicode Normalization):** تبدیل کاراکترهای تمام‌عرض NFKC به اسکی استاندارد (`＜script＞` $\rightarrow$ `<script>`).
- **Pass 4 (Null-Byte Stripping):** حذف بایت‌های نال (`%00`) جهت جلوگیری از آسیب‌پذیری‌های مسمومیت رشته.
- **Pass 5 (SQL/Shell Comment Neutralization):** پالایش کامنت‌های تزریق‌شده درون واژگان کلیدی (`UN/**/ION` $\rightarrow$ `UNION`).

### ۳. موتور تطبیق اتوماتای قطعی DFA با مصونیت ۱۰۰٪ در برابر ReDoS
- قوانین بازرسی با استفاده از اتوماتای متناهی قطعی (Deterministic Finite Automata) کامپایل می‌شوند.
- زمان تطبیق پکت‌ها دارای تضمین ریاضی **$O(N)$ خطی** است که امکان هرگونه حمله اختلال سرویس از طریق عبارات باقاعده (ReDoS) را از بین می‌برد.

### ۴. ماژول هوش مصنوعی و انتروپی ریاضی شنون (Shannon Entropy AI Brain)
برای مقابله با پی‌لودهای ناشناخته، مبهم‌سازی‌شده یا بدافزارهای صفر-روزه (Zero-Day):
$$\mathcal{H}(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- پی‌لودهایی با انتروپی بالاتر از آستانه ($H > 4.65$) به همراه بردارسازی سریع n-gram/TF-IDF شناسایی و به عنوان رفتار نامتعارف علامت‌گذاری می‌شوند.

### ۵. سد دفاعی چندمرحله‌ای ضد دیداس (Multi-Tier Anti-DDoS & Client PoW)
- **ردیف ۱:** کنترل نرخ جریان بر اساس الگوریتم Token Bucket و پنجره لغزان IP.
- **ردیف ۲:** زندان خودکار آی‌پی (Auto IP-Jail) در صورت تکرار تخلف.
- **ردیف ۳:** چالش رمزنگاری سمت کاربر مبتنی بر **اثبات کار (SHA-256 Proof-of-Work)**، مشابه مکانیزم امنیتی Cloudflare Under Attack Mode برای تفکیک بلادرنگ کاربران واقعی از ربات‌ها و ابزارهای حمله DoS بدون نیاز به کپچای آزاردهنده.

### ۶. مرکز عملیات امنیت و داشبورد SOC (Real-Time SOC Center)
- داشبورد تعاملی مبتنی بر FastAPI با ثبت رویدادها در پایگاه SQLite با حالت WAL بدون مسدودسازی دیسک.
- ابزار تست نفوذ تک‌کلیکی (Attack Simulator) برای ارائه و دمو به کارشناسان و داوران.

---

## 🏛️ معماری کلان سیستم (System Architecture)

```mermaid
flowchart TD
    Client["کلاینت / کاربر / ربات مهاجم"] -->|HTTP Traffic :8080| Ingress["مدیریت ورودی لایه شبکه (Ingress)"]
    
    subgraph RustCore["موتور هسته دیواره آتش رُخ (Rust Tokio Core Engine)"]
        direction TB
        Ingress --> DDoS["۱. کنترل نرخ و چالش ضد دیداس (PoW Challenge)"]
        DDoS --> Bot["۲. انگشت‌نگاری ابزارهای پویشگر (Scanner Detection)"]
        Bot --> Deob["۳. خط لوله رمزگشایی ۵ مرحله‌ای (Anti-Evasion Normalizer)"]
        Deob --> DFA["۴. موتور بازرسی عمیق اتوماتا (DFA Regex O(N))"]
        DFA --> Entropy["۵. ارزیابی انتروپی ریاضی شنون (Shannon Anomaly AI)"]
    end

    RustCore -->|شناسایی تهدید: مسدودسازی 403 Forbidden| Drop["پاسخ امنیتی + شناسه پیگیری رخداد"]
    RustCore -->|ثبت وقایع به صورت ناهمگام (Async WAL)| DB[("پایگاه داده رخدادها\n(SQLite WAL)")]
    RustCore -->|درخواست سالم و مجاز| Backend["سرویس برنامه کاربردی مبدا (:9000)"]
    
    DB <--> SOC["داشبورد مرکز عملیات امنیت (FastAPI SOC :9000)\nجریان بلادرنگ رخدادها • مدیریت تنظیمات • شبیه‌ساز حمله"]
    SOC --> Showcase["موشن گرافیک سینمایی معرفی به داوران (:9000/motion)"]
```

---

## 📂 ساختار فایل‌ها و شاخه‌ها (Repository Structure)

```text
rokh-waf/
├── Cargo.toml                       # مشخصات پکیج و تنظیمات کامپایلر Rust (Author: Taha Vaziri)
├── Cargo.lock                       # قفل وابستگی‌های کامپایلر Rust
├── LICENSE                          # مجوز متنباز استاندارد MIT (حق نشر طاها وزیری)
├── README.md                        # مستندات جامع فنی و راهنمای پروژه
├── requirements.txt                 # پیش‌نیازهای پایتون (FastAPI, Uvicorn, Requests)
├── install.ps1                      # اسکریپت نصب آسان و خودکار برای ویندوز
├── install.sh                       # اسکریپت نصب آسان برای لینوکس و مک
├── start_waf.ps1                    # راه‌انداز تعاملی فایروال برای ویندوز
├── start_waf.py                     # ویزارد هوشمند راه‌اندازی و تعیین سرور تحت حفاظت
├── .gitignore                       # قوانین نادیده‌گیری گیت (پایگاه‌داده، کش‌ها، موشن‌گرافیک محلی)
│
├── .github/                         # یکپارچه‌سازی و استقرار پیوسته (CI/CD)
│   └── workflows/
│       └── ci.yml                   # خط لوله تست خودکار GitHub Actions (Cargo Check + Python Tests)
│
├── src/                             # هسته اصلی دیواره آتش و پروکسی لایه ۷ (Rust)
│   ├── main.rs                      # نقطه ورود و راه‌اندازی سرورهای Axum/Tokio
│   ├── proxy.rs                     # پروکسی معکوس غیرهمگام با انتقال بدون کپی (Zero-Copy)
│   ├── rules.rs                     # پایگاه قوانین بازرسی پکت و موتور اتوماتای قطعی (OWASP CRS)
│   ├── deobfuscator.rs              # خط لوله نرمال‌سازی و شکستن ترفندهای Evasion در ۵ لایه
│   ├── antiddos.rs                  # سد ضد دیداس چندمرحله‌ای و چالش رمزنگاری SHA-256 PoW
│   ├── ratelimit.rs                 # پیاده‌سازی سطل توکن و پنجره زمانی لغزان
│   ├── logger.rs                    # سیستم لاگ‌گیری غیرهمگام رویدادها در SQLite WAL
│   └── config.rs                    # مدیریت تنظیمات داینامیک و متغیرهای عملیاتی
│
├── ai_engine/                       # موتور هوش مصنوعی و تحلیل انتروپی تهدیدات (Python)
│   ├── __init__.py
│   ├── model.py                     # مدل طبقه‌بندی ترکیبی هیوریستیک + انتروپی شنون
│   ├── dataset.py                   # استخراج ویژگی‌ها و ساختارهای داده پی‌لودها
│   ├── train.py                     # خط لوله آموزش مدل
│   └── waf_brain_weights.json       # وزن‌ها و لغت‌نامه از پیش کامپایل‌شده (سبک و سریع)
│
├── python_soc/                      # مرکز عملیات امنیت و سرور تجمیع داده‌ها (FastAPI)
│   ├── __init__.py
│   └── app.py                       # داشبورد مانیتورینگ بلادرنگ، APIهای مدیریتی و سرویس مبدا فرضی
│
├── showcase/                        # پرزنتیشن تعاملی و موشن‌گرافیک داوران (ارائه محلی / مستثنی از گیت)
│   ├── index.html                   # موشن‌گرافیک ۷ اسلایدی ۲۸ ثانیه‌ای با معرفی طاها وزیری
│   └── media/                       # فایل‌های رسانه‌ای رندرشده محلی
│
├── tests/                           # مجموعه آزمون‌های امنیتی و تست نفوذ خودکار
│   ├── test_attacks.py              # ارزیابی ۱۱ سناریوی استاندارد نفوذ OWASP Top 10
│   ├── test_ddos_flood.py           # آزمون طغیان چندنخی و حل خودکار چالش PoW
│   ├── test_sqli_fix.py             # آزمون عبور از فیلترهای پیشرفته تزریق اس‌کیو‌ال
│   ├── test_rce_fix.py              # آزمون عبور از فیلترهای اجرای کد دستوری
│   └── test_ai_engine.py            # اعتبارسنجی دقت و تاخیر موتور انتروپی هوش مصنوعی
│
├── benchmarks/                      # ابزارهای ارزیابی عملکرد و مگا بنچمارک در مقیاس صنعتی
│   ├── mega_attack_benchmark.py     # تست در برابر ۷۹۶ سناریوی واقعی برگرفته از SecLists
│   ├── heavy_attack_benchmark.py    # بنچمارک نرخ تاخیر P50 / P99 در همزمانی بالا
│   └── stress_sec_audit.py          # آزمون استرس و پایداری در بار پردازشی شدید
│
├── data/                            # امضاهای پایگاه داده و بردارها
│   └── signatures/                  # واژه‌نامه‌های حملات (SQLi, XSS, RCE, LFI, Scanners)
│
└── scripts/                         # اسکریپت‌های راه‌اندازی و مدیریت محیط توسعه
    ├── run_all.ps1                  # اسکریپت تک‌کلیکی راه‌اندازی همزمان پروکسی Rust و داشبورد Python
    ├── train_enterprise.py          # اسکریپت آموزش مدل بر روی کورپوس سازمانی
    └── train_mega.py                # اسکریپت بازتولید وزن‌های یادگیری عمیق
```

---

## 📊 نتایج ارزیابی آزمایشگاهی (Empirical Benchmarks)

در آزمون جامع ارزیابی امنیتی در برابر **۷۹۶ سناریوی تهاجمی و درخواست تمیز** از مراجع استاندارد جهانی (*SecLists* و *PayloadsAllTheThings*) نتایج زیر به ثبت رسیده است:

| شاخص سنجش عملکرد (Metric) | مقدار اندازه‌گیری‌شده در ROKH WAF | حد استاندارد صنعت امنیت | وضعیت ارزیابی |
| :--- | :---: | :---: | :---: |
| **تاخیر صدک P99 بازرسی بسته** | **$0.12\text{ ms}$** | $< 1.0\text{ ms}$ | ✅ فوق‌العاده سریع |
| **تاخیر میانه P50 بازرسی** | **$0.04\text{ ms}$** | $< 0.5\text{ ms}$ | ✅ بدون تاثیر بر سئو |
| **نرخ کشف و مهار حملات نفوذ** | **$93.9\%$** ($458$ از $488$) | $> 90.0\%$ | ✅ مهار حداکثری |
| **نرخ خطای کاذب (False Positive)** | **$0.00\%$** ($0$ خطا در $308$ تست) | $< 0.1\%$ | ✅ صفر درخواست مسدود |
| **مصرف حافظه رم دائم (RSS)** | **$18.4\text{ MB}$** | $< 100\text{ MB}$ | ✅ فوق‌العاده بهینه |
| **مصونیت در برابر حمله ReDoS** | **$100\%$** (تضمین الگوریتم DFA) | الزامی | ✅ مصونیت قطعی |

---

## 🚀 راهنمای نصب و راه‌اندازی آسان (Installation & Quick Start)

### ۱. نصب آسان و خودکار (One-Click Installation)

#### در محیط ویندوز (PowerShell):
```powershell
.\install.ps1
```

#### در محیط لینوکس و مک (Linux / macOS):
```bash
chmod +x install.sh && ./install.sh
```
*این اسکریپت به صورت خودکار پیش‌نیازهای پایتون، پکیج‌های مورد نیاز و هسته Rust WAF را کامپایل و آماده اجرا می‌کند.*

---

### ۲. راه‌اندازی هوشمند و تعیین سرویس تحت حفاظت (Smart Target Launcher)

برای اجرای فایروال و تعیین اینکه مایلید از چه سرور، پورت یا آدرسی محافظت کنید، اسکریپت راه‌انداز هوشمند را اجرا نمایید:

```powershell
# اجرای ویزارد تعاملی (پرسش آدرس مقصد، پورت، حالت امنیتی و نرخ دیداس)
.\start_waf.ps1

# یا با پایتون:
python start_waf.py
```

همچنین می‌توانید مستقیماً آدرس سرور مقصد خود را به عنوان آرگومان خط فرمان پاس دهید:

```bash
# محافظت از یک برنامه React / Node.js روی پورت ۳۰۰۰ با شنود فایروال روی ۸۰۸۰
python start_waf.py --target http://127.0.0.1:3000 --port 8080

# محافظت از یک وب‌سرور جنگو یا فست‌اِی‌پی‌آی روی پورت ۸۰۰۰
python start_waf.py --target http://localhost:8000 --mode PREVENTION --rpm 120
```

#### گزینه‌های خط فرمان:
- `--target, -t <URL>`: آدرس سرویس یا وب‌سایتی که باید از آن دفاع شود.
- `--port, -p <PORT>`: پورت شنود پروکسی فایروال (پیش‌فرض: `8080`).
- `--mode, -m <MODE>`: حالت دفاعی (`PREVENTION` برای مسدودسازی یا `DETECTION` برای مانیتورینگ).
- `--rpm <COUNT>`: سقف مجاز درخواست در دقیقه برای هر آی‌پی (پیش‌فرض: `60`).
- `--no-soc`: عدم راه‌اندازی همزمان داشبورد پایتون SOC.

---

### ۳. راه‌اندازی دستی (مستقل)

#### ۱. راه‌اندازی داشبورد SOC (پورت ۹۰۰۰):
```bash
python python_soc/app.py
```
- **داشبورد مرکز عملیات امنیت:** [http://127.0.0.1:9000](http://127.0.0.1:9000)

#### ۲. راه‌اندازی مستقیم باینری کامپایل‌شده Rust:
```bash
./target/release/waf_engine --target http://127.0.0.1:3000 --port 8080
```
- **مدخل ورودی ترافیک تحت حفاظت:** [http://127.0.0.1:8080](http://127.0.0.1:8080)

---

## 🧪 آزمون‌های امنیتی و صحت‌سنجی (Automated Verification)

برای اعتبارسنجی کارکرد موتور دفاعی، اسکریپت‌های تست را اجرا نمایید:

```bash
# آزمون ۱۱ سناریوی نفوذ استاندارد OWASP
python tests/test_attacks.py

# اعتبارسنجی موتور انتروپی شنون و هوش مصنوعی
python tests/test_ai_engine.py

# شبیه‌سازی حملات دیداس حجمی و چالش SHA-256 PoW
python tests/test_ddos_flood.py

# اجرای مگا بنچمارک ۷۹۶ سناریوی واقعی
python benchmarks/mega_attack_benchmark.py
```

---

## 👨‍💻 شناسنامه توسعه‌دهنده (Author & Credits)

- **توسعه‌دهنده و معمار سیستم:** **طاها وزیری (Taha Vaziri)**
- **تمرکز فنی:** سیستم‌های توزیع‌شده با کارایی بالا، سیستم‌های امنیتی لایه ۷ و پردازش بلادرنگ جریان‌های داده در زبان Rust.
- **لایسنس:** منتشر شده تحت مجوز متنباز [MIT](LICENSE).
