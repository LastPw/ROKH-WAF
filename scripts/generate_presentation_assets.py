import os
import subprocess
import shutil

ASSETS_DIR = r"c:\Users\imtah\OneDrive\Desktop\Waf\presentation_assets"
os.makedirs(ASSETS_DIR, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not os.path.exists(CHROME_PATH):
    CHROME_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

# 1. SHIELD LOGO SVG
SHIELD_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 500" width="500" height="500">
  <defs>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f6821f" />
      <stop offset="50%" stop-color="#d946ef" />
      <stop offset="100%" stop-color="#06b6d4" />
    </linearGradient>
    <linearGradient id="coreGrad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#020617" />
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="12" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>
  <!-- Outer glowing shield -->
  <path d="M 250,30 L 430,95 C 430,290 340,410 250,470 C 160,410 70,290 70,95 Z" 
        fill="url(#coreGrad)" stroke="url(#shieldGrad)" stroke-width="8" filter="url(#glow)"/>
  <!-- Inner cyber shield border -->
  <path d="M 250,55 L 405,110 C 405,275 325,380 250,435 C 175,380 95,275 95,110 Z" 
        fill="none" stroke="#38bdf8" stroke-width="2" stroke-dasharray="8 6" opacity="0.6"/>
  <!-- Central Rust gear & cyber lock -->
  <circle cx="250" cy="225" r="75" fill="none" stroke="#f6821f" stroke-width="6"/>
  <circle cx="250" cy="225" r="50" fill="rgba(246,130,31,0.15)" stroke="#38bdf8" stroke-width="3"/>
  <rect x="235" y="210" width="30" height="30" rx="6" fill="#10b981"/>
  <!-- Hexagon grid lines inside shield -->
  <path d="M 250,150 L 250,225 L 315,260 M 250,225 L 185,260" stroke="#06b6d4" stroke-width="3" stroke-linecap="round"/>
  <!-- Brand text -->
  <text x="250" y="340" font-family="'Segoe UI', 'Vazirmatn', sans-serif" font-weight="900" font-size="34" fill="#ffffff" text-anchor="middle" letter-spacing="4">ROKH WAF</text>
  <text x="250" y="375" font-family="'Segoe UI', 'Vazirmatn', sans-serif" font-weight="600" font-size="16" fill="#f6821f" text-anchor="middle" letter-spacing="2">NEXT-GEN CLOUD EDGE</text>
</svg>"""

# 2. DPI PIPELINE ARCHITECTURE SVG (Wide Landscape)
DPI_PIPELINE_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 360" width="1200" height="360">
  <defs>
    <linearGradient id="bgBox" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#1e293b" />
    </linearGradient>
    <linearGradient id="arrowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#f6821f" />
      <stop offset="100%" stop-color="#06b6d4" />
    </linearGradient>
  </defs>
  
  <!-- Flow connection bar -->
  <line x1="80" y1="180" x2="1120" y2="180" stroke="#334155" stroke-width="4" stroke-dasharray="6 6"/>
  <line x1="80" y1="180" x2="1120" y2="180" stroke="url(#arrowGrad)" stroke-width="4" stroke-dasharray="20 180"/>

  <!-- Node 1: Ingress / Client -->
  <g transform="translate(40, 100)">
    <rect width="150" height="160" rx="14" fill="url(#bgBox)" stroke="#64748b" stroke-width="2"/>
    <rect x="0" y="0" width="150" height="6" rx="3" fill="#64748b"/>
    <text x="75" y="40" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#94a3b8" text-anchor="middle">STEP 01</text>
    <text x="75" y="70" font-family="'Segoe UI', sans-serif" font-size="16" font-weight="800" fill="#ffffff" text-anchor="middle">HTTP Client</text>
    <text x="75" y="95" font-family="'Segoe UI', sans-serif" font-size="11" fill="#cbd5e1" text-anchor="middle">Port 8080</text>
    <rect x="25" y="115" width="100" height="24" rx="6" fill="rgba(100,116,139,0.2)"/>
    <text x="75" y="131" font-family="'Segoe UI', sans-serif" font-size="10" font-weight="700" fill="#94a3b8" text-anchor="middle">TLS 1.3 0-RTT</text>
  </g>

  <!-- Node 2: Dynamic IP Jail -->
  <g transform="translate(230, 100)">
    <rect width="150" height="160" rx="14" fill="url(#bgBox)" stroke="#ef4444" stroke-width="2"/>
    <rect x="0" y="0" width="150" height="6" rx="3" fill="#ef4444"/>
    <text x="75" y="40" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#ef4444" text-anchor="middle">STEP 02</text>
    <text x="75" y="70" font-family="'Segoe UI', sans-serif" font-size="16" font-weight="800" fill="#ffffff" text-anchor="middle">IP Jail Check</text>
    <text x="75" y="95" font-family="'Segoe UI', sans-serif" font-size="11" fill="#cbd5e1" text-anchor="middle">Dynamic Ban</text>
    <rect x="25" y="115" width="100" height="24" rx="6" fill="rgba(239,68,68,0.2)"/>
    <text x="75" y="131" font-family="'Segoe UI', sans-serif" font-size="10" font-weight="700" fill="#ef4444" text-anchor="middle">0.02ms Drop</text>
  </g>

  <!-- Node 3: PoW DDoS Guard -->
  <g transform="translate(420, 100)">
    <rect width="150" height="160" rx="14" fill="url(#bgBox)" stroke="#f6821f" stroke-width="2"/>
    <rect x="0" y="0" width="150" height="6" rx="3" fill="#f6821f"/>
    <text x="75" y="40" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#f6821f" text-anchor="middle">STEP 03</text>
    <text x="75" y="70" font-family="'Segoe UI', sans-serif" font-size="16" font-weight="800" fill="#ffffff" text-anchor="middle">PoW Defense</text>
    <text x="75" y="95" font-family="'Segoe UI', sans-serif" font-size="11" fill="#cbd5e1" text-anchor="middle">SHA-256 Puzzle</text>
    <rect x="25" y="115" width="100" height="24" rx="6" fill="rgba(246,130,31,0.2)"/>
    <text x="75" y="131" font-family="'Segoe UI', sans-serif" font-size="10" font-weight="700" fill="#f6821f" text-anchor="middle">Botnet Neutral</text>
  </g>

  <!-- Node 4: 5-Layer Deobfuscator -->
  <g transform="translate(610, 100)">
    <rect width="150" height="160" rx="14" fill="url(#bgBox)" stroke="#06b6d4" stroke-width="2"/>
    <rect x="0" y="0" width="150" height="6" rx="3" fill="#06b6d4"/>
    <text x="75" y="40" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#06b6d4" text-anchor="middle">STEP 04</text>
    <text x="75" y="70" font-family="'Segoe UI', sans-serif" font-size="16" font-weight="800" fill="#ffffff" text-anchor="middle">Deobfuscation</text>
    <text x="75" y="95" font-family="'Segoe UI', sans-serif" font-size="11" fill="#cbd5e1" text-anchor="middle">5-Pass Normalizer</text>
    <rect x="25" y="115" width="100" height="24" rx="6" fill="rgba(6,182,212,0.2)"/>
    <text x="75" y="131" font-family="'Segoe UI', sans-serif" font-size="10" font-weight="700" fill="#06b6d4" text-anchor="middle">Anti-Evasion</text>
  </g>

  <!-- Node 5: Rust DFA Automata -->
  <g transform="translate(800, 100)">
    <rect width="150" height="160" rx="14" fill="url(#bgBox)" stroke="#10b981" stroke-width="2"/>
    <rect x="0" y="0" width="150" height="6" rx="3" fill="#10b981"/>
    <text x="75" y="40" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#10b981" text-anchor="middle">STEP 05</text>
    <text x="75" y="70" font-family="'Segoe UI', sans-serif" font-size="16" font-weight="800" fill="#ffffff" text-anchor="middle">Rust DFA</text>
    <text x="75" y="95" font-family="'Segoe UI', sans-serif" font-size="11" fill="#cbd5e1" text-anchor="middle">Linear Automata</text>
    <rect x="25" y="115" width="100" height="24" rx="6" fill="rgba(16,185,129,0.2)"/>
    <text x="75" y="131" font-family="'Segoe UI', sans-serif" font-size="10" font-weight="700" fill="#10b981" text-anchor="middle">O(N) ReDoS Safe</text>
  </g>

  <!-- Node 6: Origin Web Server -->
  <g transform="translate(990, 100)">
    <rect width="150" height="160" rx="14" fill="url(#bgBox)" stroke="#8b5cf6" stroke-width="2"/>
    <rect x="0" y="0" width="150" height="6" rx="3" fill="#8b5cf6"/>
    <text x="75" y="40" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#8b5cf6" text-anchor="middle">FINAL</text>
    <text x="75" y="70" font-family="'Segoe UI', sans-serif" font-size="16" font-weight="800" fill="#ffffff" text-anchor="middle">Origin Server</text>
    <text x="75" y="95" font-family="'Segoe UI', sans-serif" font-size="11" fill="#cbd5e1" text-anchor="middle">Protected App</text>
    <rect x="25" y="115" width="100" height="24" rx="6" fill="rgba(139,92,246,0.2)"/>
    <text x="75" y="131" font-family="'Segoe UI', sans-serif" font-size="10" font-weight="700" fill="#8b5cf6" text-anchor="middle">100% Cleaned</text>
  </g>
</svg>"""

# 3. REDOS COMPARISON CHART SVG
REDOS_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 350" width="600" height="350">
  <rect width="600" height="350" rx="16" fill="#0b0f19" stroke="#1e293b" stroke-width="2"/>
  
  <!-- Title -->
  <text x="300" y="40" font-family="'Segoe UI', sans-serif" font-size="18" font-weight="800" fill="#ffffff" text-anchor="middle">پیچیدگی زمانی: موتور DFA رُخ در برابر موتورهای سنتی</text>
  
  <!-- Axes -->
  <line x1="80" y1="290" x2="540" y2="290" stroke="#475569" stroke-width="2"/>
  <line x1="80" y1="290" x2="80" y2="70" stroke="#475569" stroke-width="2"/>
  
  <text x="540" y="320" font-family="'Segoe UI', sans-serif" font-size="12" fill="#94a3b8" text-anchor="end">طول ورودی / پی‌لود (N)</text>
  <text x="40" y="80" font-family="'Segoe UI', sans-serif" font-size="12" fill="#94a3b8" transform="rotate(-90 40,80)" text-anchor="end">زمان پاسخ (ms)</text>
  
  <!-- Exponential ReDoS Spike Curve (Traditional Regex) -->
  <path d="M 80,285 Q 320,280 390,75" fill="none" stroke="#ef4444" stroke-width="4" stroke-linecap="round"/>
  <text x="405" y="90" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#ef4444">O(2^N) انفجار ReDoS و قفل سرور</text>

  <!-- Linear DFA Line (Rokh WAF) -->
  <line x1="80" y1="285" x2="520" y2="265" stroke="#10b981" stroke-width="4" stroke-linecap="round"/>
  <text x="530" y="270" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#10b981">O(N) رُخ: پایدار و خطی (0.04ms)</text>
  
  <!-- Markers -->
  <circle cx="390" cy="75" r="6" fill="#ef4444"/>
  <circle cx="520" cy="265" r="6" fill="#10b981"/>
</svg>"""

# 4. BENCHMARK SCORECARD BADGE SVG
SCORECARD_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 300" width="500" height="300">
  <defs>
    <linearGradient id="scoreBg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0f172a"/>
      <stop offset="100%" stop-color="#020617"/>
    </linearGradient>
  </defs>
  <rect width="500" height="300" rx="18" fill="url(#scoreBg)" stroke="#10b981" stroke-width="3"/>
  <rect x="0" y="0" width="500" height="8" rx="4" fill="#10b981"/>
  
  <!-- Big Score Metric -->
  <circle cx="130" cy="150" r="80" fill="none" stroke="#1e293b" stroke-width="14"/>
  <circle cx="130" cy="150" r="80" fill="none" stroke="#10b981" stroke-width="14" stroke-dasharray="470 500" stroke-linecap="round" transform="rotate(-90 130 150)"/>
  
  <text x="130" y="145" font-family="'Segoe UI', sans-serif" font-size="44" font-weight="900" fill="#ffffff" text-anchor="middle">93.9</text>
  <text x="130" y="175" font-family="'Segoe UI', sans-serif" font-size="14" font-weight="700" fill="#10b981" text-anchor="middle">از ۱۰۰ (امتیاز کل)</text>

  <!-- Score details -->
  <text x="250" y="80" font-family="'Segoe UI', sans-serif" font-size="18" font-weight="800" fill="#ffffff">کارنامه ممیزی مگا-اسکیل</text>
  <text x="250" y="105" font-family="'Segoe UI', sans-serif" font-size="12" fill="#94a3b8">ارزیابی بر روی ۷۹۶ سناریوی حمله واقعی</text>

  <g transform="translate(250, 130)">
    <rect width="210" height="36" rx="8" fill="rgba(16,185,129,0.12)" stroke="rgba(16,185,129,0.3)"/>
    <text x="15" y="23" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#10b981">نرخ مهار: ۹۲.۳۴٪ (۴۵۸ مسدود)</text>
  </g>
  <g transform="translate(250, 175)">
    <rect width="210" height="36" rx="8" fill="rgba(6,182,212,0.12)" stroke="rgba(6,182,212,0.3)"/>
    <text x="15" y="23" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#06b6d4">خطای مثبت کاذب: ۰.۰۰٪ (Zero FPR)</text>
  </g>
  <g transform="translate(250, 220)">
    <rect width="210" height="36" rx="8" fill="rgba(246,130,31,0.12)" stroke="rgba(246,130,31,0.3)"/>
    <text x="15" y="23" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#f6821f">تاخیر P50: ۰.۰۴ میلی‌ثانیه</text>
  </g>
</svg>"""

# 5. SHANNON FORMULA & AI CARD SVG
SHANNON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 300" width="600" height="300">
  <rect width="600" height="300" rx="16" fill="#0a0e17" stroke="#8b5cf6" stroke-width="2"/>
  
  <text x="300" y="45" font-family="'Segoe UI', sans-serif" font-size="18" font-weight="800" fill="#ffffff" text-anchor="middle">موتور هوش مصنوعی و انتروپی ریاضی شانون</text>
  
  <!-- Math Formula Box -->
  <rect x="50" y="70" width="500" height="70" rx="12" fill="#020617" stroke="#334155" stroke-width="2"/>
  <text x="300" y="115" font-family="'JetBrains Mono', Consolas, monospace" font-size="24" font-weight="700" fill="#38bdf8" text-anchor="middle">H(X) = - &#8721; P(x&#7522;) &middot; log&#8322; P(x&#7522;)</text>

  <!-- Criteria -->
  <g transform="translate(50, 165)">
    <rect width="235" height="100" rx="10" fill="rgba(16,185,129,0.08)" stroke="#10b981"/>
    <text x="117" y="35" font-family="'Segoe UI', sans-serif" font-size="14" font-weight="700" fill="#10b981" text-anchor="middle">ترافیک مجاز استاندارد</text>
    <text x="117" y="65" font-family="'JetBrains Mono', Consolas" font-size="20" font-weight="800" fill="#ffffff" text-anchor="middle">H &lt; 3.80</text>
    <text x="117" y="85" font-family="'Segoe UI', sans-serif" font-size="11" fill="#94a3b8" text-anchor="middle">توزیع طبیعی حروف زبان</text>
  </g>

  <g transform="translate(315, 165)">
    <rect width="235" height="100" rx="10" fill="rgba(239,68,68,0.08)" stroke="#ef4444"/>
    <text x="117" y="35" font-family="'Segoe UI', sans-serif" font-size="14" font-weight="700" fill="#ef4444" text-anchor="middle">ناهنجاری و شل‌کد نفوذ</text>
    <text x="117" y="65" font-family="'JetBrains Mono', Consolas" font-size="20" font-weight="800" fill="#ffffff" text-anchor="middle">H &gt; 4.65</text>
    <text x="117" y="85" font-family="'Segoe UI', sans-serif" font-size="11" fill="#ef4444" text-anchor="middle">مسدودسازی بلادرنگ Zero-Day</text>
  </g>
</svg>"""

# 6. DEVELOPER BADGE SVG (Taha Vaziri)
DEV_BADGE_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 240" width="500" height="240">
  <defs>
    <linearGradient id="devGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#f6821f" />
      <stop offset="100%" stop-color="#06b6d4" />
    </linearGradient>
  </defs>
  <rect width="500" height="240" rx="18" fill="#0f172a" stroke="url(#devGrad)" stroke-width="3"/>
  
  <!-- Avatar Circle with Initials -->
  <circle cx="85" cy="120" r="45" fill="#1e293b" stroke="#f6821f" stroke-width="3"/>
  <text x="85" y="132" font-family="'Segoe UI', sans-serif" font-size="30" font-weight="900" fill="#ffffff" text-anchor="middle">TV</text>
  
  <!-- Info -->
  <text x="155" y="85" font-family="'Segoe UI', sans-serif" font-size="13" font-weight="700" fill="#f6821f">طراح، معمار و توسعه‌دهنده سامانه</text>
  <text x="155" y="125" font-family="'Segoe UI', sans-serif" font-size="30" font-weight="900" fill="#ffffff">طاها وزیری (Taha Vaziri)</text>
  <text x="155" y="160" font-family="'Segoe UI', sans-serif" font-size="14" fill="#94a3b8">توسعه‌دهنده سیستم‌های توزیع‌شده امنیتی و هوش مصنوعی</text>

  <!-- Tags -->
  <g transform="translate(155, 180)">
    <rect width="80" height="24" rx="6" fill="#1e293b"/>
    <text x="40" y="16" font-family="'Segoe UI', sans-serif" font-size="11" font-weight="700" fill="#06b6d4" text-anchor="middle">Rust Core</text>
  </g>
  <g transform="translate(245, 180)">
    <rect width="90" height="24" rx="6" fill="#1e293b"/>
    <text x="45" y="16" font-family="'Segoe UI', sans-serif" font-size="11" font-weight="700" fill="#10b981" text-anchor="middle">Python SOC</text>
  </g>
  <g transform="translate(345, 180)">
    <rect width="90" height="24" rx="6" fill="#1e293b"/>
    <text x="45" y="16" font-family="'Segoe UI', sans-serif" font-size="11" font-weight="700" fill="#8b5cf6" text-anchor="middle">DFA Engine</text>
  </g>
</svg>"""

files = {
    "shield_logo.svg": SHIELD_SVG,
    "dpi_pipeline.svg": DPI_PIPELINE_SVG,
    "redos_chart.svg": REDOS_SVG,
    "scorecard_badge.svg": SCORECARD_SVG,
    "shannon_formula.svg": SHANNON_SVG,
    "dev_badge.svg": DEV_BADGE_SVG,
}

for fname, content in files.items():
    svg_path = os.path.join(ASSETS_DIR, fname)
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Saved SVG: {svg_path}")

print("Rendering high-res PNGs via Chrome/Edge...")

# Render each SVG to PNG using headless browser
for fname in files.keys():
    base_name = os.path.splitext(fname)[0]
    svg_path = os.path.join(ASSETS_DIR, fname)
    png_path = os.path.join(ASSETS_DIR, f"{base_name}.png")
    
    # HTML wrapper for perfect DPI rasterization
    wrapper_html = os.path.join(ASSETS_DIR, f"temp_{base_name}.html")
    with open(wrapper_html, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head>
<style>
  body {{ margin:0; padding:0; background: transparent; display:flex; align-items:center; justify-content:center; }}
</style>
</head>
<body>
  {files[fname]}
</body>
</html>""")
    
    # Run headless Chrome screenshot
    cmd = [
        CHROME_PATH,
        "--headless=new",
        "--hide-scrollbars",
        "--force-device-scale-factor=2",
        f"--screenshot={png_path}",
        wrapper_html
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(png_path):
            print(f"Generated PNG: {png_path} ({os.path.getsize(png_path)} bytes)")
        if os.path.exists(wrapper_html):
            os.remove(wrapper_html)
    except Exception as e:
        print(f"Error rendering {fname}: {e}")

print("All visual assets created successfully!")
