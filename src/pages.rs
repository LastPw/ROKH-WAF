// ==============================================================================
// ROKH WAF - High-Tech Cyber Security Error & Block Pages
// ==============================================================================

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn render_security_block_page(
    incident_id: &str,
    client_ip: &str,
    attack_type: &str,
    rule_id: &str,
    severity: &str,
    matched_trigger: &str,
    status_code: u16,
    message: &str,
) -> String {
    let esc_incident = html_escape(incident_id);
    let esc_ip = html_escape(client_ip);
    let esc_attack = html_escape(attack_type);
    let esc_rule = html_escape(rule_id);
    let esc_sev = html_escape(severity);
    let esc_trigger = html_escape(matched_trigger);
    let esc_msg = html_escape(message);

    let is_ddos = status_code == 429 || attack_type.contains("DDOS");
    let status_title = if is_ddos {
        "۴۲۹ محدودیت نرخ ترافیک (DDoS Mitigation)"
    } else {
        "۴۰۳ دسترسی مسدود شد (Access Denied)"
    };

    let badge_color = if is_ddos { "#f6821f" } else { "#ef4444" };
    let border_color = if is_ddos { "rgba(246, 130, 31, 0.4)" } else { "rgba(239, 68, 68, 0.4)" };

    format!(r##"<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{status_title} | دیواره آتش رُخ (ROKH WAF)</title>
    <style>
        :root {{
            --bg-deep: #07090e;
            --bg-card: rgba(14, 19, 32, 0.82);
            --accent-red: #ef4444;
            --accent-orange: #f6821f;
            --accent-cyan: #06b6d4;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --font-mono: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
            --font-sans: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-deep);
            color: var(--text-main);
            font-family: var(--font-sans);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            overflow-x: hidden;
            position: relative;
        }}

        /* Subtle Cybernetic Grid Background */
        body::before {{
            content: '';
            position: absolute;
            inset: 0;
            background-image: 
                linear-gradient(to right, rgba(255, 255, 255, 0.02) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }}

        /* Ambient Glowing Orbs */
        .glow-orb {{
            position: absolute;
            width: 480px;
            height: 480px;
            border-radius: 50%;
            filter: blur(120px);
            opacity: 0.18;
            pointer-events: none;
            z-index: 0;
        }}
        .orb-red {{
            top: 10%;
            left: 20%;
            background: radial-gradient(circle, {badge_color} 0%, transparent 70%);
        }}
        .orb-cyan {{
            bottom: 10%;
            right: 20%;
            background: radial-gradient(circle, #06b6d4 0%, transparent 70%);
        }}

        .security-container {{
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 820px;
            background: var(--bg-card);
            border: 1px solid {border_color};
            border-radius: 20px;
            box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.8), 0 0 40px -10px rgba(239, 68, 68, 0.2);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            padding: 40px 44px;
            animation: fadeInCard 0.45s ease-out;
        }}

        @keyframes fadeInCard {{
            from {{ opacity: 0; transform: translateY(16px) scale(0.98); }}
            to {{ opacity: 1; transform: translateY(0) scale(1); }}
        }}

        /* Top Header */
        .card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.07);
            padding-bottom: 24px;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 16px;
        }}

        .brand-badge {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .shield-icon {{
            width: 44px;
            height: 44px;
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.35);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.25);
        }}

        .shield-icon svg {{
            width: 24px;
            height: 24px;
            stroke: {badge_color};
            fill: none;
            stroke-width: 2;
            stroke-linecap: round;
            stroke-linejoin: round;
        }}

        .brand-title {{
            font-size: 19px;
            font-weight: 800;
            letter-spacing: -0.3px;
            color: #fff;
        }}

        .brand-title span {{
            color: {badge_color};
        }}

        .edge-status {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.09);
            padding: 6px 14px;
            border-radius: 999px;
            font-size: 12px;
            font-family: var(--font-mono);
            color: var(--text-muted);
        }}

        .pulse-dot {{
            width: 8px;
            height: 8px;
            background-color: {badge_color};
            border-radius: 50%;
            box-shadow: 0 0 10px {badge_color};
            animation: pulseAnim 1.8s infinite;
        }}

        @keyframes pulseAnim {{
            0%, 100% {{ transform: scale(1); opacity: 1; }}
            50% {{ transform: scale(1.4); opacity: 0.5; }}
        }}

        /* Hero Notice */
        .notice-hero {{
            margin-bottom: 28px;
        }}

        .status-code {{
            font-family: var(--font-mono);
            font-size: 13px;
            font-weight: 700;
            color: {badge_color};
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 8px;
        }}

        .notice-title {{
            font-size: 28px;
            font-weight: 800;
            line-height: 1.3;
            margin-bottom: 12px;
            color: #ffffff;
        }}

        .notice-desc {{
            font-size: 14.5px;
            color: var(--text-muted);
            line-height: 1.7;
            max-width: 720px;
        }}

        /* Forensic Grid */
        .forensic-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }}

        .forensic-card {{
            background: rgba(255, 255, 255, 0.025);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            padding: 14px 16px;
            transition: border-color 0.2s;
        }}

        .forensic-card:hover {{
            border-color: rgba(255, 255, 255, 0.15);
        }}

        .card-label {{
            font-size: 11.5px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}

        .card-value {{
            font-family: var(--font-mono);
            font-size: 13.5px;
            font-weight: 700;
            color: #fff;
            word-break: break-all;
        }}

        .card-value.highlight {{
            color: {badge_color};
        }}

        /* Forensic Code Box */
        .evidence-box {{
            background: rgba(0, 0, 0, 0.45);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 28px;
            font-family: var(--font-mono);
            font-size: 12.5px;
        }}

        .evidence-header {{
            display: flex;
            justify-content: space-between;
            color: var(--text-muted);
            font-size: 11.5px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
            padding-bottom: 8px;
            margin-bottom: 10px;
        }}

        .evidence-content {{
            color: #fca5a5;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.5;
        }}

        /* Footer & Actions */
        .card-footer {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-top: 1px solid rgba(255, 255, 255, 0.07);
            padding-top: 24px;
            flex-wrap: wrap;
            gap: 16px;
        }}

        .copy-btn {{
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: #fff;
            padding: 9px 18px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
        }}

        .copy-btn:hover {{
            background: rgba(255, 255, 255, 0.12);
            border-color: rgba(255, 255, 255, 0.25);
            transform: translateY(-1px);
        }}

        .support-info {{
            font-size: 12.5px;
            color: var(--text-muted);
            line-height: 1.6;
        }}

        .support-info strong {{
            color: #e2e8f0;
        }}

        @media (max-width: 640px) {{
            .security-container {{
                padding: 24px 20px;
            }}
            .notice-title {{
                font-size: 22px;
            }}
            .forensic-grid {{
                grid-template-columns: 1fr 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="glow-orb orb-red"></div>
    <div class="glow-orb orb-cyan"></div>

    <main class="security-container">
        <!-- Top Bar -->
        <header class="card-header">
            <div class="brand-badge">
                <div class="shield-icon">
                    <svg viewBox="0 0 24 24">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    </svg>
                </div>
                <div class="brand-title">
                    دیواره آتش <span>رُخ</span> (ROKH WAF)
                </div>
            </div>
            <div class="edge-status">
                <span class="pulse-dot"></span>
                <span>Anycast Edge Core · Rust DFA</span>
            </div>
        </header>

        <!-- Main Banner -->
        <section class="notice-hero">
            <div class="status-code">HTTP {status_code} · SECURITY INTERCEPTION</div>
            <h1 class="notice-title">{status_title}</h1>
            <p class="notice-desc">
                درخواست ارسالی شما حاوی الگوهای تهاجمی و رفتارهای نفوذ به لایه برنامه تشخیص داده شد و پیش از دسترسی به سرور مبدا، توسط هسته دفاعی رُخ متوقف گردید.
                {esc_msg}
            </p>
        </section>

        <!-- Forensics Matrix -->
        <section class="forensic-grid">
            <div class="forensic-card">
                <div class="card-label">شناسه رویداد (Ray ID)</div>
                <div class="card-value highlight">{esc_incident}</div>
            </div>
            <div class="forensic-card">
                <div class="card-label">نوع تهدید شناسایی‌شده</div>
                <div class="card-value">{esc_attack}</div>
            </div>
            <div class="forensic-card">
                <div class="card-label">شناسه قانون امنیتی</div>
                <div class="card-value">{esc_rule}</div>
            </div>
            <div class="forensic-card">
                <div class="card-label">آی‌پی درخواست‌دهنده</div>
                <div class="card-value">{esc_ip}</div>
            </div>
        </section>

        <!-- Trigger Evidence -->
        <section class="evidence-box">
            <div class="evidence-header">
                <span>ردپای بسته نفوذ (Matched Pattern Trigger)</span>
                <span>سطح خطر: {esc_sev}</span>
            </div>
            <div class="evidence-content">{esc_trigger}</div>
        </section>

        <!-- Footer / Action -->
        <footer class="card-footer">
            <div class="support-info">
                در صورتی که معتقدید این مسدودسازی به اشتباه رخ داده است، لطفاً شناسه رویداد <strong>{esc_incident}</strong> را برای مدیر سامانه ارسال فرمایید.
            </div>
            <button class="copy-btn" onclick="copyRayId('{esc_incident}')">
                <span id="btnText">کپی شناسه رویداد (Copy Ray ID)</span>
            </button>
        </footer>
    </main>

    <script>
        function copyRayId(id) {{
            navigator.clipboard.writeText(id).then(function() {{
                const btn = document.getElementById('btnText');
                const orig = btn.innerText;
                btn.innerText = 'کپی شد! (Copied)';
                setTimeout(function() {{
                    btn.innerText = orig;
                }}, 2000);
            }}).catch(function() {{}});
        }}
    </script>
</body>
</html>
"##)
}
