import os
import sys
import math
import wave
import struct
import shutil
import subprocess
import numpy as np
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Target save destinations:
# 1. Directly on the User's Windows Desktop
DESKTOP_DIR = os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\imtah"), "OneDrive", "Desktop")
if not os.path.exists(DESKTOP_DIR):
    DESKTOP_DIR = os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\imtah"), "Desktop")

OUTPUT_DESKTOP_MP4 = os.path.join(DESKTOP_DIR, "ROKH_WAF.mp4")
OUTPUT_PROJECT_MP4 = os.path.join(BASE_DIR, "waf_commercial_ad.mp4")
TEMP_AUDIO = os.path.join(BASE_DIR, "temp_soundtrack.wav")

WIDTH = 1280
HEIGHT = 720
FPS = 30
DURATION_SEC = 21
TOTAL_FRAMES = FPS * DURATION_SEC

# ------------------------------------------------------------------------------
# 1. GENERATE EPIC SYNTHWAVE / CYBERPUNK AD TRAILER SOUNDTRACK (21 SECONDS)
# ------------------------------------------------------------------------------
def generate_soundtrack(filename, duration, sample_rate=44100):
    print(f"[*] Synthesizing {duration}-second cinematic advertising soundtrack...", flush=True)
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    audio = np.zeros_like(t)

    bpm = 128
    beat_interval = 60.0 / bpm
    total_beats = int(duration / beat_interval)
    
    for b in range(total_beats):
        beat_time = b * beat_interval
        if beat_time >= 3.0:
            idx_start = int(beat_time * sample_rate)
            kick_dur = 0.25
            kick_samples = int(kick_dur * sample_rate)
            if idx_start + kick_samples <= len(t):
                kt = np.linspace(0, kick_dur, kick_samples, endpoint=False)
                freq = 150 * np.exp(-18 * kt) + 40
                kick_env = np.exp(-12 * kt)
                kick = np.sin(2 * np.pi * freq * kt) * kick_env * 0.45
                audio[idx_start:idx_start + kick_samples] += kick

    drone_freq = np.where(t < 6.0, 43.6, np.where(t < 13.0, 65.4, 55.0))
    sub_drone = np.sin(2 * np.pi * drone_freq * t) * 0.22
    sub_drone += np.sin(4 * np.pi * drone_freq * t) * 0.08
    audio += sub_drone

    arp_notes = [130.81, 164.81, 196.00, 261.63, 196.00, 164.81]
    sixteenth = beat_interval / 4.0
    for i in range(int(duration / sixteenth)):
        note_time = i * sixteenth
        if 6.0 <= note_time < 20.0:
            idx = int(note_time * sample_rate)
            dur = 0.12
            nsamples = int(dur * sample_rate)
            if idx + nsamples <= len(t):
                note_freq = arp_notes[i % len(arp_notes)]
                nt = np.linspace(0, dur, nsamples, endpoint=False)
                env = np.exp(-25 * nt)
                saw = 0.6 * np.sin(2 * np.pi * note_freq * nt) + 0.3 * np.sin(4 * np.pi * note_freq * nt)
                audio[idx:idx + nsamples] += saw * env * 0.18

    impact_times = [0.0, 3.0, 6.0, 9.5, 13.0]
    for it in impact_times:
        idx = int(it * sample_rate)
        dur = 1.3
        ns = int(dur * sample_rate)
        if idx + ns <= len(t):
            it_t = np.linspace(0, dur, ns, endpoint=False)
            boom = np.sin(2 * np.pi * (80 * np.exp(-5 * it_t)) * it_t) * np.exp(-4 * it_t) * 0.55
            noise = (np.random.rand(ns) * 2 - 1) * np.exp(-15 * it_t) * 0.25
            audio[idx:idx + ns] += boom + noise

    fade_start = int(20.0 * sample_rate)
    fade_len = len(t) - fade_start
    audio[fade_start:] *= np.linspace(1.0, 0.0, fade_len)

    max_amp = np.max(np.abs(audio))
    if max_amp > 0:
        audio = (audio / max_amp) * 0.88

    audio_int16 = (audio * 32767).astype(np.int16)
    with wave.open(filename, 'w') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(audio_int16.tobytes())
    print(f"[+] Audio track synthesized successfully: {filename}", flush=True)

# ------------------------------------------------------------------------------
# 2. FRAME RENDERING ENGINE WITH VECTOR GRAPHICS & TYPOGRAPHY
# ------------------------------------------------------------------------------
def get_font(size, bold=True):
    font_names = [
        "C:\\Windows\\Fonts\\segoeuib.ttf" if bold else "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\arialbd.ttf" if bold else "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\tahomabd.ttf" if bold else "C:\\Windows\\Fonts\\tahoma.ttf",
        "C:\\Windows\\Fonts\\impact.ttf"
    ]
    for fn in font_names:
        if os.path.exists(fn):
            try:
                return ImageFont.truetype(fn, size)
            except Exception:
                pass
    return ImageFont.load_default()

def draw_cyber_grid(draw, frame_idx, color=(15, 23, 42)):
    offset = (frame_idx * 4) % 60
    for x in range(-60 + offset, WIDTH + 60, 60):
        draw.line([(x, 0), (x, HEIGHT)], fill=color, width=1)
    for y in range(-60 + offset, HEIGHT + 60, 60):
        draw.line([(0, y), (WIDTH, y)], fill=color, width=1)

def draw_vignette_and_bars(draw):
    bar_height = 36
    draw.rectangle([(0, 0), (WIDTH, bar_height)], fill=(2, 6, 23))
    draw.rectangle([(0, HEIGHT - bar_height), (WIDTH, HEIGHT)], fill=(2, 6, 23))

def draw_rust_vector_logo(draw, cx, cy, radius=24, color=(246, 130, 31)):
    # Outer Gear Ring
    draw.ellipse([(cx - radius, cy - radius), (cx + radius, cy + radius)], outline=color, width=3)
    for i in range(8):
        ang = i * (math.pi / 4)
        gx = cx + math.cos(ang) * (radius + 4)
        gy = cy + math.sin(ang) * (radius + 4)
        draw.rectangle([(gx - 3, gy - 3), (gx + 3, gy + 3)], fill=color)
    # Inner Hub
    inner_r = radius // 2
    draw.ellipse([(cx - inner_r, cy - inner_r), (cx + inner_r, cy + inner_r)], outline=color, width=2)
    f_r = get_font(18, bold=True)
    draw.text((cx, cy), "R", font=f_r, fill=(255, 255, 255), anchor="mm")

def draw_dataset_vector_logo(draw, cx, cy, radius=22, color=(56, 189, 248)):
    # 3 Stacked Cylinders
    for dy in [-12, 0, 12]:
        draw.ellipse([(cx - radius, cy + dy - 6), (cx + radius, cy + dy + 6)], outline=color, width=2)
    draw.line([(cx - radius, cy - 12), (cx - radius, cy + 12)], fill=color, width=2)
    draw.line([(cx + radius, cy - 12), (cx + radius, cy + 12)], fill=color, width=2)

def draw_decision_vector_logo(draw, cx, cy, radius=22, color=(168, 85, 247)):
    # CPU Core Square
    draw.rectangle([(cx - radius, cy - radius), (cx + radius, cy + radius)], outline=color, width=2)
    draw.rectangle([(cx - radius//2, cy - radius//2), (cx + radius//2, cy + radius//2)], fill=color)
    # Bus Traces / Pins
    for p in [-10, 0, 10]:
        draw.line([(cx + p, cy - radius), (cx + p, cy - radius - 5)], fill=color, width=2)
        draw.line([(cx + p, cy + radius), (cx + p, cy + radius + 5)], fill=color, width=2)
        draw.line([(cx - radius, cy + p), (cx - radius - 5, cy + p)], fill=color, width=2)
        draw.line([(cx + radius, cy + p), (cx + radius + 5, cy + p)], fill=color, width=2)

def render_frame(f_idx):
    sec = f_idx / FPS
    img = Image.new("RGB", (WIDTH, HEIGHT), (4, 8, 18))
    draw = ImageDraw.Draw(img)

    # --------------------------------------------------------------------------
    # SCENE 1 (0.0s - 3.0s): THE HOOK / RED ALERT / CYBER CRISIS
    # --------------------------------------------------------------------------
    if sec < 3.0:
        strobe = int(abs(math.sin(sec * 12)) * 60)
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(25 + strobe, 4, 12))
        draw_cyber_grid(draw, f_idx, color=(60 + strobe, 10, 20))

        font_badge = get_font(20, bold=True)
        draw.rectangle([(WIDTH//2 - 180, 120), (WIDTH//2 + 180, 160)], outline=(255, 0, 85), width=2, fill=(35, 5, 15))
        draw.text((WIDTH//2, 140), "CRITICAL ALERT: ZERO-DAY EXPLOITS", font=font_badge, fill=(255, 60, 100), anchor="mm")

        glitch_x = (math.sin(f_idx * 2) * 5) if (f_idx % 4 == 0) else 0
        font_hero = get_font(62, bold=True)
        draw.text((WIDTH//2 + glitch_x, 260), "IS YOUR WEBSITE SAFE?", font=font_hero, fill=(255, 255, 255), anchor="mm")

        font_sub = get_font(32, bold=True)
        threats = ["500,000 REQ/SEC DDoS FLOOD", "SQL INJECTIONS", "ZERO-DAY EXPLOITS", "RCE REMOTE SHELLS"]
        curr_threat = threats[int(sec * 2.5) % len(threats)]
        draw.text((WIDTH//2, 360), curr_threat, font=font_sub, fill=(255, 0, 85), anchor="mm")

        font_mono = get_font(20, bold=False)
        dots = "." * (int(sec * 6) % 4)
        draw.text((WIDTH//2, 500), f">> SERVER OVERLOAD DETECTED {dots} SYSTEM CRASH IMMINENT", font=font_mono, fill=(244, 63, 94), anchor="mm")

    # --------------------------------------------------------------------------
    # SCENE 2 (3.0s - 6.0s): THE PROBLEM / LEGACY WAF FAILURE
    # --------------------------------------------------------------------------
    elif sec < 6.0:
        local_t = (sec - 3.0) / 3.0
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(12, 10, 24))
        draw_cyber_grid(draw, f_idx, color=(30, 25, 50))

        font_badge = get_font(20, bold=True)
        draw.rectangle([(WIDTH//2 - 200, 120), (WIDTH//2 + 200, 160)], outline=(245, 158, 11), width=2, fill=(25, 20, 10))
        draw.text((WIDTH//2, 140), "THE LEGACY SECURITY BOTTLENECK", font=font_badge, fill=(245, 158, 11), anchor="mm")

        font_hero = get_font(54, bold=True)
        draw.text((WIDTH//2, 240), "TRADITIONAL WAFs ARE BROKEN.", font=font_hero, fill=(255, 255, 255), anchor="mm")

        point_font = get_font(26, bold=True)
        if local_t > 0.15:
            draw.text((WIDTH//2, 340), "120ms Latency Overhead (Slows down real users)", font=point_font, fill=(239, 68, 68), anchor="mm")
        if local_t > 0.45:
            draw.text((WIDTH//2, 400), "High False Positive Rates (Blocks legitimate shoppers)", font=point_font, fill=(239, 68, 68), anchor="mm")
        if local_t > 0.70:
            draw.text((WIDTH//2, 460), "Severe Memory Leaks & ReDoS Vulnerabilities", font=point_font, fill=(239, 68, 68), anchor="mm")

    # --------------------------------------------------------------------------
    # SCENE 3 (6.0s - 9.5s): THE HERO REVEAL / ROKH WAF
    # --------------------------------------------------------------------------
    elif sec < 9.5:
        local_t = (sec - 6.0) / 3.5
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(2, 6, 23))
        draw_cyber_grid(draw, f_idx, color=(8, 30, 60))

        pulse = math.sin(f_idx * 0.15) * 8
        shield_r = max(50, min(160, int(local_t * 220)) + int(pulse))
        
        for r_step, alpha in [(shield_r + 25, (6, 182, 212)), (shield_r, (0, 243, 255)), (max(15, shield_r - 20), (59, 130, 246))]:
            draw.ellipse(
                [(WIDTH//2 - r_step, HEIGHT//2 - r_step), (WIDTH//2 + r_step, HEIGHT//2 + r_step)],
                outline=alpha, width=3
            )

        hex_points = []
        inner_r = max(20, shield_r - 40)
        for i in range(6):
            ang = (i * math.pi / 3) + (f_idx * 0.02)
            hx = WIDTH//2 + math.cos(ang) * inner_r
            hy = HEIGHT//2 + math.sin(ang) * inner_r
            hex_points.append((hx, hy))
        draw.polygon(hex_points, outline=(0, 243, 255), fill=(10, 25, 55))

        font_hero_brand = get_font(72, bold=True)
        draw.text((WIDTH//2, HEIGHT//2 - 15), "ROKH WAF", font=font_hero_brand, fill=(255, 255, 255), anchor="mm")
        
        font_slogan = get_font(24, bold=True)
        draw.text((WIDTH//2, HEIGHT//2 + 45), "NEXT-GEN ENTERPRISE EDGE DEFENSE", font=font_slogan, fill=(6, 182, 212), anchor="mm")

        font_tech = get_font(18, bold=False)
        draw.text((WIDTH//2, 130), "RUST TOKIO ASYNC CORE  |  SHANNON ENTROPY AI", font=font_tech, fill=(147, 197, 253), anchor="mm")

    # --------------------------------------------------------------------------
    # SCENE 4 (9.5s - 13.0s): ENTERPRISE BENCHMARK RESULTS
    # --------------------------------------------------------------------------
    elif sec < 13.0:
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(3, 7, 18))
        draw_cyber_grid(draw, f_idx, color=(12, 35, 65))

        font_title = get_font(40, bold=True)
        draw.text((WIDTH//2, 110), "ENTERPRISE-GRADE BENCHMARK RESULTS", font=font_title, fill=(255, 255, 255), anchor="mm")

        cards = [
            ("0.12 ms", "P99 LATENCY", "Bare-Metal Zero-Copy Tokio Proxy", (0, 243, 255)),
            ("93.9%", "LIVE CATCH RATE", "Tested Against 796 SecLists Attacks", (16, 185, 129)),
            ("0.00%", "FALSE POSITIVES", "Zero Legitimate Packets Blocked", (59, 130, 246))
        ]

        card_width = 340
        card_gap = 40
        total_w = len(cards) * card_width + (len(cards) - 1) * card_gap
        start_x = (WIDTH - total_w) // 2

        font_stat_val = get_font(44, bold=True)
        font_stat_title = get_font(18, bold=True)
        font_stat_sub = get_font(14, bold=False)

        for i, (val, title, desc, col) in enumerate(cards):
            cx = start_x + i * (card_width + card_gap)
            cy = 220
            draw.rectangle([(cx, cy), (cx + card_width, cy + 280)], fill=(15, 23, 42), outline=col, width=2)
            draw.rectangle([(cx, cy), (cx + card_width, cy + 8)], fill=col)
            draw.text((cx + card_width//2, cy + 80), val, font=font_stat_val, fill=col, anchor="mm")
            draw.text((cx + card_width//2, cy + 150), title, font=font_stat_title, fill=(255, 255, 255), anchor="mm")
            draw.text((cx + card_width//2, cy + 200), desc, font=font_stat_sub, fill=(148, 163, 184), anchor="mm")

        font_foot = get_font(18, bold=True)
        draw.text((WIDTH//2, 580), "OFFICIAL INDUSTRY GRADE: A (HIGH-ASSURANCE RESILIENCE)", font=font_foot, fill=(245, 158, 11), anchor="mm")

    # --------------------------------------------------------------------------
    # SCENE 5 (13.0s - 21.0s): SIMPLE & ELEGANT 3-CARD STACK + DEVELOPER CREDIT
    # --------------------------------------------------------------------------
    else:
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(2, 6, 20))
        draw_cyber_grid(draw, f_idx, color=(14, 40, 75))

        # Top Category Pill
        font_badge = get_font(15, bold=True)
        draw.rectangle([(WIDTH//2 - 180, 50), (WIDTH//2 + 180, 82)], outline=(6, 182, 212), width=1, fill=(10, 25, 45))
        draw.text((WIDTH//2, 66), "ARCHITECTURE & SYSTEM CREDITS", font=font_badge, fill=(6, 182, 212), anchor="mm")

        # Main Developer Title (Simple, clean, exactly as requested: 'توسعه دهنده: طاها وزیری')
        font_dev_en = get_font(42, bold=True)
        draw.text((WIDTH//2, 118), "DEVELOPER: TAHA VAZIRI", font=font_dev_en, fill=(255, 255, 255), anchor="mm")

        font_dev_fa = get_font(24, bold=True)
        draw.text((WIDTH//2, 162), "توسعه دهنده: طاها وزیری", font=font_dev_fa, fill=(6, 182, 212), anchor="mm")

        # 3 Clean Large Cards with Distinct Colors and Vector Logos
        cards_data = [
            {
                "title_fa": "زبان هسته Rust",
                "title_en": "Core Language: Rust",
                "sub": "Tokio Async Engine & Zero-Copy Proxy",
                "color": (246, 130, 31),
                "draw_icon": draw_rust_vector_logo
            },
            {
                "title_fa": "دیتاست ها برای یادگیری ماشین",
                "title_en": "Machine Learning Datasets",
                "sub": "SecLists Corpora & Python Vectorizer",
                "color": (56, 189, 248),
                "draw_icon": draw_dataset_vector_logo
            },
            {
                "title_fa": "زبان ماشین تصمیم گیری",
                "title_en": "Decision Machine Engine",
                "sub": "Shannon Entropy AI & DFA Automata",
                "color": (168, 85, 247),
                "draw_icon": draw_decision_vector_logo
            }
        ]

        card_w = 360
        card_h = 240
        gap = 30
        total_w = len(cards_data) * card_w + (len(cards_data) - 1) * gap
        start_x = (WIDTH - total_w) // 2
        card_y = 215

        font_c_title_fa = get_font(21, bold=True)
        font_c_title_en = get_font(17, bold=True)
        font_c_sub = get_font(13, bold=False)

        for i, cd in enumerate(cards_data):
            cx = start_x + i * (card_w + gap)
            cy = card_y

            # Outer Card Box
            draw.rectangle([(cx, cy), (cx + card_w, cy + card_h)], fill=(12, 18, 34), outline=cd["color"], width=2)
            # Glowing Accent Top Line
            draw.rectangle([(cx, cy), (cx + card_w, cy + 6)], fill=cd["color"])

            # Center Vector Icon
            icon_cx = cx + card_w // 2
            icon_cy = cy + 55
            cd["draw_icon"](draw, icon_cx, icon_cy, radius=26, color=cd["color"])

            # Persian Title
            draw.text((cx + card_w // 2, cy + 125), cd["title_fa"], font=font_c_title_fa, fill=(255, 255, 255), anchor="mm")
            # English Title
            draw.text((cx + card_w // 2, cy + 160), cd["title_en"], font=font_c_title_en, fill=cd["color"], anchor="mm")
            # Subtitle Description
            draw.text((cx + card_w // 2, cy + 195), cd["sub"], font=font_c_sub, fill=(148, 163, 184), anchor="mm")

        # Bottom Bar
        font_footer = get_font(15, bold=True)
        draw.rectangle([(WIDTH//2 - 420, 570), (WIDTH//2 + 420, 615)], fill=(8, 14, 28), outline=(6, 182, 212), width=1)
        draw.text((WIDTH//2, 592), "ROKH WAF | OPEN-SOURCE EDGE DEFENSE | HTTPS://GITHUB.COM/LASTPW/ROKH-WAF", font=font_footer, fill=(147, 197, 253), anchor="mm")

    draw_vignette_and_bars(draw)
    return img

# ------------------------------------------------------------------------------
# 3. MAIN RENDER PIPELINE VIA FFMPEG
# ------------------------------------------------------------------------------
def main():
    print("=" * 70, flush=True)
    print(" [*] RENDERING FULL-HD COMMERCIAL MOTION GRAPHIC VIDEO (MP4)", flush=True)
    print(f" Resolution    : {WIDTH}x{HEIGHT} @ {FPS} FPS")
    print(f" Duration      : {DURATION_SEC} Seconds ({TOTAL_FRAMES} frames)")
    print(f" Primary Path  : {OUTPUT_DESKTOP_MP4}")
    print(f" Project Path  : {OUTPUT_PROJECT_MP4}")
    print("=" * 70, flush=True)

    # 1. Synthesize Soundtrack
    generate_soundtrack(TEMP_AUDIO, DURATION_SEC)

    # 2. Launch FFmpeg Process for rawvideo stream directly to Project MP4
    cmd = [
        "ffmpeg",
        "-y",
        "-f", "rawvideo",
        "-vcodec", "rawvideo",
        "-s", f"{WIDTH}x{HEIGHT}",
        "-pix_fmt", "rgb24",
        "-r", str(FPS),
        "-i", "-",                     # Pipe raw frames via stdin
        "-i", TEMP_AUDIO,              # Audio soundtrack
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "18",                  # Pristine visual quality
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        OUTPUT_PROJECT_MP4
    ]

    print("[*] Launching FFmpeg encoder...", flush=True)
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        for f in range(TOTAL_FRAMES):
            frame_img = render_frame(f)
            raw_data = frame_img.tobytes()
            proc.stdin.write(raw_data)
            if f % 45 == 0 or f == TOTAL_FRAMES - 1:
                pct = (f + 1) / TOTAL_FRAMES * 100
                print(f" [*] Rendering Progress: {f + 1}/{TOTAL_FRAMES} frames ({pct:.1f}%)", flush=True)
        
        proc.stdin.close()
        proc.wait()
        if proc.returncode != 0:
            print("[!] FFmpeg process returned error code", flush=True)
        else:
            # Also copy directly to Desktop so user has it right on their desktop screen!
            try:
                shutil.copyfile(OUTPUT_PROJECT_MP4, OUTPUT_DESKTOP_MP4)
            except Exception as ce:
                print(f"[!] Notice copying to desktop: {ce}", flush=True)

            size_mb = os.path.getsize(OUTPUT_PROJECT_MP4) / (1024 * 1024)
            print("=" * 70, flush=True)
            print(f"[+] SUCCESS: Video rendered and saved in two locations!", flush=True)
            print(f" [1] Directly on Desktop: {OUTPUT_DESKTOP_MP4} ({size_mb:.2f} MB)", flush=True)
            print(f" [2] Project Directory  : {OUTPUT_PROJECT_MP4}", flush=True)
            print("=" * 70, flush=True)
    except Exception as e:
        print(f"[!] Render failed: {e}", flush=True)
    finally:
        if os.path.exists(TEMP_AUDIO):
            try:
                os.remove(TEMP_AUDIO)
            except Exception:
                pass

if __name__ == "__main__":
    main()
