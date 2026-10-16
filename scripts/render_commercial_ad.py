import os
import sys
import math
import wave
import struct
import subprocess
import numpy as np
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
OUTPUT_MP4 = os.path.join(BASE_DIR, "waf_commercial_ad.mp4")
TEMP_AUDIO = os.path.join(BASE_DIR, "temp_soundtrack.wav")

WIDTH = 1280
HEIGHT = 720
FPS = 30
DURATION_SEC = 16
TOTAL_FRAMES = FPS * DURATION_SEC

# ------------------------------------------------------------------------------
# 1. GENERATE EPIC SYNTHWAVE / CYBERPUNK AD TRAILER SOUNDTRACK
# ------------------------------------------------------------------------------
def generate_soundtrack(filename, duration, sample_rate=44100):
    print("[*] Synthesizing 16-second cinematic advertising soundtrack...", flush=True)
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    audio = np.zeros_like(t)

    # A) Driving 128 BPM Techno/Cyber Kick Drum
    bpm = 128
    beat_interval = 60.0 / bpm
    total_beats = int(duration / beat_interval)
    
    for b in range(total_beats):
        beat_time = b * beat_interval
        # Start kicks from 3.0s onwards (Scene 2+)
        if beat_time >= 3.0:
            idx_start = int(beat_time * sample_rate)
            kick_dur = 0.25
            kick_samples = int(kick_dur * sample_rate)
            if idx_start + kick_samples <= len(t):
                kt = np.linspace(0, kick_dur, kick_samples, endpoint=False)
                # Pitch sweep from 150Hz down to 40Hz
                freq = 150 * np.exp(-18 * kt) + 40
                kick_env = np.exp(-12 * kt)
                kick = np.sin(2 * np.pi * freq * kt) * kick_env * 0.45
                audio[idx_start:idx_start + kick_samples] += kick

    # B) Dark Cinematic Sub-Bass Drone (C2 = 65.4Hz / F1 = 43.6Hz)
    drone_freq = np.where(t < 6.0, 43.6, np.where(t < 12.0, 65.4, 55.0))
    sub_drone = np.sin(2 * np.pi * drone_freq * t) * 0.22
    # Add subtle harmonic saturation
    sub_drone += np.sin(4 * np.pi * drone_freq * t) * 0.08
    audio += sub_drone

    # C) Arpeggiator Synth (Starts from Scene 3: 6.0s - 16.0s)
    arp_notes = [130.81, 164.81, 196.00, 261.63, 196.00, 164.81] # C major / cyber
    sixteenth = beat_interval / 4.0
    for i in range(int(duration / sixteenth)):
        note_time = i * sixteenth
        if 6.0 <= note_time < 15.0:
            idx = int(note_time * sample_rate)
            dur = 0.12
            nsamples = int(dur * sample_rate)
            if idx + nsamples <= len(t):
                note_freq = arp_notes[i % len(arp_notes)]
                nt = np.linspace(0, dur, nsamples, endpoint=False)
                env = np.exp(-25 * nt)
                # Sawtooth wave approximation
                saw = 0.6 * np.sin(2 * np.pi * note_freq * nt) + 0.3 * np.sin(4 * np.pi * note_freq * nt)
                audio[idx:idx + nsamples] += saw * env * 0.18

    # D) Transition Impacts & Risers at Scene Changes (0s, 3s, 6s, 9s, 12s)
    impact_times = [0.0, 3.0, 6.0, 9.0, 12.0]
    for it in impact_times:
        idx = int(it * sample_rate)
        # Low boom impact
        dur = 1.2
        ns = int(dur * sample_rate)
        if idx + ns <= len(t):
            it_t = np.linspace(0, dur, ns, endpoint=False)
            boom = np.sin(2 * np.pi * (80 * np.exp(-5 * it_t)) * it_t) * np.exp(-4 * it_t) * 0.5
            # Add noise burst
            noise = (np.random.rand(ns) * 2 - 1) * np.exp(-15 * it_t) * 0.25
            audio[idx:idx + ns] += boom + noise

    # E) Final Fade-out at 15.5s - 16.0s
    fade_start = int(15.0 * sample_rate)
    fade_len = len(t) - fade_start
    audio[fade_start:] *= np.linspace(1.0, 0.0, fade_len)

    # Normalize audio to prevent clipping
    max_amp = np.max(np.abs(audio))
    if max_amp > 0:
        audio = (audio / max_amp) * 0.88

    # Export to 16-bit WAV
    audio_int16 = (audio * 32767).astype(np.int16)
    with wave.open(filename, 'w') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(audio_int16.tobytes())
    print(f"[+] Audio track synthesized successfully: {filename}", flush=True)

# ------------------------------------------------------------------------------
# 2. FRAME RENDERING ENGINE WITH KINETIC TYPOGRAPHY & MOTION GRAPHICS
# ------------------------------------------------------------------------------
def get_font(size, bold=True):
    font_names = [
        "C:\\Windows\\Fonts\\arialbd.ttf" if bold else "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\impact.ttf",
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\tahoma.ttf"
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
    # Cinematic 2.39:1 letterbox bars
    bar_height = 42
    draw.rectangle([(0, 0), (WIDTH, bar_height)], fill=(2, 6, 23))
    draw.rectangle([(0, HEIGHT - bar_height), (WIDTH, HEIGHT)], fill=(2, 6, 23))

def render_frame(f_idx):
    sec = f_idx / FPS
    img = Image.new("RGB", (WIDTH, HEIGHT), (4, 8, 18))
    draw = ImageDraw.Draw(img)

    # --------------------------------------------------------------------------
    # SCENE 1 (0.0s - 3.0s): THE HOOK / RED ALERT / CYBER CRISIS
    # --------------------------------------------------------------------------
    if sec < 3.0:
        local_t = sec / 3.0
        # Red warning strobe background
        strobe = int(abs(math.sin(sec * 12)) * 60)
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(25 + strobe, 4, 12))
        draw_cyber_grid(draw, f_idx, color=(60 + strobe, 10, 20))

        # Alert Badge
        font_badge = get_font(20, bold=True)
        draw.rectangle([(WIDTH//2 - 180, 120), (WIDTH//2 + 180, 160)], outline=(255, 0, 85), width=2, fill=(35, 5, 15))
        draw.text((WIDTH//2, 140), "⚠️ CRITICAL ALERT: CYBER ATTACK", font=font_badge, fill=(255, 60, 100), anchor="mm")

        # Big Kinetic Typography with glitch jitter
        glitch_x = (math.sin(f_idx * 2) * 5) if (f_idx % 4 == 0) else 0
        font_hero = get_font(62, bold=True)
        draw.text((WIDTH//2 + glitch_x, 260), "IS YOUR WEBSITE SAFE?", font=font_hero, fill=(255, 255, 255), anchor="mm")

        # Threat Vectors subtext
        font_sub = get_font(32, bold=True)
        threats = ["500,000 REQ/SEC DDoS FLOOD", "SQL INJECTIONS", "ZERO-DAY EXPLOITS", "RCE REMOTE SHELLS"]
        curr_threat = threats[int(sec * 2.5) % len(threats)]
        draw.text((WIDTH//2, 360), curr_threat, font=font_sub, fill=(255, 0, 85), anchor="mm")

        # Terminal status bar
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
        draw.text((WIDTH//2, 140), "❌ THE LEGACY SECURITY TRAP", font=font_badge, fill=(245, 158, 11), anchor="mm")

        font_hero = get_font(56, bold=True)
        draw.text((WIDTH//2, 240), "TRADITIONAL WAFs ARE BROKEN.", font=font_hero, fill=(255, 255, 255), anchor="mm")

        # Comparison points appearing sequentially
        point_font = get_font(26, bold=True)
        if local_t > 0.15:
            draw.text((WIDTH//2, 340), "120ms Latency Overhead (Slows down users)", font=point_font, fill=(239, 68, 68), anchor="mm")
        if local_t > 0.45:
            draw.text((WIDTH//2, 400), "High False Positive Rates (Blocks clean clients)", font=point_font, fill=(239, 68, 68), anchor="mm")
        if local_t > 0.70:
            draw.text((WIDTH//2, 460), "Massive CPU & Memory Bloat (Crashes under surge)", font=point_font, fill=(239, 68, 68), anchor="mm")

    # --------------------------------------------------------------------------
    # SCENE 3 (6.0s - 9.5s): THE HERO REVEAL / ROKH WAF
    # --------------------------------------------------------------------------
    elif sec < 9.5:
        local_t = (sec - 6.0) / 3.5
        # Deep sci-fi void with cyan grid
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(2, 6, 23))
        draw_cyber_grid(draw, f_idx, color=(8, 30, 60))

        # Animated Expanding Shield Core
        pulse = math.sin(f_idx * 0.15) * 8
        shield_r = max(50, min(160, int(local_t * 220)) + int(pulse))
        
        # Concentric glowing rings
        for r_step, alpha in [(shield_r + 25, (6, 182, 212)), (shield_r, (0, 243, 255)), (max(15, shield_r - 20), (59, 130, 246))]:
            draw.ellipse(
                [(WIDTH//2 - r_step, HEIGHT//2 - r_step), (WIDTH//2 + r_step, HEIGHT//2 + r_step)],
                outline=alpha, width=3
            )

        # Hexagonal core shield
        hex_points = []
        inner_r = max(20, shield_r - 40)
        for i in range(6):
            ang = (i * math.pi / 3) + (f_idx * 0.02)
            hx = WIDTH//2 + math.cos(ang) * inner_r
            hy = HEIGHT//2 + math.sin(ang) * inner_r
            hex_points.append((hx, hy))
        draw.polygon(hex_points, outline=(0, 243, 255), fill=(10, 25, 55))

        # Hero Brand Title
        font_hero_brand = get_font(72, bold=True)
        draw.text((WIDTH//2, HEIGHT//2 - 15), "ROKH WAF", font=font_hero_brand, fill=(255, 255, 255), anchor="mm")
        
        font_slogan = get_font(24, bold=True)
        draw.text((WIDTH//2, HEIGHT//2 + 45), "THE SOVEREIGN CYBER FORTRESS", font=font_slogan, fill=(6, 182, 212), anchor="mm")

        font_tech = get_font(18, bold=False)
        draw.text((WIDTH//2, 130), "NEXT-GEN RUST CORE ENGINE + AI NEURAL THREAT DEFENSE", font=font_tech, fill=(147, 197, 253), anchor="mm")

    # --------------------------------------------------------------------------
    # SCENE 4 (9.5s - 13.0s): KILLER PERFORMANCE METRICS
    # --------------------------------------------------------------------------
    elif sec < 13.0:
        local_t = (sec - 9.5) / 3.5
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(3, 7, 18))
        draw_cyber_grid(draw, f_idx, color=(12, 35, 65))

        # Title
        font_title = get_font(42, bold=True)
        draw.text((WIDTH//2, 110), "ENTERPRISE-GRADE BENCHMARK RESULTS", font=font_title, fill=(255, 255, 255), anchor="mm")

        # 3 Key Value Cards
        cards = [
            ("⚡ 0.12 ms", "SUB-MILLISECOND DPI", "Zero Latency Impact (Rust Core)", (0, 243, 255)),
            ("🛡️ 93.9%", "LIVE ATTACK BLOCK RATE", "Tested on 796 Live OWASP Packets", (16, 185, 129)),
            ("🟢 0.00%", "ZERO FALSE POSITIVES", "100% Verified Clean Traffic Pass", (59, 130, 246))
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
            # Card Container
            draw.rectangle([(cx, cy), (cx + card_width, cy + 280)], fill=(15, 23, 42), outline=col, width=2)
            # Glowing accent bar
            draw.rectangle([(cx, cy), (cx + card_width, cy + 8)], fill=col)
            # Stat Value
            draw.text((cx + card_width//2, cy + 80), val, font=font_stat_val, fill=col, anchor="mm")
            # Stat Title
            draw.text((cx + card_width//2, cy + 150), title, font=font_stat_title, fill=(255, 255, 255), anchor="mm")
            # Stat Desc
            draw.text((cx + card_width//2, cy + 200), desc, font=font_stat_sub, fill=(148, 163, 184), anchor="mm")

        # Bottom badge
        font_foot = get_font(18, bold=True)
        draw.text((WIDTH//2, 580), "OFFICIAL INDUSTRY GRADE: A (HIGH-ASSURANCE PROTECTION)", font=font_foot, fill=(245, 158, 11), anchor="mm")

    # --------------------------------------------------------------------------
    # SCENE 5 (13.0s - 16.0s): GRAND FINALE / CALL TO ACTION (CTA)
    # --------------------------------------------------------------------------
    else:
        local_t = (sec - 13.0) / 3.0
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=(2, 6, 23))
        draw_cyber_grid(draw, f_idx, color=(16, 45, 80))

        # Logo Icon
        shield_glow = math.sin(f_idx * 0.2) * 5
        draw.rectangle([(WIDTH//2 - 60, 110), (WIDTH//2 + 60, 190)], fill=(6, 182, 212), outline=(255, 255, 255), width=3)
        draw.text((WIDTH//2, 150), "ROKH", font=get_font(28, bold=True), fill=(255, 255, 255), anchor="mm")

        # Brand Title
        font_hero_final = get_font(68, bold=True)
        draw.text((WIDTH//2, 260), "ROKH WAF", font=font_hero_final, fill=(255, 255, 255), anchor="mm")

        font_sub_final = get_font(26, bold=True)
        draw.text((WIDTH//2, 330), "LOCK DOWN YOUR WEB APPLICATIONS TODAY", font=font_sub_final, fill=(6, 182, 212), anchor="mm")

        # CTA Button
        btn_w, btn_h = 360, 64
        btn_x1 = WIDTH//2 - btn_w//2
        btn_y1 = 410
        draw.rectangle([(btn_x1, btn_y1), (btn_x1 + btn_w, btn_y1 + btn_h)], fill=(16, 185, 129), outline=(255, 255, 255), width=2)
        font_btn = get_font(24, bold=True)
        draw.text((WIDTH//2, btn_y1 + btn_h//2), "DEPLOY IN UNDER 5 MINUTES", font=font_btn, fill=(255, 255, 255), anchor="mm")

        # Website URL
        font_url = get_font(22, bold=True)
        draw.text((WIDTH//2, 530), "HTTP://127.0.0.1:8080  |  ROKH-SECURITY.IO", font=font_url, fill=(147, 197, 253), anchor="mm")

    draw_vignette_and_bars(draw)
    return img

# ------------------------------------------------------------------------------
# 3. MAIN RENDER PIPELINE VIA FFMPEG
# ------------------------------------------------------------------------------
def main():
    print("=" * 70, flush=True)
    print(" [*] RENDERING BROADCAST COMMERCIAL MOTION GRAPHIC (MP4)", flush=True)
    print(f" Resolution : {WIDTH}x{HEIGHT} @ {FPS} FPS")
    print(f" Duration   : {DURATION_SEC} Seconds ({TOTAL_FRAMES} frames)")
    print(f" Output     : {OUTPUT_MP4}")
    print("=" * 70, flush=True)

    # 1. Synthesize Soundtrack
    generate_soundtrack(TEMP_AUDIO, DURATION_SEC)

    # 2. Launch FFmpeg Process for rawvideo stream
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
        "-crf", "18",                  # High visual quality
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        OUTPUT_MP4
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
            print(f"[+] Commercial Motion Graphic successfully rendered to:\n    {OUTPUT_MP4}", flush=True)
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
