import os
import sys
import math
import subprocess
from PIL import Image

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRAMES_DIR = os.path.join(BASE_DIR, "showcase", "render_frames")
AUDIO_SOURCE = os.path.join(BASE_DIR, "showcase", "media", "cyberpunk_theme.opus")

DESKTOP_DIR = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\imtah"), "OneDrive", "Desktop")
if not os.path.exists(DESKTOP_DIR):
    DESKTOP_DIR = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\imtah"), "Desktop")

TEMP_VIDEO = os.path.join(FRAMES_DIR, "temp_video_60fps.mp4")
OUTPUT_ANIMATED_MP4 = os.path.join(DESKTOP_DIR, "ROKH_WAF_Animated.mp4")

print("=" * 75, flush=True)
print(" [*] RENDERING ULTRA-SMOOTH 60 FPS KINETIC MOTION GRAPHIC (BOXES & TEXT FLY-IN)", flush=True)
print(f" Target: {OUTPUT_ANIMATED_MP4}", flush=True)
print("=" * 75, flush=True)

# 1. Cubic-bezier ease-out function
def ease_out_quint(x):
    return 1.0 - math.pow(1.0 - x, 5)

FPS = 60
SCENE_DURATION_SEC = 3.5
FRAMES_PER_SCENE = int(SCENE_DURATION_SEC * FPS) # 210 frames per scene
ENTRANCE_DURATION_SEC = 0.8
ENTRANCE_FRAMES = int(ENTRANCE_DURATION_SEC * FPS) # 48 frames of pure motion

# Prepare FFmpeg pipe for 60 FPS video (DEVNULL on stderr to prevent OS pipe deadlock)
ffmpeg_cmd = [
    "ffmpeg", "-y",
    "-f", "rawvideo",
    "-vcodec", "rawvideo",
    "-s", "1920x1080",
    "-pix_fmt", "rgba",
    "-r", "60",
    "-i", "-",
    "-c:v", "libx264",
    "-preset", "ultrafast",
    "-crf", "14",
    "-pix_fmt", "yuv420p",
    "-r", "60",
    TEMP_VIDEO
]

proc = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

bg_canvas = Image.new("RGBA", (1920, 1080), (7, 9, 14, 255))

for sc in range(7):
    src_img_path = os.path.join(FRAMES_DIR, f"master_sc{sc}.png")
    if not os.path.exists(src_img_path):
        print(f"[!] Missing frame: {src_img_path}", flush=True)
        continue
    
    full_im = Image.open(src_img_path).convert("RGBA")
    full_im = full_im.resize((1920, 1080), Image.Resampling.LANCZOS)
    
    # Split into Top Header region (y: 0 to 480) and Bottom Boxes region (y: 480 to 1080)
    hdr_img = full_im.crop((0, 0, 1920, 480))
    boxes_img = full_im.crop((0, 480, 1920, 1080))
    
    print(f" [*] Rendering Scene {sc + 1}/7 at 60 FPS (Fluid Box Entrance)...", flush=True)
    
    for f in range(FRAMES_PER_SCENE):
        frame = bg_canvas.copy()
        
        if f < ENTRANCE_FRAMES:
            # 60 FPS Kinetic Entrance Animation
            prog = f / float(ENTRANCE_FRAMES)
            e = ease_out_quint(prog)
            
            # Header slides down from -50px with fade-in
            hdr_offset_y = int(-50 * (1.0 - e))
            
            # Boxes slide up from +140px with punchy springy ease-out
            boxes_offset_y = int(140 * (1.0 - e))
            
            # Composite Header
            frame.paste(hdr_img, (0, hdr_offset_y), hdr_img)
            # Composite Boxes
            frame.paste(boxes_img, (0, 480 + boxes_offset_y), boxes_img)
            
            # Fade-in overlay during initial 10 frames
            if f < 10:
                fade_cover = Image.new("RGBA", (1920, 1080), (7, 9, 14, int(255 * (1.0 - f / 10.0))))
                frame = Image.alpha_composite(frame, fade_cover)
        else:
            # Settle at 100% resting position
            frame.paste(hdr_img, (0, 0))
            frame.paste(boxes_img, (0, 480))
            
            # Smooth crossfade out during the last 15 frames (0.25s) into black/next scene
            rem_frames = FRAMES_PER_SCENE - f
            if rem_frames < 15 and sc < 6:
                fade_alpha = int(255 * (1.0 - rem_frames / 15.0) * 0.45)
                dim = Image.new("RGBA", (1920, 1080), (7, 9, 14, fade_alpha))
                frame = Image.alpha_composite(frame, dim)

        proc.stdin.write(frame.tobytes())

proc.stdin.close()
proc.wait()

print("[*] Video frames completed. Muxing 320k Studio Cyberpunk Soundtrack...", flush=True)

# Mux audio
total_dur = 7 * SCENE_DURATION_SEC - 0.5
cmd_mux = [
    "ffmpeg", "-y",
    "-i", TEMP_VIDEO,
    "-ss", "00:00:00",
    "-t", str(total_dur),
    "-i", AUDIO_SOURCE,
    "-filter_complex", f"[1:a]afade=t=in:st=0:d=1.0,afade=t=out:st={total_dur - 2.0}:d=2.0[aout]",
    "-map", "0:v",
    "-map", "[aout]",
    "-c:v", "copy",
    "-c:a", "aac",
    "-b:a", "320k",
    "-movflags", "+faststart",
    OUTPUT_ANIMATED_MP4
]

res = subprocess.run(cmd_mux, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if res.returncode == 0:
    size_mb = os.path.getsize(OUTPUT_ANIMATED_MP4) / (1024 * 1024)
    print("=" * 75, flush=True)
    print(f" [+] SUCCESS: TRUE 60 FPS ANIMATED VIDEO RENDERED!", flush=True)
    print(f"     File on Desktop : {OUTPUT_ANIMATED_MP4} ({size_mb:.2f} MB)", flush=True)
    print(f"     Framerate       : 60.00 FPS (Zero Lag, Silky Smooth)", flush=True)
    print(f"     Animation       : Boxes fly up from below, Header slides down into place", flush=True)
    print(f"     Framing         : Perfect 1.0x Full HD (No excessive zoom)", flush=True)
    print(f"     Soundtrack      : 320kbps Cyberpunk Electro Mastered", flush=True)
    print("=" * 75, flush=True)
else:
    print("[!] Muxing failed", flush=True)
