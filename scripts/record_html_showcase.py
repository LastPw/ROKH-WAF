import os
import sys
import shutil
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOWCASE_HTML = os.path.join(BASE_DIR, "showcase", "index.html")
FRAMES_DIR = os.path.join(BASE_DIR, "showcase", "render_frames")
os.makedirs(FRAMES_DIR, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
AUDIO_SOURCE = os.path.join(BASE_DIR, "showcase", "media", "cyberpunk_theme.opus")

DESKTOP_DIR = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\imtah"), "OneDrive", "Desktop")
if not os.path.exists(DESKTOP_DIR):
    DESKTOP_DIR = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\imtah"), "Desktop")

OUTPUT_DESKTOP_MP4 = os.path.join(DESKTOP_DIR, "ROKH_WAF.mp4")
OUTPUT_PROJECT_MP4 = os.path.join(BASE_DIR, "waf_commercial_ad.mp4")

print("Rendering high quality video...")
scene_images = []
for sc in range(7):
    out_img = os.path.join(FRAMES_DIR, f"master_sc{sc}.png")
    html_url = "file:///" + SHOWCASE_HTML.replace("\\", "/") + f"?scene={sc}"
    cmd = [
        CHROME_PATH,
        "--headless=new",
        f"--screenshot={out_img}",
        "--window-size=1280,720",
        "--force-device-scale-factor=2",
        "--hide-scrollbars",
        html_url
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(out_img):
        scene_images.append(out_img)

inputs = []
for img in scene_images:
    inputs += ["-loop", "1", "-t", "4", "-i", img]
inputs += ["-ss", "00:00:00", "-t", "25", "-i", AUDIO_SOURCE]

filter_complex = (
    "[0:v][1:v]xfade=transition=fade:duration=0.5:offset=3.5[v01];"
    "[v01][2:v]xfade=transition=fade:duration=0.5:offset=7.0[v02];"
    "[v02][3:v]xfade=transition=fade:duration=0.5:offset=10.5[v03];"
    "[v03][4:v]xfade=transition=fade:duration=0.5:offset=14.0[v04];"
    "[v04][5:v]xfade=transition=fade:duration=0.5:offset=17.5[v05];"
    "[v05][6:v]xfade=transition=fade:duration=0.5:offset=21.0,"
    "scale=1920:1080:flags=lanczos,format=yuv420p[vfinal];"
    "[7:a]afade=t=in:st=0:d=1.0,afade=t=out:st=23:d=2.0[afinal]"
)

ffmpeg_cmd = [
    "ffmpeg", "-y"
] + inputs + [
    "-filter_complex", filter_complex,
    "-map", "[vfinal]",
    "-map", "[afinal]",
    "-c:v", "libx264",
    "-preset", "veryfast",
    "-crf", "14",
    "-r", "60",
    "-c:a", "aac",
    "-b:a", "320k",
    "-movflags", "+faststart",
    OUTPUT_DESKTOP_MP4
]

res = subprocess.run(ffmpeg_cmd, capture_output=True, text=True)
if res.returncode == 0:
    try:
        shutil.copyfile(OUTPUT_DESKTOP_MP4, OUTPUT_PROJECT_MP4)
    except Exception:
        pass
    print("DONE_SUCCESS:", OUTPUT_DESKTOP_MP4, os.path.getsize(OUTPUT_DESKTOP_MP4))
else:
    print("FFMPEG_ERROR:", res.stderr)
