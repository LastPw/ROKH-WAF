import os
import sys
import time
import json
import base64
import asyncio
import shutil
import subprocess
import urllib.request
import websockets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOWCASE_HTML = os.path.join(BASE_DIR, "showcase", "index.html")
FRAMES_BASE = os.path.join(BASE_DIR, "showcase", "render_frames", "staggered_anim")
os.makedirs(FRAMES_BASE, exist_ok=True)

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
AUDIO_SOURCE = os.path.join(BASE_DIR, "showcase", "media", "cyberpunk_theme.opus")

DESKTOP_DIR = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\imtah"), "OneDrive", "Desktop")
if not os.path.exists(DESKTOP_DIR):
    DESKTOP_DIR = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\imtah"), "Desktop")

OUTPUT_ANIMATED_MP4 = os.path.join(DESKTOP_DIR, "ROKH_WAF_Animated.mp4")

print("=" * 75)
print(" [*] RECORDING KINETIC MOTION GRAPHIC (BOXES & TEXTS ENTERING DYNAMICALLY)")
print(f" Target Output: {OUTPUT_ANIMATED_MP4}")
print("=" * 75)

# Launch dedicated headless Chrome on port 9333
TEMP_USER_DATA = r"C:\Users\imtah\AppData\Local\Temp\waf_chrome_staggered_rec"
chrome_proc = subprocess.Popen([
    CHROME_PATH,
    "--headless=new",
    "--remote-debugging-port=9333",
    "--remote-allow-origins=*",
    "--window-size=1280,720",
    "--force-device-scale-factor=1.5",
    "--hide-scrollbars",
    f"--user-data-dir={TEMP_USER_DATA}",
    "about:blank"
])

time.sleep(1.8)

async def capture_all_scenes():
    res = urllib.request.urlopen("http://127.0.0.1:9333/json/version")
    b_info = json.loads(res.read().decode())
    b_ws = b_info["webSocketDebuggerUrl"]
    
    html_url = "file:///" + SHOWCASE_HTML.replace("\\", "/") + "?render=live"
    
    async with websockets.connect(b_ws) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Target.createTarget", "params": {"url": html_url}}))
        target_res = json.loads(await ws.recv())
        target_id = target_res["result"]["targetId"]
        page_ws_url = f"ws://127.0.0.1:9333/devtools/page/{target_id}"

    scene_clips = []

    async with websockets.connect(page_ws_url, max_size=25*1024*1024) as page_ws:
        await page_ws.send(json.dumps({"id": 1, "method": "Page.enable"}))
        await page_ws.recv()
        await page_ws.send(json.dumps({"id": 2, "method": "Emulation.setDeviceMetricsOverride", "params": {
            "width": 1280, "height": 720, "deviceScaleFactor": 1.5, "mobile": False
        }}))
        await page_ws.recv()

        for sc in range(7):
            sc_dir = os.path.join(FRAMES_BASE, f"scene_{sc}")
            os.makedirs(sc_dir, exist_ok=True)
            print(f" [*] Animating Scene {sc + 1}/7 (Boxes & Text Entrance)...", end=" ", flush=True)

            # Trigger staggered entrance in HTML
            await page_ws.send(json.dumps({"id": 10 + sc, "method": "Runtime.evaluate", "params": {
                "expression": f"window.playSceneEntrance({sc})"
            }}))
            await page_ws.recv()

            # Capture 10 frames during 1.0s entrance (showing boxes rising into place)
            frame_paths = []
            for f_idx in range(10):
                await page_ws.send(json.dumps({"id": 1000 + sc * 100 + f_idx, "method": "Page.captureScreenshot", "params": {"format": "jpeg", "quality": 85}}))
                while True:
                    msg = json.loads(await page_ws.recv())
                    if msg.get("id") == 1000 + sc * 100 + f_idx:
                        b64 = msg["result"]["data"]
                        f_path = os.path.join(sc_dir, f"frame_{f_idx:02d}.jpg")
                        with open(f_path, "wb") as f_out:
                            f_out.write(base64.b64decode(b64))
                        frame_paths.append(f_path)
                        break
                await asyncio.sleep(0.09)

            # Build a 3.5s video clip for this scene:
            # 1.0s entrance animation (10 frames at 10fps upscaled to 30fps) + 2.5s resting state
            clip_path = os.path.join(FRAMES_BASE, f"clip_sc_{sc}.mp4")
            concat_txt = os.path.join(sc_dir, "concat.txt")
            with open(concat_txt, "w") as f_txt:
                for fp in frame_paths:
                    f_txt.write(f"file '{fp.replace(os.sep, '/')}'\n")
                    f_txt.write("duration 0.10\n")
                # Last frame holds for 2.5 seconds
                f_txt.write(f"file '{frame_paths[-1].replace(os.sep, '/')}'\n")
                f_txt.write("duration 2.5\n")
                f_txt.write(f"file '{frame_paths[-1].replace(os.sep, '/')}'\n")

            cmd_clip = [
                "ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", concat_txt,
                "-vf", "scale=1920:1080:flags=lanczos,format=yuv420p",
                "-c:v", "libx264", "-preset", "veryfast", "-crf", "14", "-r", "30",
                clip_path
            ]
            subprocess.run(cmd_clip, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            scene_clips.append(clip_path)
            print("[OK]")

    return scene_clips

try:
    clips = asyncio.run(capture_all_scenes())
finally:
    chrome_proc.terminate()

# Now concatenate all 7 scene clips with smooth crossfade and mix soundtrack
print("[*] Assembling full motion graphic video with cyberpunk soundtrack...")

inputs = []
for c in clips:
    inputs += ["-i", c]
inputs += ["-ss", "00:00:00", "-t", "25", "-i", AUDIO_SOURCE]

# Each clip is 3.5s. Crossfade duration 0.4s.
# Offsets:
# 0: 0-3.5
# 1: 3.1
# 2: 6.2
# 3: 9.3
# 4: 12.4
# 5: 15.5
# 6: 18.6
# Total duration = 18.6 + 3.5 = 22.1s
filter_complex = (
    "[0:v][1:v]xfade=transition=fade:duration=0.4:offset=3.1[v01];"
    "[v01][2:v]xfade=transition=fade:duration=0.4:offset=6.2[v02];"
    "[v02][3:v]xfade=transition=fade:duration=0.4:offset=9.3[v03];"
    "[v03][4:v]xfade=transition=fade:duration=0.4:offset=12.4[v04];"
    "[v04][5:v]xfade=transition=fade:duration=0.4:offset=15.5[v05];"
    "[v05][6:v]xfade=transition=fade:duration=0.4:offset=18.6,format=yuv420p[vfinal];"
    "[7:a]afade=t=in:st=0:d=1.0,afade=t=out:st=20.5:d=1.5[afinal]"
)

cmd_final = [
    "ffmpeg", "-y"
] + inputs + [
    "-filter_complex", filter_complex,
    "-map", "[vfinal]",
    "-map", "[afinal]",
    "-c:v", "libx264",
    "-preset", "veryfast",
    "-crf", "14",
    "-r", "30",
    "-c:a", "aac",
    "-b:a", "320k",
    "-movflags", "+faststart",
    OUTPUT_ANIMATED_MP4
]

res = subprocess.run(cmd_final, capture_output=True, text=True)
if res.returncode == 0:
    size_mb = os.path.getsize(OUTPUT_ANIMATED_MP4) / (1024 * 1024)
    print("=" * 75)
    print(f" [+] SUCCESS: KINETIC ANIMATED VIDEO RENDERED!")
    print(f"     File on Desktop : {OUTPUT_ANIMATED_MP4} ({size_mb:.2f} MB)")
    print(f"     Animation       : Boxes, cards & texts fly in dynamically on every scene")
    print(f"     Framing         : Perfect 1.0x scale (NO excessive zoom)")
    print(f"     Soundtrack      : 320kbps Cyberpunk Electro Stereo")
    print("=" * 75)
else:
    print(f"[!] Encoding error: {res.stderr}")
