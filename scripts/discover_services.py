#!/usr/bin/env python3
# ==============================================================================
# ROKH WAF - Active Web Server & Website Discovery Engine
# ==============================================================================

import os
import re
import sys
import json
import socket
import subprocess
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

COMMON_WEB_PORTS = [80, 443, 3000, 3001, 4000, 4200, 5000, 5001, 5173, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090]

def get_process_name_by_pid(pid):
    if not pid or pid in ["0", "-", ""]:
        return "System / Unknown"
    if sys.platform == "win32":
        try:
            cmd = f'tasklist /FI "PID eq {pid}" /FO CSV /NH'
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            if out and '"' in out:
                return out.split('"')[1]
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(f'ps -p {pid} -o comm=', shell=True, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore').strip()
            if out:
                return out
        except Exception:
            pass
    return f"PID {pid}"

def get_listening_tcp_ports():
    ports_map = {} # port -> pid
    if sys.platform == "win32":
        try:
            out = subprocess.check_output("netstat -ano -p tcp", shell=True, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "TCP" and parts[3] == "LISTENING":
                    addr = parts[1]
                    pid = parts[4] if len(parts) >= 5 else ""
                    if ":" in addr:
                        try:
                            port = int(addr.split(":")[-1])
                            # Exclude ephemeral high ports unless in COMMON_WEB_PORTS
                            if port < 10000 or port in COMMON_WEB_PORTS:
                                if port not in ports_map or pid != "0":
                                    ports_map[port] = pid
                        except ValueError:
                            pass
        except Exception:
            pass
    else:
        # Linux / macOS
        try:
            out = subprocess.check_output("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null", shell=True).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                if "LISTEN" in line:
                    parts = line.strip().split()
                    for p in parts:
                        if ":" in p:
                            try:
                                port = int(p.split(":")[-1])
                                if port < 10000 or port in COMMON_WEB_PORTS:
                                    ports_map[port] = ""
                            except ValueError:
                                pass
        except Exception:
            pass

    # Ensure all common web ports are tested even if netstat lacked permission
    for cp in COMMON_WEB_PORTS:
        if cp not in ports_map:
            ports_map[cp] = ""

    return ports_map

def probe_http_service(port, pid):
    # Ignore our own WAF proxy port (8080) when finding backend targets
    # (Though we can still report it if requested)
    schemes = ["http"]
    if port in [443, 8443]:
        schemes = ["https", "http"]

    for scheme in schemes:
        url = f"{scheme}://127.0.0.1:{port}"
        try:
            req = urllib.request.Request(
                f"{url}/",
                headers={"User-Agent": "RokhWAF-AutoDiscovery/1.0", "Accept": "*/*"}
            )
            with urllib.request.urlopen(req, timeout=0.45) as resp:
                headers = dict(resp.headers)
                server = headers.get("Server", "").strip()
                content_type = headers.get("Content-Type", "")
                sample = resp.read(1024).decode("utf-8", errors="ignore")
                
                title_match = re.search(r"<title>(.*?)</title>", sample, re.IGNORECASE)
                title = title_match.group(1).strip() if title_match else ""

                pname = get_process_name_by_pid(pid)
                service_type = classify_web_service(server, pname, port, title)

                return {
                    "url": url,
                    "port": port,
                    "pid": pid,
                    "process_name": pname,
                    "server_banner": server if server else "HTTP Web Service",
                    "status_code": resp.status,
                    "title": title,
                    "service_type": service_type,
                    "reachable": True
                }
        except urllib.error.HTTPError as e:
            headers = dict(e.headers) if e.headers else {}
            server = headers.get("Server", "").strip()
            pname = get_process_name_by_pid(pid)
            service_type = classify_web_service(server, pname, port, "")

            return {
                "url": url,
                "port": port,
                "pid": pid,
                "process_name": pname,
                "server_banner": server if server else "HTTP Web Service",
                "status_code": e.code,
                "title": "",
                "service_type": service_type,
                "reachable": True
            }
        except Exception:
            pass

    return None

def classify_web_service(server, process, port, title):
    srv = server.lower()
    prc = process.lower()
    tit = title.lower()

    if "nginx" in srv or "nginx" in prc:
        return "Nginx Reverse Proxy / Web Server"
    if "apache" in srv or "httpd" in prc:
        return "Apache HTTP Server"
    if "iis" in srv or "w3wp" in prc:
        return "Microsoft IIS Web Server"
    if "caddy" in srv or "caddy" in prc:
        return "Caddy Web Server"
    if "litespeed" in srv:
        return "LiteSpeed Web Server"
    if "node" in prc or "express" in srv or "next" in tit or port in [3000, 5173]:
        return "Node.js / React / Next.js Web Application"
    if "uvicorn" in srv or "gunicorn" in srv or "python" in prc or "fastapi" in tit:
        return "Python Web Service (FastAPI / Uvicorn)"
    if "werkzeug" in srv or "flask" in tit or "django" in tit:
        return "Python Web Application (Django / Flask)"
    if "tomcat" in srv or "java" in prc:
        return "Java / Tomcat Web Service"
    if "docker" in prc:
        return "Docker Containerized Web Service"

    if port == 80:
        return "Standard HTTP Web Server"
    if port == 443:
        return "Standard HTTPS Web Server"

    return "HTTP Web Application"

def discover_installed_web_servers():
    installed = []
    # 1. Check Nginx
    nginx_paths = ["C:\\nginx\\nginx.exe", "/usr/sbin/nginx", "/usr/local/bin/nginx"]
    for p in nginx_paths:
        if os.path.exists(p):
            installed.append({"name": "Nginx", "path": p, "config": "nginx.conf"})
            break

    # 2. Check Apache
    apache_paths = ["C:\\Apache24\\bin\\httpd.exe", "/usr/sbin/apache2", "/usr/sbin/httpd"]
    for p in apache_paths:
        if os.path.exists(p):
            installed.append({"name": "Apache", "path": p, "config": "httpd.conf"})
            break

    # 3. Check IIS on Windows
    if sys.platform == "win32":
        iis_path = "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
        if os.path.exists(iis_path) or os.path.exists("C:\\inetpub"):
            installed.append({"name": "Microsoft IIS", "path": "C:\\Windows\\System32\\inetsrv", "config": "applicationHost.config"})

    return installed

def scan_all_web_services(exclude_ports=[8080]):
    ports_map = get_listening_tcp_ports()
    results = []

    # Parallel HTTP scan across discovered ports
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {}
        for port, pid in ports_map.items():
            if port in exclude_ports:
                continue
            futures[executor.submit(probe_http_service, port, pid)] = port

        for f in as_completed(futures):
            res = f.result()
            if res:
                results.append(res)

    # Sort results by port number
    results.sort(key=lambda s: s["port"])
    return results

if __name__ == "__main__":
    print("======================================================================")
    print(" [ROKH WAF] Web Services & Active Sites Discovery")
    print("======================================================================")
    print(" [*] Scanning active web servers (Nginx, Apache, IIS, Node, Python)...")
    services = scan_all_web_services(exclude_ports=[8080])

    if not services:
        print(" [-] No active HTTP web services currently detected on localhost.")
    else:
        print(f" [+] Found {len(services)} active web service(s):\n")
        for idx, s in enumerate(services, 1):
            print(f" [{idx}] {s['service_type']}")
            print(f"     |-- URL     : {s['url']}")
            print(f"     |-- Port    : {s['port']}")
            print(f"     |-- Process : {s['process_name']} (PID: {s['pid']})")
            print(f"     |-- Server  : {s['server_banner']}")
            if s['title']:
                print(f"     |-- Title   : {s['title']}")
            print(f"     \\-- Status  : HTTP {s['status_code']}")
            print("")
