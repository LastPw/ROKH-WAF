import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re
import urllib.parse
try:
    from benchmarks.mega_attack_benchmark import load_payloads
except ImportError:
    from scripts.mega_attack_benchmark import load_payloads

rce_list = load_payloads("patt_rce.txt", 100)

# Current regexes
r_pipe = re.compile(r"(\|\s*(cat|whoami|id|ls|dir|wget|curl|nc|bash|sh|cmd\.exe|powershell)\b)", re.I)
r_semi = re.compile(r"(;\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell)\b)", re.I)
r_chain = re.compile(r"(&&|\|\|)\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell)\b", re.I)
r_sub = re.compile(r"(`[^`]+`|\$\([^)]+\))", re.I)

# Enhanced patterns matching Rust rules:
r_cmd = re.compile(r"(^|[\s;&|`\n\r])(cat\s+[/.]|whoami\b|id\s*([;&|`\n\r]|$)|/bin/(cat|sh|bash|id)|/usr/bin/(id|whoami|uname)|net\s+user\b|dir\s+[a-zA-Z]:[/\\]|curl\s+https?://|wget\s+https?://)", re.I)
r_shellshock = re.compile(r"\(\s*\)\s*\{\s*:;\s*\};", re.I)
r_delim = re.compile(r"([;&|`\n\r]|%0a|%0d)\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell|ping)\b", re.I)
r_php = re.compile(r"(\b(ping|nslookup|traceroute|phpinfo|passthru|shell_exec)\b|\b(system|exec|popen|proc_open)\s*\(|\{\$\{|/bin/(cat|sh|bash|id)|/usr/bin/(id|whoami|uname))", re.I)
r_webshell = re.compile(r"(<\?php|<\?=|\$_get\[|\$_post\[|\$_request\[|\b(include|require)(_once)?\s*\(|\beval\s*\(|base64_decode\s*\(|echo\s+['\x22]<|>\s*rfi\.php)", re.I)
r_evasion = re.compile(r"(\$(IFS|\{IFS\}|\{cat,|\{whoami,)|/dev/(tcp|udp)/\d+|\|\s*(base64\s+-d|sh|bash)\b|\{\$\{[^}]+\}\})", re.I)

blocked = 0
missed = []
for p in rce_list:
    norm = urllib.parse.unquote(p)
    if (r_cmd.search(p) or r_cmd.search(norm) or
        r_shellshock.search(p) or r_shellshock.search(norm) or
        r_delim.search(p) or r_delim.search(norm) or
        r_sub.search(p) or r_sub.search(norm) or
        r_php.search(p) or r_php.search(norm) or
        r_webshell.search(p) or r_webshell.search(norm) or
        r_evasion.search(p) or r_evasion.search(norm)):
        blocked += 1
    else:
        missed.append(p)

print(f"RCE Detection Rate with enhancements: {blocked}/{len(rce_list)} ({blocked/len(rce_list)*100:.1f}%)")
print(f"Missed: {len(missed)}")
for m in missed[:15]:
    print("  ->", repr(m))
