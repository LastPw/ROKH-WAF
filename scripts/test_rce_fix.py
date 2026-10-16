import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re
import urllib.parse
from scripts.mega_attack_benchmark import load_payloads

rce_list = load_payloads("patt_rce.txt", 100)

# Current regexes
r_pipe = re.compile(r"(\|\s*(cat|whoami|id|ls|dir|wget|curl|nc|bash|sh|cmd\.exe|powershell)\b)", re.I)
r_semi = re.compile(r"(;\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell)\b)", re.I)
r_chain = re.compile(r"(&&|\|\|)\s*(cat|whoami|id|ls|dir|net\s+user|wget|curl|nc|bash|sh|cmd\.exe|powershell)\b", re.I)
r_sub = re.compile(r"(`[^`]+`|\$\([^)]+\))", re.I)

# Enhanced patterns:
# 1. Shell commands following newlines or start of input:
r_newline = re.compile(r"(\r|\n|%0a|%0d)\s*(cat|whoami|id|ls|dir|wget|curl|nc|bash|sh|powershell|ping)\b", re.I)
# 2. Binary invocations like /bin/sh, /bin/bash, /bin/cat, /usr/bin/id
r_bin = re.compile(r"(/bin/(cat|sh|bash|id)|/usr/bin/(id|whoami|uname))", re.I)
# 3. Direct RCE probes like `cat /`, `whoami`, `id;`
r_direct = re.compile(r"(^|\s)(cat\s+/|whoami\b|/bin/cat|net\s+user)", re.I)
# 4. Network utilities & PHP execution functions:
r_php_net = re.compile(r"(\b(ping|nslookup|traceroute|phpinfo|passthru|shell_exec)\b|\b(system|exec)\s*\()", re.I)

blocked = 0
missed = []
for p in rce_list:
    norm = urllib.parse.unquote(p)
    if (r_pipe.search(p) or r_semi.search(p) or r_chain.search(p) or r_sub.search(p) or
        r_pipe.search(norm) or r_semi.search(norm) or r_chain.search(norm) or r_sub.search(norm) or
        r_newline.search(p) or r_bin.search(p) or r_bin.search(norm) or r_direct.search(norm) or
        r_php_net.search(p) or r_php_net.search(norm)):
        blocked += 1
    else:
        missed.append(p)

print(f"RCE Detection Rate with enhancements: {blocked}/{len(rce_list)} ({blocked/len(rce_list)*100:.1f}%)")
print(f"Missed: {len(missed)}")
for m in missed[:15]:
    print("  ->", repr(m))
