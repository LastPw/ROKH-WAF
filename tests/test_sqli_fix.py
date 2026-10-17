import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re
import urllib.parse
try:
    from benchmarks.mega_attack_benchmark import load_payloads
except ImportError:
    from scripts.mega_attack_benchmark import load_payloads

sqli_list = load_payloads("patt_sqli_union.txt", 60) + load_payloads("sec_sqli.txt", 40)

# Current regexes
r1 = re.compile(r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\binsert\b.*\binto\b|\bdrop\b.*\btable\b|\bupdate\b.*\bset\b|\balter\b.*\btable\b|\border\s+by\b.*\b(sleep|benchmark))", re.I)
r3 = re.compile(r"(--|\#|;\s*waitfor\s+delay|\b(sleep|benchmark|pg_sleep)\s*\(|\b(exec|execute)\s+(xp_|sp_|immediate)|\bdeclare\s+@)", re.I)

# Improved r2: catches all boolean SQLi (OR 1=1, OR 'a'='a, OR a=a, OR 2>1, with or without leading quotes or parens)
r2_new = re.compile(r"(\b(or|and)\b\s*[\(\'\"\s]*([0-9a-z_]+|'[^']*'|\"[^\"]*\")\s*(=|>|<|!=|like)\s*[\(\'\"\s]*([0-9a-z_]+|'[^']*'|\"[^\"]*\")|'\s*(or|and)\s*')", re.I)

# Check functions like char, hex, elt, ord, load_file in SQLi
r5 = re.compile(r"\b(char|hex|ord|elt|concat|version|user|database|schema|load_file)\s*\(", re.I)

blocked = 0
missed = []
for p in sqli_list:
    norm = urllib.parse.unquote(p)
    if r1.search(norm) or r2_new.search(norm) or r3.search(norm) or r5.search(norm):
        blocked += 1
    else:
        missed.append(p)

print(f"SQLi Detection Rate with r2_new & r5: {blocked}/{len(sqli_list)} ({blocked/len(sqli_list)*100:.1f}%)")
print(f"Missed: {len(missed)}")
for m in missed:
    print("  ->", repr(m))
