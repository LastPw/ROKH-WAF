import math
import json
import time
import os
from typing import Dict, Any, List

class AegisNeuralBrain:
    """
    High-Performance Zero-Dependency Machine Learning Threat Classifier for AegisGuard WAF.
    Combines:
    1. Character Tri-gram (3-gram) frequency vectorization
    2. Shannon Information Entropy (obfuscation & shellcode detection)
    3. Syntactic punctuation & symbol density analysis
    4. Fast vectorized Logistic Decision function (< 0.2ms inference)
    """

    SUSPICIOUS_TOKENS = [
        # Classic OWASP Top 10
        "union", "select", "from", "insert", "drop", "delete", "where",
        "script", "alert", "eval", "onload", "onerror", "javascript",
        "../", "..\\", "etc/", "passwd", "windows", "win.ini", "cmd.exe",
        "whoami", "powershell", "bash", "cat ", "curl", "wget", "nc ", "|", ";",
        "--", "/*", "*/", "waitfor", "sleep", "<svg", "<iframe>", "document.cookie",
        "php://", "base64", "$ifs",
        # Modern AI & Prompt Injection Vectors (OWASP LLM Top 10)
        "ignore previous", "system prompt", "system override", "jailbreak",
        "override rules", "dan mode", "do anything now", "---begin instruction",
        "assistant:", "disregard prior", "leak api key", "output system prompt",
        # Prototype Pollution & Deserialization
        "__proto__", "constructor.prototype", "object.prototype", "child_process",
        # Cloud Metadata & SSRF Exploits
        "169.254.169.254", "metadata.google", "latest/meta-data", "instance/service-accounts",
        # Modern Zero-Days (Log4Shell, Spring4Shell, SSTI)
        "${jndi:", "jndi:ldap", "jndi:rmi", "jndi:dns", "lipsum.__globals__",
        "__class__.__mro__", "class.module.classloader"
    ]

    DANGEROUS_SYMBOLS = set("'\"<>;|`()${}[]!*^~\\")
    URL_SYMBOLS = set("&=-_/?.:@%")

    def __init__(self, weights_path: str = None):
        self.vocab: Dict[str, int] = {}
        self.weights: List[float] = []
        self.bias: float = 0.0
        self.threshold: float = 0.65
        self.weights_path = weights_path or os.path.join(os.path.dirname(__file__), "waf_brain_weights.json")

        if os.path.exists(self.weights_path):
            self.load_model(self.weights_path)

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon Entropy of payload to detect encoded/obfuscated attacks"""
        if not text:
            return 0.0
        freqs = {}
        for ch in text:
            freqs[ch] = freqs.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freqs.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def extract_features(self, payload: str) -> List[float]:
        """Extracts fixed-length feature vector combining N-grams and statistical heuristics"""
        lower_p = payload.lower()
        length = len(payload)
        safe_len = max(length, 1)

        # 1. Statistical heuristics
        entropy = self.calculate_entropy(payload)
        danger_count = sum(1 for ch in payload if ch in self.DANGEROUS_SYMBOLS)
        danger_ratio = danger_count / safe_len
        digit_count = sum(1 for ch in payload if ch.isdigit())
        digit_ratio = digit_count / safe_len
        upper_count = sum(1 for ch in payload if ch.isupper())
        upper_ratio = upper_count / safe_len

        # Suspicious keyword matches
        keyword_hits = sum(1 for kw in self.SUSPICIOUS_TOKENS if kw in lower_p)

        heuristics = [
            entropy / 8.0,         # Normalized entropy (0-1)
            min(danger_ratio * 4.0, 1.0),
            min(digit_ratio * 2.0, 1.0),
            upper_ratio,
            min(keyword_hits / 3.0, 1.0),
            min(length / 500.0, 1.0)
        ]

        # 2. Tri-gram feature mapping
        ngram_feats = [0.0] * len(self.vocab)
        if len(lower_p) >= 3 and self.vocab:
            total_ngrams = len(lower_p) - 2
            for i in range(total_ngrams):
                tri = lower_p[i:i+3]
                if tri in self.vocab:
                    idx = self.vocab[tri]
                    ngram_feats[idx] += 1.0 / total_ngrams

        return heuristics + ngram_feats

    def predict(self, payload: str) -> Dict[str, Any]:
        """Predicts whether an incoming payload is malicious with confidence and intent"""
        t0 = time.perf_counter()

        if not payload or not payload.strip():
            return {
                "payload": payload,
                "is_malicious": False,
                "threat_probability": 0.01,
                "anomaly_score": 0.1,
                "entropy": 0.0,
                "verdict": "BENIGN",
                "detected_intent": "NORMAL_QUERY",
                "inference_time_ms": round((time.perf_counter() - t0) * 1000, 3)
            }

        features = self.extract_features(payload)

        # Dot product: z = W · X + b
        if len(self.weights) == len(features):
            z = sum(w * x for w, x in zip(self.weights, features)) + self.bias
        else:
            # Fallback heuristic calculation if weights not loaded
            h = features[:6]
            z = (h[0] * 1.5 + h[1] * 2.5 + h[4] * 3.5) - 1.8

        # Numerically stable Sigmoid
        if z >= 0:
            prob = 1.0 / (1.0 + math.exp(-z))
        else:
            exp_z = math.exp(z)
            prob = exp_z / (1.0 + exp_z)

        prob = round(prob, 4)
        is_malicious = prob >= self.threshold
        lower_p = payload.lower()
        entropy = self.calculate_entropy(payload)

        # High-severity zero-day & exploit intent classification
        if any(k in lower_p for k in ["ignore previous", "system prompt", "system override", "jailbreak", "override rules", "dan mode", "do anything now"]):
            intent = "PROMPT_INJECTION"
            prob = max(prob, 0.88)
            is_malicious = True
        elif any(k in lower_p for k in ["__proto__", "constructor.prototype", "object.prototype", "child_process"]):
            intent = "PROTOTYPE_POLLUTION"
            prob = max(prob, 0.92)
            is_malicious = True
        elif any(k in lower_p for k in ["169.254.169.254", "metadata.google", "latest/meta-data"]):
            intent = "SSRF_CLOUD_METADATA"
            prob = max(prob, 0.95)
            is_malicious = True
        elif any(k in lower_p for k in ["${jndi:", "jndi:ldap", "lipsum.__globals__", "class.module"]):
            intent = "LOG4SHELL_SSTI"
            prob = max(prob, 0.98)
            is_malicious = True
        elif any(k in lower_p for k in ["union", "select", "insert", "--", "/*", "waitfor", "'--"]) and ("'" in payload or '"' in payload or ";" in payload or "=" in payload):
            intent = "SQL_INJECTION"
            prob = max(prob, 0.85)
            is_malicious = True
        elif any(k in lower_p for k in ["<script", "script>", "alert(", "onload=", "onerror=", "javascript:", "<svg", "<iframe"]):
            intent = "XSS_ATTACK"
            prob = max(prob, 0.90)
            is_malicious = True
        elif any(k in lower_p for k in ["../", "..\\", "/etc/", "etc/passwd", "win.ini", ".env", "php://filter", "boot.ini", ".htaccess", "global.asa", "web.config", "php.ini", "/proc/"]):
            intent = "PATH_TRAVERSAL"
            prob = max(prob, 0.90)
            is_malicious = True
        elif any(k in lower_p for k in ["whoami", "powershell", "bash", " cat ", "/bin/cat", ";cat", "|cat", "`", "/dev/tcp"]):
            intent = "COMMAND_INJECTION"
            prob = max(prob, 0.88)
            is_malicious = True
        elif entropy > 4.8 and len(payload) > 30 and any(ch in payload for ch in self.DANGEROUS_SYMBOLS):
            intent = "OBFUSCATED_PAYLOAD"
            prob = max(prob, 0.82)
            is_malicious = True
        elif is_malicious:
            intent = "SUSPICIOUS_HEURISTIC"
        else:
            intent = "NORMAL_QUERY"

        prob = round(prob, 4)
        anomaly_score = round(prob * 10.0, 2)
        verdict = "CRITICAL_THREAT" if prob >= 0.85 else ("SUSPICIOUS" if is_malicious else "BENIGN")

        dt_ms = round((time.perf_counter() - t0) * 1000, 3)

        return {
            "payload": payload[:120] + ("..." if len(payload) > 120 else ""),
            "is_malicious": is_malicious,
            "threat_probability": prob,
            "anomaly_score": anomaly_score,
            "entropy": entropy,
            "verdict": verdict,
            "detected_intent": intent,
            "inference_time_ms": dt_ms
        }

    def save_model(self, path: str):
        data = {
            "vocab": self.vocab,
            "weights": self.weights,
            "bias": self.bias,
            "threshold": self.threshold
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_model(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.vocab = data.get("vocab", {})
            self.weights = data.get("weights", [])
            self.bias = data.get("bias", 0.0)
            self.threshold = data.get("threshold", 0.55)
