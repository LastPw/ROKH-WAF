import os
import sys
import math
import time
import json
import random
import urllib.request
from collections import Counter
from typing import List, Tuple, Dict, Set

import numpy as np
import pandas as pd

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

DATA_CACHE_DIR = os.path.join(BASE_DIR, "data_cache")
os.makedirs(DATA_CACHE_DIR, exist_ok=True)
WEIGHTS_PATH = os.path.join(BASE_DIR, "ai_engine", "waf_brain_weights.json")

def download_file(url: str, dest_path: str) -> bool:
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 100:
        return True
    try:
        print(f" [*] Fetching: {os.path.basename(dest_path)}...")
        req = urllib.request.Request(url, headers={"User-Agent": "AegisTrainer/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(dest_path, "wb") as f:
            f.write(resp.read())
        print(f" [+] Cached: {dest_path} ({os.path.getsize(dest_path) / 1024:.1f} KB)")
        return True
    except Exception as e:
        print(f" [!] Warning: Could not download {url}: {e}")
        return False

# ==============================================================================
# 1. COMPREHENSIVE MULTI-SOURCE DATASET INGESTION
# ==============================================================================

def load_all_datasets() -> Tuple[List[str], List[int]]:
    all_payloads: List[str] = []
    all_labels: List[int] = []

    # 1. Morzeux/HttpParamsDataset
    print("\n[1/5] Ingesting Morzeux/HttpParamsDataset...")
    morzeux_train = os.path.join(DATA_CACHE_DIR, "morzeux_train.csv")
    morzeux_test = os.path.join(DATA_CACHE_DIR, "morzeux_test.csv")
    download_file("https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/master/payload_train.csv", morzeux_train)
    download_file("https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/master/payload_test.csv", morzeux_test)

    for p_path in [morzeux_train, morzeux_test]:
        if os.path.exists(p_path):
            try:
                df = pd.read_csv(p_path, on_bad_lines='skip')
                for _, row in df.iterrows():
                    p = str(row.get('payload', '')).strip()
                    if len(p) < 2:
                        continue
                    lbl = str(row.get('label', '')).lower()
                    atype = str(row.get('attack_type', '')).lower()
                    is_attack = 0 if (lbl == 'norm' or atype == 'norm') else 1
                    all_payloads.append(p)
                    all_labels.append(is_attack)
                print(f" [+] {os.path.basename(p_path)}: {len(df):,} samples")
            except Exception as e:
                print(f" [!] Error reading Morzeux: {e}")

    # 2. notesbymuneeb/ai-waf-dataset (Hugging Face)
    print("\n[2/5] Ingesting notesbymuneeb/ai-waf-dataset (Hugging Face)...")
    try:
        from huggingface_hub import hf_hub_download
        hf_path = hf_hub_download(
            repo_id="notesbymuneeb/ai-waf-dataset",
            filename="data/train-00000-of-00001.parquet",
            repo_type="dataset"
        )
        hf_df = pd.read_parquet(hf_path)
        for _, row in hf_df.iterrows():
            text = str(row.get('text', '')).strip()
            if len(text) < 2:
                continue
            is_attack = 0 if str(row.get('label', '')).lower() == 'benign' else 1
            all_payloads.append(text)
            all_labels.append(is_attack)
        print(f" [+] HuggingFace AI-WAF: {len(hf_df):,} samples")
    except Exception as e:
        print(f" [!] Error loading HF dataset: {e}")

    # 3. msudol/Web-Application-Attack-Datasets (ECML PKDD)
    print("\n[3/5] Ingesting msudol/Web-Application-Attack-Datasets (ECML)...")
    ecml_file = os.path.join(DATA_CACHE_DIR, "ecml_final.csv")
    download_file("https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/CSVData/ecml_final.csv", ecml_file)
    if os.path.exists(ecml_file):
        try:
            df = pd.read_csv(ecml_file, on_bad_lines='skip')
            for _, row in df.iterrows():
                query = str(row.get('GET-Query', '')).strip()
                post = str(row.get('POST-Data', '')).strip()
                uri = str(row.get('URI', '')).strip()
                text = query if query and query != 'nan' else (post if post and post != 'nan' else uri)
                if not text or text == 'nan' or len(text) < 2:
                    continue
                is_attack = 1 if str(row.get('Class', '')).lower() == 'anomalous' else 0
                all_payloads.append(text)
                all_labels.append(is_attack)
            print(f" [+] msudol ECML: {len(df):,} samples")
        except Exception as e:
            print(f" [!] Error reading ECML: {e}")

    # 4. swisskyrepo/PayloadsAllTheThings
    print("\n[4/5] Ingesting swisskyrepo/PayloadsAllTheThings...")
    patt_urls = [
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_SQLI.txt", "patt_sqli.txt"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_UnionSelect.txt", "patt_sqli_union.txt"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/SQLi_Polyglots.txt", "patt_sqli_poly.txt"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/JHADDIX_XSS.txt", "patt_xss_jhaddix.txt"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/XSS_Polyglots.txt", "patt_xss_poly.txt"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt", "patt_lfi.txt"),
        ("https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command_exec.txt", "patt_rce.txt")
    ]
    patt_added = 0
    for url, fname in patt_urls:
        dest = os.path.join(DATA_CACHE_DIR, fname)
        if download_file(url, dest):
            with open(dest, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        all_payloads.append(line)
                        all_labels.append(1)
                        patt_added += 1
    print(f" [+] PayloadsAllTheThings: {patt_added:,} attack vectors")

    # 5. danielmiessler/SecLists
    print("\n[5/5] Ingesting danielmiessler/SecLists...")
    sec_urls = [
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt", "sec_sqli.txt"),
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/SQLi-Polyglots.txt", "sec_sqli_poly.txt"),
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt", "sec_blind_sqli.txt"),
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/human-friendly/xss-payload-list.txt", "sec_xss.txt"),
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt", "sec_lfi.txt"),
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt", "sec_rce.txt"),
        ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Server-Side-Template-Injection/ssti-payloads.txt", "sec_ssti.txt")
    ]
    sec_added = 0
    for url, fname in sec_urls:
        dest = os.path.join(DATA_CACHE_DIR, fname)
        if download_file(url, dest):
            with open(dest, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        all_payloads.append(line)
                        all_labels.append(1)
                        sec_added += 1
    print(f" [+] SecLists: {sec_added:,} fuzzing attack vectors")

    # 6. shengqin/web-attacks (Hugging Face)
    print("\n[6/10] Ingesting shengqin/web-attacks (Hugging Face)...")
    try:
        from huggingface_hub import hf_hub_download
        sq_path = hf_hub_download(repo_id="shengqin/web-attacks", filename="all.csv", repo_type="dataset")
        sq_df = pd.read_csv(sq_path)
        sq_added = 0
        for _, row in sq_df.iterrows():
            text = str(row.get('Payload', '')).strip()
            if len(text) < 2:
                continue
            is_attack = 0 if str(row.get('text_label', '')).lower() == 'normal' else 1
            all_payloads.append(text)
            all_labels.append(is_attack)
            sq_added += 1
        print(f" [+] shengqin/web-attacks: {sq_added:,} samples (SQLi, XSS, Normal)")
    except Exception as e:
        print(f" [!] Error loading shengqin: {e}")

    # 7. neuralchemy/Prompt-injection-dataset (Hugging Face)
    print("\n[7/10] Ingesting neuralchemy/Prompt-injection-dataset (Hugging Face)...")
    try:
        from huggingface_hub import hf_hub_download
        na_added = 0
        for split in ['train', 'validation', 'test']:
            na_path = hf_hub_download(repo_id="neuralchemy/Prompt-injection-dataset", filename=f"core/{split}-00000-of-00001.parquet", repo_type="dataset")
            na_df = pd.read_parquet(na_path)
            for _, row in na_df.iterrows():
                text = str(row.get('text', '')).strip()
                if len(text) < 2:
                    continue
                lbl = int(row.get('label', 0))
                all_payloads.append(text)
                all_labels.append(lbl)
                na_added += 1
        print(f" [+] neuralchemy/Prompt-injection: {na_added:,} samples (Modern AI attacks & hard negatives)")
    except Exception as e:
        print(f" [!] Error loading neuralchemy: {e}")

    # 8. jackhhao/jailbreak-classification (Hugging Face)
    print("\n[8/10] Ingesting jackhhao/jailbreak-classification (Hugging Face)...")
    try:
        from huggingface_hub import hf_hub_download
        jh_path = hf_hub_download(repo_id="jackhhao/jailbreak-classification", filename="default/jailbreak_dataset_full.csv", repo_type="dataset")
        jh_df = pd.read_csv(jh_path)
        jh_added = 0
        for _, row in jh_df.iterrows():
            text = str(row.get('prompt', '')).strip()
            if len(text) < 2:
                continue
            lbl = 0 if str(row.get('type', '')).lower() == 'benign' else 1
            all_payloads.append(text)
            all_labels.append(lbl)
            jh_added += 1
        print(f" [+] jackhhao/jailbreak-classification: {jh_added:,} samples")
    except Exception as e:
        print(f" [!] Error loading jackhhao: {e}")

    # 9. deepset/prompt-injections (Hugging Face)
    print("\n[9/10] Ingesting deepset/prompt-injections (Hugging Face)...")
    try:
        from huggingface_hub import hf_hub_download
        ds_added = 0
        for fn in ['data/train-00000-of-00001-9564e8b05b4757ab.parquet', 'data/test-00000-of-00001-701d16158af87368.parquet']:
            ds_path = hf_hub_download(repo_id="deepset/prompt-injections", filename=fn, repo_type="dataset")
            ds_df = pd.read_parquet(ds_path)
            for _, row in ds_df.iterrows():
                text = str(row.get('text', '')).strip()
                if len(text) < 2:
                    continue
                lbl = int(row.get('label', 0))
                all_payloads.append(text)
                all_labels.append(lbl)
                ds_added += 1
        print(f" [+] deepset/prompt-injections: {ds_added:,} samples")
    except Exception as e:
        print(f" [!] Error loading deepset: {e}")

    # 10. rubend18/ChatGPT-Jailbreak-Prompts (Hugging Face)
    print("\n[10/10] Ingesting rubend18/ChatGPT-Jailbreak-Prompts (Hugging Face)...")
    try:
        from huggingface_hub import hf_hub_download
        rb_path = hf_hub_download(repo_id="rubend18/ChatGPT-Jailbreak-Prompts", filename="dataset.csv", repo_type="dataset")
        rb_df = pd.read_csv(rb_path)
        rb_added = 0
        for _, row in rb_df.iterrows():
            text = str(row.get('Prompt', '')).strip()
            if len(text) < 2:
                continue
            all_payloads.append(text)
            all_labels.append(1)
            rb_added += 1
        print(f" [+] rubend18/ChatGPT-Jailbreak-Prompts: {rb_added:,} samples")
    except Exception as e:
        print(f" [!] Error loading rubend18: {e}")

    # 11. Curated Zero-Day & Prompt-Injection dataset
    try:
        from ai_engine.dataset import MALICIOUS_DATASET, BENIGN_DATASET
        # Repeat 5x as high-priority anchor samples
        for _ in range(5):
            for p in MALICIOUS_DATASET:
                all_payloads.append(p)
                all_labels.append(1)
            for p in BENIGN_DATASET:
                all_payloads.append(p)
                all_labels.append(0)
        print(f" [+] Curated Zero-Day & Prompt Injection: {len(MALICIOUS_DATASET) + len(BENIGN_DATASET):,} samples (anchored 5x)")
    except Exception as e:
        print(f" [!] Note on local dataset: {e}")

    return all_payloads, all_labels

# ==============================================================================
# 2. FEATURE EXTRACTION & TOP-N DISCRIMINATIVE N-GRAM SELECTION
# ==============================================================================

DANGEROUS_SYMBOLS = set(["'", '"', '<', '>', ';', '|', '`', '$', '\\'])
SUSPICIOUS_TOKENS = [
    "union", "select", "insert", "drop", "sleep", "waitfor",
    "script", "alert", "onload", "onerror", "eval", "document.",
    "../", "..\\", "etc/passwd", "win.ini", "cmd.exe", "powershell",
    "/bin/sh", "/bin/bash", "whoami", "curl", "wget", "nc ", "cat ",
    "__proto__", "prototype", "169.254.169.254", "${jndi", "system prompt",
    "ignore previous", "system override"
]

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freqs = Counter(text)
    length = len(text)
    ent = 0.0
    for cnt in freqs.values():
        p = cnt / length
        ent -= p * math.log2(p)
    return ent

def extract_heuristics(payload: str) -> List[float]:
    lower_p = payload.lower()
    length = len(payload)
    safe_len = max(length, 1)

    entropy = calculate_entropy(payload)
    danger_count = sum(1 for ch in payload if ch in DANGEROUS_SYMBOLS)
    digit_count = sum(1 for ch in payload if ch.isdigit())
    upper_count = sum(1 for ch in payload if ch.isupper())
    keyword_hits = sum(1 for kw in SUSPICIOUS_TOKENS if kw in lower_p)

    return [
        entropy / 8.0,
        min((danger_count / safe_len) * 4.0, 1.0),
        min((digit_count / safe_len) * 2.0, 1.0),
        upper_count / safe_len,
        min(keyword_hits / 3.0, 1.0),
        min(length / 500.0, 1.0)
    ]

def select_top_trigrams(payloads: List[str], labels: List[int], top_k: int = 400) -> Dict[str, int]:
    print(f"\n[*] Selecting top {top_k} most discriminatory character tri-grams...")
    mal_doc_freq = Counter()
    ben_doc_freq = Counter()
    total_mal = sum(labels)
    total_ben = len(labels) - total_mal

    for p, y in zip(payloads, labels):
        lower = p.lower()
        if len(lower) < 3:
            continue
        seen_tri = set(lower[i:i+3] for i in range(len(lower) - 2))
        if y == 1:
            for tri in seen_tri:
                mal_doc_freq[tri] += 1
        else:
            for tri in seen_tri:
                ben_doc_freq[tri] += 1

    all_trigrams = set(mal_doc_freq.keys()) | set(ben_doc_freq.keys())
    scores = {}

    for tri in all_trigrams:
        m_count = mal_doc_freq[tri]
        b_count = ben_doc_freq[tri]
        # Ignore extremely rare trigrams (< 5 occurrences)
        if m_count + b_count < 10:
            continue
        m_rate = m_count / max(total_mal, 1)
        b_rate = b_count / max(total_ben, 1)
        # Score by absolute rate difference weighted by variance
        score = abs(m_rate - b_rate) / math.sqrt(m_rate + b_rate + 0.001)
        scores[tri] = score

    sorted_trigrams = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
    vocab = {tri: idx for idx, (tri, _) in enumerate(sorted_trigrams)}
    print(f" [+] Selected {len(vocab)} high-impact tri-grams.")
    return vocab

def build_feature_matrix(payloads: List[str], vocab: Dict[str, int]) -> np.ndarray:
    n_samples = len(payloads)
    n_features = 6 + len(vocab)
    X = np.zeros((n_samples, n_features), dtype=np.float32)

    for i, p in enumerate(payloads):
        X[i, :6] = extract_heuristics(p)
        lower_p = p.lower()
        if len(lower_p) >= 3:
            n_tri = len(lower_p) - 2
            inv_n = 1.0 / n_tri
            for j in range(n_tri):
                tri = lower_p[j:j+3]
                if tri in vocab:
                    X[i, 6 + vocab[tri]] += inv_n

    return X

# ==============================================================================
# 3. VECTORIZED TRAINING WITH MOMENTUM & L2 REGULARIZATION
# ==============================================================================

def train_enterprise_model(X: np.ndarray, y: np.ndarray, epochs: int = 25, lr: float = 0.15, l2_reg: float = 0.0005, batch_size: int = 512):
    n_samples, n_features = X.shape
    weights = np.zeros(n_features, dtype=np.float32)
    bias = 0.0

    # Class weighting to balance benign vs attack
    pos_count = np.sum(y)
    neg_count = n_samples - pos_count
    pos_weight = neg_count / max(pos_count, 1)

    print(f"\n[*] Training on {n_samples:,} samples ({n_features} features) on 12-thread CPU...")
    print(f"    Class Balance: {pos_count:,} Malicious vs {neg_count:,} Benign (Weight: {pos_weight:.2f})")

    indices = np.arange(n_samples)
    v_w = np.zeros_like(weights)
    v_b = 0.0
    momentum = 0.9

    for epoch in range(1, epochs + 1):
        t_epoch = time.perf_counter()
        np.random.shuffle(indices)

        for start_idx in range(0, n_samples, batch_size):
            end_idx = min(start_idx + batch_size, n_samples)
            batch_idx = indices[start_idx:end_idx]

            X_b = X[batch_idx]
            y_b = y[batch_idx]

            # Forward pass: z = X · W + b
            z = np.dot(X_b, weights) + bias
            z = np.clip(z, -30.0, 30.0)
            preds = 1.0 / (1.0 + np.exp(-z))

            # Weighted error
            sample_weights = np.where(y_b == 1, pos_weight, 1.0)
            errors = (preds - y_b) * sample_weights

            # Gradients with L2 regularization
            grad_w = (np.dot(X_b.T, errors) / len(batch_idx)) + (l2_reg * weights)
            grad_b = np.sum(errors) / len(batch_idx)

            # Momentum updates
            v_w = momentum * v_w + lr * grad_w
            v_b = momentum * v_b + lr * grad_b

            weights -= v_w
            bias -= v_b

        # Measure epoch accuracy and loss
        z_all = np.dot(X, weights) + bias
        z_all = np.clip(z_all, -30.0, 30.0)
        p_all = 1.0 / (1.0 + np.exp(-z_all))
        binary_preds = (p_all >= 0.5).astype(int)
        acc = np.mean(binary_preds == y) * 100.0

        if epoch % 5 == 0 or epoch == epochs:
            ep_time = time.perf_counter() - t_epoch
            print(f"  Epoch [{epoch:02d}/{epochs}] | Accuracy: {acc:.2f}% | Latency: {ep_time*1000:.1f}ms")

    return weights, bias

# ==============================================================================
# 4. MAIN ORCHESTRATION PIPELINE
# ==============================================================================

def main():
    print("=" * 70)
    print(" 🚀 AEGISGUARD ENTERPRISE DATASET INGESTION & TRAINING ENGINE")
    print("=" * 70)

    t_start = time.perf_counter()

    # Step 1: Ingest all 5 datasets
    payloads, labels = load_all_datasets()
    assert len(payloads) > 10000, "Dataset ingestion failed: not enough samples."

    # Deduplication & sanitization
    seen = set()
    clean_p, clean_y = [], []
    for p, y in zip(payloads, labels):
        if p not in seen:
            seen.add(p)
            clean_p.append(p)
            clean_y.append(y)

    total_samples = len(clean_p)
    print(f"\n[+] Total Deduplicated Enterprise Corpus: {total_samples:,} samples")
    print(f"    - Malicious Attacks : {sum(clean_y):,}")
    print(f"    - Clean Web Traffic : {total_samples - sum(clean_y):,}")

    # Export full consolidated dataset to CSV for inspection and academic proof
    csv_path_enterprise = os.path.join(BASE_DIR, "ai_engine", "full_dataset_enterprise.csv")
    csv_path_76k = os.path.join(BASE_DIR, "ai_engine", "full_dataset_76k.csv")
    print(f"\n[*] Exporting consolidated CSV dataset to disk...")
    df_export = pd.DataFrame({"payload": clean_p, "is_attack": clean_y})
    df_export.to_csv(csv_path_enterprise, index=False, encoding="utf-8")
    df_export.to_csv(csv_path_76k, index=False, encoding="utf-8")
    csv_mb = os.path.getsize(csv_path_enterprise) / (1024 * 1024)
    print(f" [+] Exported {len(df_export):,} samples to:\n     - {csv_path_enterprise} ({csv_mb:.2f} MB - Well under 1 GB!)\n     - {csv_path_76k}")

    # Step 2: Select top discriminatory tri-grams
    vocab = select_top_trigrams(clean_p, clean_y, top_k=500)

    # Step 3: Build high-speed vectorized feature matrix
    print("\n[*] Vectorizing feature matrix with NumPy...")
    t_feat = time.perf_counter()
    X = build_feature_matrix(clean_p, vocab)
    y = np.array(clean_y, dtype=np.float32)
    print(f" [+] Feature matrix ready: {X.shape} ({X.nbytes / (1024*1024):.1f} MB in RAM) in {time.perf_counter() - t_feat:.2f}s")

    # Step 4: 85/15 Train / Validation Split
    indices = np.arange(total_samples)
    np.random.seed(42)
    np.random.shuffle(indices)
    split = int(0.85 * total_samples)
    train_idx, val_idx = indices[:split], indices[split:]

    X_train, y_train = X[train_idx], y[train_idx]
    X_val, y_val = X[val_idx], y[val_idx]

    # Step 5: Train Model
    weights, bias = train_enterprise_model(X_train, y_train, epochs=28, lr=0.12, l2_reg=0.0002, batch_size=512)

    # Step 6: Evaluate on Validation Set
    z_val = np.dot(X_val, weights) + bias
    z_val = np.clip(z_val, -30.0, 30.0)
    p_val = 1.0 / (1.0 + np.exp(-z_val))
    preds_val = (p_val >= 0.65).astype(int)

    tp = np.sum((preds_val == 1) & (y_val == 1))
    fp = np.sum((preds_val == 1) & (y_val == 0))
    tn = np.sum((preds_val == 0) & (y_val == 0))
    fn = np.sum((preds_val == 0) & (y_val == 1))

    val_acc = (tp + tn) / len(y_val) * 100.0
    val_prec = tp / max(tp + fp, 1) * 100.0
    val_rec = tp / max(tp + fn, 1) * 100.0
    val_f1 = 2 * (val_prec * val_rec) / max(val_prec + val_rec, 1e-6)

    print("\n" + "=" * 70)
    print(f" 🏆 ENTERPRISE VALIDATION METRICS (Held-out {len(y_val):,} samples):")
    print(f"    - Overall Accuracy : {val_acc:.2f}%")
    print(f"    - Precision        : {val_prec:.2f}%")
    print(f"    - Recall           : {val_rec:.2f}%")
    print(f"    - F1-Score         : {val_f1:.2f}%")
    print("=" * 70)

    # Step 7: Serialize Enterprise Model Weights
    export_data = {
        "metadata": {
            "version": "3.0-Enterprise-Corpus",
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "training_samples": total_samples,
            "dataset_file_size_mb": round(csv_mb, 2),
            "validation_accuracy": round(val_acc, 2),
            "validation_f1": round(val_f1, 2),
            "sources": [
                "Morzeux/HttpParamsDataset",
                "notesbymuneeb/ai-waf-dataset",
                "msudol/Web-Application-Attack-Datasets (ECML)",
                "swisskyrepo/PayloadsAllTheThings",
                "danielmiessler/SecLists",
                "shengqin/web-attacks",
                "neuralchemy/Prompt-injection-dataset",
                "jackhhao/jailbreak-classification",
                "deepset/prompt-injections",
                "rubend18/ChatGPT-Jailbreak-Prompts"
            ]
        },
        "vocab": vocab,
        "weights": [round(float(w), 6) for w in weights],
        "bias": round(float(bias), 6),
        "threshold": 0.65
    }

    with open(WEIGHTS_PATH, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)

    total_time = time.perf_counter() - t_start
    print(f"\n[+] Successfully saved trained enterprise weights to:\n    {WEIGHTS_PATH}")
    print(f"[+] Total Pipeline Duration: {total_time:.2f} seconds")
    print("=" * 70)

if __name__ == "__main__":
    main()
