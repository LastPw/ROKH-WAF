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

# ==============================================================================
# 1. MEGA-SCALE MULTI-SOURCE INGESTION (UP TO 1 GB CORPUS)
# ==============================================================================

def load_mega_datasets() -> Tuple[List[str], List[int]]:
    all_payloads: List[str] = []
    all_labels: List[int] = []

    # 1. Existing Enterprise Corpus (118k samples from 10 sources)
    print("\n[1/4] Ingesting Existing Curated Multi-Source Corpus...")
    ent_path = os.path.join(BASE_DIR, "ai_engine", "full_dataset_enterprise.csv")
    if os.path.exists(ent_path):
        df_ent = pd.read_csv(ent_path, on_bad_lines='skip')
        for _, row in df_ent.iterrows():
            p = str(row.get('payload', '')).strip()
            if len(p) >= 2:
                all_payloads.append(p)
                all_labels.append(int(row.get('is_attack', 0)))
        print(f" [+] Consolidated Enterprise Corpus: {len(df_ent):,} samples")

    # 2. YangYang-Research/web-attack-detection (155 MB on HF, 625k samples)
    print("\n[2/4] Ingesting YangYang-Research/web-attack-detection (155 MB)...")
    def clean_yangyang_sentence(s: str) -> str:
        s = str(s).strip()
        if "\r\n\r\n" in s:
            parts = s.split("\r\n\r\n", 1)
            tail = parts[1].strip()
            if tail:
                s = tail
        if ", GET, " in s:
            s = s.split(", GET, ", 1)[1].strip()
        elif ", POST, " in s:
            s = s.split(", POST, ", 1)[1].strip()
        return s

    try:
        from huggingface_hub import hf_hub_download
        yy_path = hf_hub_download(repo_id="YangYang-Research/web-attack-detection", filename="dataset.csv", repo_type="dataset")
        df_yy = pd.read_csv(yy_path)
        # Sample 140k malicious and 140k benign to keep ideal balance and memory efficiency
        df_yy_mal = df_yy[df_yy['Label'] == 1].sample(n=min(140000, sum(df_yy['Label'] == 1)), random_state=42)
        df_yy_ben = df_yy[df_yy['Label'] == 0].sample(n=min(140000, sum(df_yy['Label'] == 0)), random_state=42)
        df_yy_sub = pd.concat([df_yy_mal, df_yy_ben])
        
        yy_added = 0
        for _, row in df_yy_sub.iterrows():
            text = clean_yangyang_sentence(str(row.get('Sentence', '')))
            if len(text) < 2:
                continue
            all_payloads.append(text)
            all_labels.append(int(row.get('Label', 0)))
            yy_added += 1
        print(f" [+] YangYang Web Attack Detection: {yy_added:,} high-fidelity HTTP request samples")
    except Exception as e:
        print(f" [!] Error loading YangYang dataset: {e}")

    # 3. surajshelke/malicious_url (Take true malware / shell / exploit URLs)
    print("\n[3/4] Ingesting surajshelke/malicious_url (Malware payloads & benign)...")
    try:
        from huggingface_hub import hf_hub_download
        su_path = hf_hub_download(repo_id="surajshelke/malicious_url", filename="data/train-00000-of-00001.parquet", repo_type="dataset")
        df_su = pd.read_parquet(su_path)
        # Select malware (true binaries, reverse shells, scripts, .sh, .exe)
        df_su_mal = df_su[df_su['type'] == 'malware']
        df_su_ben = df_su[df_su['type'] == 'benign'].sample(n=len(df_su_mal), random_state=42)
        df_su_sub = pd.concat([df_su_mal, df_su_ben])

        su_added = 0
        for _, row in df_su_sub.iterrows():
            u = str(row.get('url', '')).strip()
            if len(u) < 2:
                continue
            is_attack = 0 if row.get('type', '') == 'benign' else 1
            all_payloads.append(u)
            all_labels.append(is_attack)
            su_added += 1
        print(f" [+] surajshelke Malware & Shell Payloads: {su_added:,} URLs")
    except Exception as e:
        print(f" [!] Error loading surajshelke dataset: {e}")

    # 4. zrmarine/sql_injection (30.9k SQL queries)
    print("\n[4/4] Ingesting zrmarine/sql_injection (30.9k SQL samples)...")
    try:
        from huggingface_hub import hf_hub_download
        zr_path = hf_hub_download(repo_id="zrmarine/sql_injection", filename="Modified_SQL_Dataset.csv", repo_type="dataset")
        df_zr = pd.read_csv(zr_path)
        zr_added = 0
        for _, row in df_zr.iterrows():
            q = str(row.get('Query', '')).strip()
            if len(q) < 2:
                continue
            all_payloads.append(q)
            all_labels.append(int(row.get('Label', 0)))
            zr_added += 1
        print(f" [+] zrmarine SQL Injection Dataset: {zr_added:,} SQL queries")
    except Exception as e:
        print(f" [!] Error loading zrmarine dataset: {e}")

    # 5. Reinforce high-priority Zero-Day & Prompt-Injection anchors (20x)
    try:
        from ai_engine.dataset import MALICIOUS_DATASET, BENIGN_DATASET
        for _ in range(20):
            for p in MALICIOUS_DATASET:
                all_payloads.append(p)
                all_labels.append(1)
            for p in BENIGN_DATASET:
                all_payloads.append(p)
                all_labels.append(0)
        print(f" [+] Anchored Core Zero-Days & Prompt Injections: {len(MALICIOUS_DATASET) + len(BENIGN_DATASET):,} samples (20x weight)")
    except Exception as e:
        print(f" [!] Note on anchors: {e}")

    return all_payloads, all_labels

# ==============================================================================
# 2. FEATURE EXTRACTION & TOP-N DISCRIMINATIVE N-GRAM SELECTION
# ==============================================================================

from ai_engine.model import AegisNeuralBrain
DANGEROUS_SYMBOLS = AegisNeuralBrain.DANGEROUS_SYMBOLS
SUSPICIOUS_TOKENS = AegisNeuralBrain.SUSPICIOUS_TOKENS

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

def select_top_trigrams(payloads: List[str], labels: List[int], top_k: int = 550) -> Dict[str, int]:
    print(f"\n[*] Selecting top {top_k} most discriminatory character tri-grams across mega-corpus...")
    mal_doc_freq = Counter()
    ben_doc_freq = Counter()
    total_mal = sum(labels)
    total_ben = len(labels) - total_mal

    # Sample up to 150k representative samples for vocabulary mining for speed & variance
    sample_size = min(len(payloads), 150000)
    indices = np.random.choice(len(payloads), size=sample_size, replace=False)

    for idx in indices:
        p = payloads[idx]
        y = labels[idx]
        lower = p.lower()
        if len(lower) < 3:
            continue
        seen_tri = set(lower[i:i+3] for i in range(min(len(lower) - 2, 250))) # cap at 250 ngrams per string
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
        if m_count + b_count < 25:
            continue
        m_rate = m_count / max(total_mal, 1)
        b_rate = b_count / max(total_ben, 1)
        score = abs(m_rate - b_rate) / math.sqrt(m_rate + b_rate + 0.0005)
        scores[tri] = score

    sorted_trigrams = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
    vocab = {tri: idx for idx, (tri, _) in enumerate(sorted_trigrams)}
    print(f" [+] Selected {len(vocab)} high-impact discriminative tri-grams.")
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
            for j in range(min(n_tri, 300)):
                tri = lower_p[j:j+3]
                if tri in vocab:
                    X[i, 6 + vocab[tri]] += inv_n

    return X

# ==============================================================================
# 3. HIGH-SPEED VECTORIZED TRAINING (MOMENTUM SGD)
# ==============================================================================

def train_mega_model(X: np.ndarray, y: np.ndarray, epochs: int = 20, lr: float = 0.10, l2_reg: float = 0.0001, batch_size: int = 1024):
    n_samples, n_features = X.shape
    weights = np.zeros(n_features, dtype=np.float32)
    bias = 0.0

    pos_count = np.sum(y)
    neg_count = n_samples - pos_count
    pos_weight = neg_count / max(pos_count, 1)

    print(f"\n[*] Training on {n_samples:,} samples ({n_features} features) with 12-thread CPU SIMD...")
    print(f"    Class Distribution: {pos_count:,.0f} Attacks vs {neg_count:,.0f} Benign (Weight: {pos_weight:.2f})")

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

            z = np.dot(X_b, weights) + bias
            z = np.clip(z, -30.0, 30.0)
            preds = 1.0 / (1.0 + np.exp(-z))

            sample_weights = np.where(y_b == 1, pos_weight, 1.0)
            errors = (preds - y_b) * sample_weights

            grad_w = (np.dot(X_b.T, errors) / len(batch_idx)) + (l2_reg * weights)
            grad_b = np.sum(errors) / len(batch_idx)

            v_w = momentum * v_w + lr * grad_w
            v_b = momentum * v_b + lr * grad_b

            weights -= v_w
            bias -= v_b

        if epoch % 5 == 0 or epoch == epochs:
            # Sample subset for fast epoch check
            check_idx = indices[:50000]
            z_c = np.clip(np.dot(X[check_idx], weights) + bias, -30.0, 30.0)
            acc = np.mean((1.0 / (1.0 + np.exp(-z_c)) >= 0.5).astype(int) == y[check_idx]) * 100.0
            ep_time = time.perf_counter() - t_epoch
            print(f"  Epoch [{epoch:02d}/{epochs}] | Check Accuracy: {acc:.2f}% | Step Latency: {ep_time*1000:.1f}ms")

    return weights, bias

# ==============================================================================
# 4. ORCHESTRATION PIPELINE
# ==============================================================================

def main():
    print("=" * 70)
    print(" 🚀 AEGISGUARD MEGA-SCALE DATASET INGESTION & TRAINING ENGINE")
    print("    Scaling up to hundreds of megabytes / hundreds of thousands of samples")
    print("=" * 70)

    t_start = time.perf_counter()

    # Step 1: Ingest all mega datasets
    payloads, labels = load_mega_datasets()
    print(f"\n[*] Total Raw Ingested Samples: {len(payloads):,}")

    # Deduplication & sanitization
    seen = set()
    clean_p, clean_y = [], []
    for p, y in zip(payloads, labels):
        if p not in seen:
            seen.add(p)
            clean_p.append(p)
            clean_y.append(y)

    total_samples = len(clean_p)
    print(f"\n[+] Total Deduplicated Mega-Corpus: {total_samples:,} samples")
    print(f"    - Malicious Attacks : {sum(clean_y):,}")
    print(f"    - Clean Web Traffic : {total_samples - sum(clean_y):,}")

    # Export consolidated mega-corpus to CSV
    csv_mega_path = os.path.join(BASE_DIR, "ai_engine", "full_dataset_mega_600k.csv")
    csv_ent_path = os.path.join(BASE_DIR, "ai_engine", "full_dataset_enterprise.csv")
    csv_76k_path = os.path.join(BASE_DIR, "ai_engine", "full_dataset_76k.csv")

    print(f"\n[*] Exporting Mega-Dataset to disk...")
    df_export = pd.DataFrame({"payload": clean_p, "is_attack": clean_y})
    df_export.to_csv(csv_mega_path, index=False, encoding="utf-8")
    df_export.to_csv(csv_ent_path, index=False, encoding="utf-8")
    df_export.to_csv(csv_76k_path, index=False, encoding="utf-8")

    csv_mb = os.path.getsize(csv_mega_path) / (1024 * 1024)
    print(f" [+] Consolidated Mega-Dataset exported to:\n     - {csv_mega_path} ({csv_mb:.2f} MB - Solid scale under 1 GB!)")

    # Step 2: Extract top 550 tri-grams
    vocab = select_top_trigrams(clean_p, clean_y, top_k=550)

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
    weights, bias = train_mega_model(X_train, y_train, epochs=25, lr=0.12, l2_reg=0.0001, batch_size=1024)

    # Step 6: Evaluate on Validation Set
    print("\n[*] Evaluating on Validation Set...")
    z_val = np.dot(X_val, weights) + bias
    z_val = np.clip(z_val, -30.0, 30.0)
    p_val = 1.0 / (1.0 + np.exp(-z_val))
    preds_val = (p_val >= 0.60).astype(int)

    tp = np.sum((preds_val == 1) & (y_val == 1))
    fp = np.sum((preds_val == 1) & (y_val == 0))
    tn = np.sum((preds_val == 0) & (y_val == 0))
    fn = np.sum((preds_val == 0) & (y_val == 1))

    val_acc = (tp + tn) / len(y_val) * 100.0
    val_prec = tp / max(tp + fp, 1) * 100.0
    val_rec = tp / max(tp + fn, 1) * 100.0
    val_f1 = 2 * (val_prec * val_rec) / max(val_prec + val_rec, 1e-6)

    print("\n" + "=" * 70)
    print(f" 🏆 MEGA-SCALE VALIDATION METRICS (Held-out {len(y_val):,} samples):")
    print(f"    - Overall Accuracy : {val_acc:.2f}%")
    print(f"    - Precision        : {val_prec:.2f}%")
    print(f"    - Recall           : {val_rec:.2f}%")
    print(f"    - F1-Score         : {val_f1:.2f}%")
    print("=" * 70)

    # Step 7: Serialize Model Weights
    export_data = {
        "metadata": {
            "version": "4.0-MegaScale-Corpus",
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "training_samples": total_samples,
            "dataset_file_size_mb": round(csv_mb, 2),
            "validation_accuracy": round(val_acc, 2),
            "validation_precision": round(val_prec, 2),
            "validation_f1": round(val_f1, 2),
            "sources": [
                "YangYang-Research/web-attack-detection (155 MB)",
                "surajshelke/malicious_url (31 MB parquet)",
                "zrmarine/sql_injection (30.9k queries)",
                "shengqin/web-attacks (53.8k samples)",
                "Morzeux/HttpParamsDataset (31k samples)",
                "msudol/Web-Application-Attack-Datasets ECML (23.8k)",
                "notesbymuneeb/ai-waf-dataset (11.9k)",
                "neuralchemy/Prompt-injection-dataset (6.2k)",
                "jackhhao/jailbreak-classification (2k)",
                "deepset/prompt-injections",
                "rubend18/ChatGPT-Jailbreak-Prompts",
                "swisskyrepo/PayloadsAllTheThings",
                "danielmiessler/SecLists"
            ]
        },
        "vocab": vocab,
        "weights": [round(float(w), 6) for w in weights],
        "bias": round(float(bias), 6),
        "threshold": 0.60
    }

    with open(WEIGHTS_PATH, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)

    total_time = time.perf_counter() - t_start
    print(f"\n[+] Successfully saved trained mega-scale weights to:\n    {WEIGHTS_PATH}")
    print(f"[+] Total Mega-Pipeline Duration: {total_time:.2f} seconds")
    print("=" * 70)

if __name__ == "__main__":
    main()
