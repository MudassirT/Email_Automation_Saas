import time
import base64
import os
import math
from collections import Counter
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def benchmark_10k_bm25_crypto():
    master_key = Fernet.generate_key()
    salt = os.urandom(16)
    info = b"automail:org_benchmark:v1"
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    tenant_key = base64.urlsafe_b64encode(hkdf.derive(master_key))
    cipher = Fernet(tenant_key)

    sample_sub = "Urgent: Incident Escalation & API Throttling Event on Staging Cluster"
    sample_body = (
        "Team, we observed a spike in 429 Too Many Requests errors starting at 14:22 UTC. "
        "Affected endpoints include /api/v1/messages and /api/v1/auth/tokens. "
        "Please inspect Redis connection pools, pgbouncer stats, and customer rate limits immediately. "
        "We need an incident post-mortem filed within 24 hours under SOC-2 CC7.3 compliance rules."
    )

    doc_text = f"{sample_sub}\n{sample_body}"
    ciphertexts = [cipher.encrypt(doc_text.encode("utf-8")) for _ in range(10000)]

    # 1. Measure Decryption Latency for 10,000 Messages
    t0 = time.perf_counter()
    decrypted_docs = [cipher.decrypt(ct).decode("utf-8") for ct in ciphertexts]
    t_dec = (time.perf_counter() - t0) * 1000

    # 2. Measure Full BM25 Model Index Construction
    t1 = time.perf_counter()
    doc_lens = []
    term_freqs = []
    df = Counter()
    for doc in decrypted_docs:
        words = [w.strip(".,:;!?()[]\"'").lower() for w in doc.split() if w]
        doc_lens.append(len(words))
        tf = Counter(words)
        term_freqs.append(tf)
        for word in tf.keys():
            df[word] += 1

    avgdl = sum(doc_lens) / len(doc_lens)
    N = len(decrypted_docs)
    idf = {word: math.log((N - freq + 0.5) / (freq + 0.5) + 1.0) for word, freq in df.items()}
    t_idx = (time.perf_counter() - t1) * 1000

    # 3. Measure Query Latency on the in-memory BM25 index
    t2 = time.perf_counter()
    query = "incident throttling rate limits"
    q_words = query.lower().split()
    k1, b = 1.5, 0.75
    scores = []
    for doc_id, tf in enumerate(term_freqs):
        score = 0.0
        dl = doc_lens[doc_id]
        for qw in q_words:
            if qw in tf:
                f = tf[qw]
                score += idf.get(qw, 0) * (f * (k1 + 1)) / (f + k1 * (1 - b + b * (dl / avgdl)))
        if score > 0:
            scores.append((score, doc_id))
    scores.sort(reverse=True)
    top5 = scores[:5]
    t_query = (time.perf_counter() - t2) * 1000

    # 4. Measure Incremental Document Ingestion (1 new email decrypt + tokenization update)
    t3 = time.perf_counter()
    new_doc = cipher.decrypt(ciphertexts[0]).decode("utf-8")
    new_words = [w.strip(".,:;!?()[]\"'").lower() for w in new_doc.split() if w]
    new_tf = Counter(new_words)
    t_inc = (time.perf_counter() - t3) * 1000

    print("=" * 65)
    print("      BM25 RAG INDEX DECRYPTION & REBUILD BENCHMARK (10,000 EMAILS)")
    print("=" * 65)
    print(f"1. Decryption Throughput (10k emails):  {t_dec:7.2f} ms ({t_dec/10000:.4f} ms/email)")
    print(f"2. BM25 Index Build (10k docs):         {t_idx:7.2f} ms ({t_idx/10000:.4f} ms/doc)")
    print(f"3. Total Cold Rebuild (Decrypt + Index):{t_dec + t_idx:7.2f} ms ({(t_dec + t_idx)/1000:.2f}s)")
    print(f"4. Search Query Latency (10k corpus):   {t_query:7.2f} ms")
    print(f"5. Incremental Add Latency (1 email):   {t_inc:7.2f} ms")
    print("=" * 65)

if __name__ == "__main__":
    benchmark_10k_bm25_crypto()
