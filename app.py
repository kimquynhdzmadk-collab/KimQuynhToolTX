"""MD5 TAI/XIU Prediction API — 147 deterministic algorithms"""
import math, time, os, json
from flask import Flask, request, jsonify
from flask_cors import CORS
from collections import Counter

from utils import *
from algorithms import run_all_algorithms

app = Flask(__name__)
CORS(app)

START_TIME = time.time()

# ========== MD5 DECODING ==========
def decode_md5(h):
    bs, ns = hex_to_bytes(h), nibbles(h)
    res = []
    xp = 0
    for i in range(0, 16, 2): xp ^= (bs[i] << 8) | bs[i + 1]
    res.append({'name': 'XOR Byte Pairs', 'result': 'TAI' if xp & 0x8000 else 'XIU', 'raw': hex(xp)})
    ps = sum(ns)
    res.append({'name': 'Parity Sum', 'result': 'TAI' if ps % 2 == 0 else 'XIU', 'raw': ps})
    hc = sum(1 for n in ns if n >= 8); lc = 32 - hc
    res.append({'name': 'Hex Distribution H/L', 'result': 'TAI' if hc >= lc else 'XIU', 'raw': f'H:{hc} L:{lc}'})
    ra = 0
    for n in ns: ra = ((ra << 1) | (ra >> 31)) ^ n
    res.append({'name': 'Bitwise Rotation', 'result': 'TAI' if ra & 1 else 'XIU', 'raw': ra})
    crc = 0xFFFF
    for b in bs:
        crc ^= b
        for _ in range(8): crc = ((crc >> 1) ^ 0xA001) if (crc & 1) else (crc >> 1)
    res.append({'name': 'CRC16 Checksum', 'result': 'TAI' if crc & 1 else 'XIU', 'raw': crc})
    freq = Counter(ns)
    ent = -sum((c / 32) * math.log2(c / 32) for c in freq.values())
    res.append({'name': 'Shannon Entropy', 'result': 'TAI' if ent > 3.5 else 'XIU', 'raw': round(ent, 4)})
    fib = [1, 1, 2, 3, 5, 8, 13, 21]; fx = 0
    for idx in fib:
        if idx < 32: fx ^= ns[idx]
    res.append({'name': 'Fibonacci XOR', 'result': 'TAI' if fx & 1 else 'XIU', 'raw': fx})
    rr = 0
    for n in ns: rr = ((rr << 3) | (rr >> 29)) ^ (n & 0xF)
    res.append({'name': 'Bit Rotation Accum', 'result': 'TAI' if rr & 0x80000000 else 'XIU', 'raw': rr})
    hd = 0
    for i in range(16):
        xv = ns[i] ^ ns[i + 16]
        while xv: hd += xv & 1; xv >>= 1
    res.append({'name': 'Hamming Dist Halves', 'result': 'TAI' if hd >= 32 else 'XIU', 'raw': hd})
    return res

# ========== DATA GENERATION ==========
def generate_data(h):
    ns = nibbles(h); seed = hash_to_seed(h)
    cnt = 40 + (ns[0] % 21)
    res = []
    g = lambda s: ((s * 1103515245 + 12345) & 0x7FFFFFFF) / 0x7FFFFFFF
    state = seed
    for i in range(cnt):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        nv = ns[i % 32]; pf = (i * 7 + nv * 13 + seed) % 256
        is_tai = (pf & 1) == 0
        score = 11 + ((pf >> 1) % 8) if is_tai else 4 + ((pf >> 1) % 7)
        res.append({'index': i + 1, 'result': 'TAI' if is_tai else 'XIU', 'score': score})
    return res

# ========== HASH REVERSAL ==========
def analyze_hash_structure(h):
    bs = hex_to_bytes(h)
    ns = nibbles(h)
    res = []
    ascii_cnt = sum(1 for b in bs if 32 <= b <= 126)
    res.append({'name': 'ASCII Pattern', 'result': 'TAI' if ascii_cnt >= 6 else 'XIU', 'raw': f'{ascii_cnt}/16'})
    high_cnt = sum(1 for b in bs if b >= 128)
    res.append({'name': 'High Byte Count', 'result': 'XIU' if high_cnt >= 4 else 'TAI', 'raw': f'{high_cnt}/16'})
    av = sum(((ns[i] ^ ns[i + 16]) & 0xF) / (i + 1) * 16 for i in range(16))
    res.append({'name': 'Avalanche Score', 'result': 'TAI' if av > 30 else 'XIU', 'raw': round(av, 2)})
    len_bits = ((bs[14] << 8) | bs[15]) * 8
    res.append({'name': 'Input Length Est', 'result': 'TAI' if len_bits % 2 == 0 else 'XIU', 'raw': f'~{len_bits} bits'})
    known = ['d41d8cd98f00b204e9800998ecf8427e', '5d41402abc4b2a76b9719d911017c592', '098f6bcd4621d373cade4e832627b4f6']
    min_d = min(sum(abs(int(h[i], 16) - int(kp[i], 16)) for i in range(32)) for kp in known)
    res.append({'name': 'Known Pattern Dist', 'result': 'TAI' if min_d > 40 else 'XIU', 'raw': min_d})
    mx_c = cur = 0
    for i in range(1, 32):
        if h[i] == h[i - 1]: cur += 1
        else: mx_c = max(mx_c, cur); cur = 0
    res.append({'name': 'Max Repeated Nibbles', 'result': 'XIU' if mx_c > 2 else 'TAI', 'raw': mx_c})
    res.append({'name': 'First Byte', 'result': 'XIU' if bs[0] >= 128 else 'TAI', 'raw': hex(bs[0])})
    res.append({'name': 'Byte Sum mod 256', 'result': 'TAI' if sum(bs) % 256 >= 128 else 'XIU', 'raw': sum(bs) % 256})
    return res

# ============================================================
# ROUTES
# ============================================================
@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'uptime': round(time.time() - START_TIME, 2),
        'version': '3.0.0',
        'algorithms': 147
    })

@app.route('/api/predict/<hash>', methods=['GET'])
def predict_get(hash):
    md5_hash = hash.strip().lower()
    if len(md5_hash) != 32 or not all(c in '0123456789abcdef' for c in md5_hash):
        return jsonify({'error': 'Invalid MD5 hash', 'example': '/api/predict/d41d8cd98f00b204e9800998ecf8427e'}), 400
    return _run_prediction(md5_hash)

@app.route('/api/predict', methods=['POST'])
def predict_post():
    data = request.get_json(silent=True) or {}
    md5_hash = (data.get('hash') or data.get('md5') or '').strip().lower()
    if not md5_hash or len(md5_hash) != 32 or not all(c in '0123456789abcdef' for c in md5_hash):
        return jsonify({'error': 'Invalid MD5 hash. Must be 32 hex characters.', 'example': 'POST /api/predict {"hash": "d41d8cd98f00b204e9800998ecf8427e"}'}), 400
    return _run_prediction(md5_hash)

def _run_prediction(md5_hash):
    t0 = time.time()

    # Run all analyses
    hash_decoding = decode_md5(md5_hash)
    hash_structure = analyze_hash_structure(md5_hash)
    sim_data = generate_data(md5_hash)
    algorithms = run_all_algorithms(sim_data, md5_hash)

    # Compute votes
    groups = {}
    total_tai = total_xiu = 0
    group_weights = {'stat': 1.0, 'tech': 1.15, 'markov': 1.3, 'pattern': 1.2,
                     'fourier': 1.05, 'bayes': 1.1, 'reg': 1.1, 'adv': 1.2, 'ml': 1.4}
    weighted_tai = weighted_xiu = 0

    for a in algorithms:
        g = a['group']
        if g not in groups:
            groups[g] = {'tai': 0, 'xiu': 0, 'total': 0}
        groups[g]['total'] += 1
        if a['prediction'] == 'TAI':
            groups[g]['tai'] += 1
            total_tai += 1
            weighted_tai += group_weights.get(g, 1.0)
        else:
            groups[g]['xiu'] += 1
            total_xiu += 1
            weighted_xiu += group_weights.get(g, 1.0)
        groups[g]['weighted_tai'] = round(groups[g]['tai'] * group_weights.get(g, 1.0), 1)
        groups[g]['weighted_xiu'] = round(groups[g]['xiu'] * group_weights.get(g, 1.0), 1)

    main_prediction = 'TAI' if total_tai >= total_xiu else 'XIU'
    weighted_prediction = 'TAI' if weighted_tai >= weighted_xiu else 'XIU'
    confidence = round(max(total_tai, total_xiu) / len(algorithms) * 100, 1)
    spread = abs(total_tai - total_xiu)

    elapsed = round((time.time() - t0) * 1000, 2)

    return jsonify({
        'hash': md5_hash,
        'prediction': main_prediction,
        'weighted_prediction': weighted_prediction,
        'confidence': confidence,
        'total_algorithms': len(algorithms),
        'tai_votes': total_tai,
        'xiu_votes': total_xiu,
        'weighted_tai': round(weighted_tai, 1),
        'weighted_xiu': round(weighted_xiu, 1),
        'spread': spread,
        'risk': 'LOW' if spread / len(algorithms) > 0.15 else ('MEDIUM' if spread / len(algorithms) > 0.05 else 'HIGH'),
        'processing_time_ms': elapsed,
        'data': {
            'hash_decoding': hash_decoding,
            'hash_structure': hash_structure,
            'simulated_sessions': len(sim_data),
            'groups': {g: {
                'name': g, 'tai': groups[g]['tai'], 'xiu': groups[g]['xiu'],
                'total': groups[g]['total'], 'weight': group_weights.get(g, 1.0),
                'dominant': 'TAI' if groups[g]['tai'] >= groups[g]['xiu'] else 'XIU'
            } for g in sorted(groups.keys())},
            'algorithms': algorithms
        }
    })

@app.route('/api/predict/batch', methods=['POST'])
def predict_batch():
    data = request.get_json(silent=True) or {}
    hashes = data.get('hashes', [])
    if not isinstance(hashes, list) or len(hashes) > 50:
        return jsonify({'error': 'Provide "hashes" array (max 50)'}), 400
    results = []
    for h in hashes:
        try:
            r = app.test_client().post('/api/predict', json={'hash': h})
            results.append(r.get_json())
        except:
            results.append({'hash': h, 'error': 'processing failed'})
    return jsonify({'count': len(results), 'results': results})

@app.route('/')
def index():
    return jsonify({
        'service': 'MD5 TAI/XIU Prediction API',
        'version': '3.0.0',
        'endpoints': {
            'POST /api/predict': 'Predict from single MD5 hash. Body: {"hash": "32-char-md5"}',
            'POST /api/predict/batch': 'Batch predict (max 50). Body: {"hashes": ["hash1","hash2",...]}',
            'GET /api/health': 'Health check'
        },
        'algorithms': 147,
        'groups': ['stat', 'tech', 'markov', 'pattern', 'fourier', 'bayes', 'reg', 'adv', 'ml'],
        'no_random': True
    })

if __name__ == '__main__':
    print("🚀 MD5 TAI/XIU API starting on http://0.0.0.0:5000")
    print("   POST /api/predict  - Predict TAI/XIU from MD5 hash")
    print("   POST /api/predict/batch  - Batch predict (max 50)")
    print("   GET  /api/health   - Health check")
    app.run(host='0.0.0.0', port=5000, debug=False)
