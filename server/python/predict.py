import sys
import json
import joblib
import re
import math
import urllib.parse
from urllib.parse import urlparse
import socket
import os

# === Fungsi Ekstraksi Fitur ===
def calculate_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def count_non_alphanum(url):
    return sum(not c.isalnum() for c in url)

def has_suspicious_extension(url):
    suspicious_exts = ['.exe', '.zip', '.scr', '.rar', '.php', '.apk']
    return int(any(url.lower().endswith(ext) for ext in suspicious_exts))

def extract_keywords(url):
    keywords = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'webscr']
    return sum(1 for word in keywords if word in url.lower())

def detect_suspicious_patterns(url):
    patterns = ['cgi-bin', 'base64', 'redirect=', 'confirm', 'webscr', '//', '@', '-secure']
    return sum(1 for pattern in patterns if pattern in url.lower())

def get_url_length(url):
    return len(url)

def get_num_dots(url):
    return url.count('.')

def check_ip_address(url):
    try:
        domain = urlparse(url).netloc
        socket.inet_aton(domain)
        return 1
    except (OSError, socket.error):
        return 0

def check_https(url):
    return int(url.startswith('https'))

def check_port(url):
    parsed = urlparse(url)
    return int(bool(parsed.port))

def count_subdomains(url):
    netloc = urlparse(url).netloc
    return len(netloc.split('.')) - 2 if len(netloc.split('.')) > 2 else 0

def has_https_token(url):
    return int('https' in url[8:].lower())

def ratio_digits(url):
    digits = sum(c.isdigit() for c in url)
    return digits / len(url)

def check_tld_length(url):
    try:
        tld = urlparse(url).netloc.split('.')[-1]
        return len(tld)
    except Exception:
        return 0

# === Ambil URL dari argumen ===
if len(sys.argv) < 2:
    print(json.dumps({ "error": "URL tidak diberikan" }))
    sys.exit(1)

url = sys.argv[1]

# === Whitelist pengecualian domain populer ===
whitelist = ['youtube.com', 'google.com', 'github.com', 'wikipedia.org', 'openai.com']
domain = urlparse(url).netloc.lower()
if any(w in domain for w in whitelist):
    print(json.dumps({
        "status": "aman",
        "note": "URL termasuk whitelist domain populer",
        "probability_phishing": 0.0
    }))
    sys.exit(0)

# === Ekstraksi Fitur ===
entropy = calculate_entropy(url)
non_alphanum = count_non_alphanum(url)
suspicious_extension = has_suspicious_extension(url)
sensitive_keywords = extract_keywords(url)
suspicious_patterns = detect_suspicious_patterns(url)
url_length = get_url_length(url)
num_dots = get_num_dots(url)
has_ip = check_ip_address(url)
uses_https = check_https(url)
has_port = check_port(url)
num_subdomains = count_subdomains(url)
https_token = has_https_token(url)
digit_ratio = ratio_digits(url)
tld_length = check_tld_length(url)

features = [
    entropy,
    non_alphanum,
    url_length,
    num_dots,
    has_ip,
    suspicious_extension,
    sensitive_keywords,
    suspicious_patterns,
    uses_https,
    has_port,
    num_subdomains,
    https_token,
    digit_ratio,
    tld_length
]

# === Load Model dan Scaler ===
model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
model = joblib.load(model_path)
scaler = joblib.load(scaler_path)

features_scaled = scaler.transform([features])
pred = model.predict(features_scaled)[0]
prob_phishing = model.predict_proba(features_scaled)[0][1]

# === Output sebagai JSON ===
output = {
    "status": "phishing" if pred == 1 else "aman",
    "probability_phishing": round(float(prob_phishing), 4),
    "features": {
        "entropy": round(entropy, 4),
        "non_alphanum": non_alphanum,
        "url_length": url_length,
        "num_dots": num_dots,
        "has_ip": has_ip,
        "has_suspicious_extension": suspicious_extension,
        "sensitive_keywords": sensitive_keywords,
        "suspicious_patterns": suspicious_patterns,
        "uses_https": uses_https,
        "has_port": has_port,
        "num_subdomains": num_subdomains,
        "has_https_token": https_token,
        "digit_ratio": round(digit_ratio, 4),
        "tld_length": tld_length
    }
}

print(json.dumps(output))
