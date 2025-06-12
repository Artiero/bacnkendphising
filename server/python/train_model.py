import pandas as pd
import joblib
import math
import re
from urllib.parse import urlparse
from collections import Counter
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
from collections import Counter as Cn

# === FUNGSI EKSTRAKSI FITUR ===
def calculate_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def count_non_alphanum(url):
    return sum(not c.isalnum() for c in url)

def url_length(url):
    return len(url)

def num_dots(url):
    return url.count('.')

def has_ip(url):
    return int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url)))

def has_suspicious_extension(url):
    suspicious_exts = ['.exe', '.zip', '.scr', '.rar', '.php', '.apk']
    return int(any(url.lower().endswith(ext) for ext in suspicious_exts))

def get_sensitive_keywords_count(url):
    keywords = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'webscr']
    return sum(1 for word in keywords if word in url.lower())

def detect_suspicious_patterns_count(url):
    patterns = ['cgi-bin', 'base64', 'redirect=', 'confirm', 'webscr', '//', '@', '-secure']
    return sum(1 for p in patterns if p in url.lower())

def uses_https(url):
    return int(url.startswith('https'))

def has_port(url):
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
    except IndexError:
        return 0

# === EKSTRAKSI SEMUA FITUR ===
def extract_features(url):
    return [
        calculate_entropy(url),
        count_non_alphanum(url),
        url_length(url),
        num_dots(url),
        has_ip(url),
        has_suspicious_extension(url),
        get_sensitive_keywords_count(url),
        detect_suspicious_patterns_count(url),
        uses_https(url),
        has_port(url),
        count_subdomains(url),
        has_https_token(url),
        ratio_digits(url),
        check_tld_length(url)
    ]

# === LOAD DATASET ===
df = pd.read_csv('dataset.csv')  # pastikan kolom: 'url' dan 'label'
df['features'] = df['url'].apply(extract_features)
X = list(df['features'])
y = list(df['label'])

print("Jumlah data sebelum SMOTE:", Cn(y))

# === SMOTE UNTUK IMBALANCED DATA ===
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

print("Jumlah data setelah SMOTE:", Cn(y_resampled))

# === NORMALISASI FITUR ===
scaler = StandardScaler()
X_resampled_scaled = scaler.fit_transform(X_resampled)

# === SPLIT DAN TRAIN MODEL ===
X_train, X_test, y_train, y_test = train_test_split(X_resampled_scaled, y_resampled, test_size=0.2, random_state=42)

model = XGBClassifier(eval_metric='logloss', random_state=42)
model.fit(X_train, y_train)

# === EVALUASI ===
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# === SIMPAN MODEL DAN SCALER ===
joblib.dump(model, 'phishing_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
print("Model dan scaler disimpan sebagai phishing_model.pkl dan scaler.pkl")
