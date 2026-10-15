"""
Generate comparison CSV: GuardDog vs ML Model
"""
import pandas as pd
import numpy as np
import json
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Load GuardDog results
guarddog_df = pd.read_excel('ml_analysis/guarddog_results.xlsx')
guarddog_packages = set(guarddog_df['Package Name'].str.lower().tolist())
guarddog_fails = set(guarddog_df[guarddog_df['GuardDog Result'] == 'FAIL']['Package Name'].str.lower().tolist())

# Feature extraction
def extract_features(data):
    features = {}
    features['num_file_operations'] = len(data.get('file_operations', []))
    features['num_network_connections'] = len(data.get('network_connections', []))
    features['num_process_events'] = len(data.get('process_events', []))
    features['num_dns_queries'] = len(data.get('dns_queries', []))
    file_ops = data.get('file_operations', [])
    features['file_reads'] = sum(1 for op in file_ops if op.get('operation') == 'read')
    features['file_writes'] = sum(1 for op in file_ops if op.get('operation') == 'write')
    features['file_deletes'] = sum(1 for op in file_ops if op.get('operation') == 'delete')
    sensitive_patterns = ['/etc/passwd', '/etc/shadow', '.ssh', '.env', '.npmrc', 'credentials', 'password', 'secret', 'token', 'api_key']
    sensitive_count = 0
    for op in file_ops:
        path = op.get('path', '').lower()
        if any(p in path for p in sensitive_patterns):
            sensitive_count += 1
    features['sensitive_file_access'] = sensitive_count
    net_conns = data.get('network_connections', [])
    features['outbound_connections'] = sum(1 for conn in net_conns if conn.get('direction') == 'outbound')
    features['unique_domains'] = len(set(conn.get('domain', '') for conn in net_conns))
    features['http_requests'] = sum(1 for conn in net_conns if conn.get('protocol', '').lower() in ['http', 'https'])
    proc_events = data.get('process_events', [])
    features['child_processes'] = sum(1 for e in proc_events if e.get('event_type') == 'fork')
    features['exec_calls'] = sum(1 for e in proc_events if e.get('event_type') == 'exec')
    features['shell_invocations'] = sum(1 for e in proc_events if 'sh' in str(e.get('comm', '')).lower())
    features['curl_wget_calls'] = sum(1 for e in proc_events if any(x in str(e.get('comm', '')).lower() for x in ['curl', 'wget']))
    return features

# Load captures
print("Loading captures...")
benign_data, benign_names = [], []
for f in os.listdir('captures/benign'):
    if f.endswith('.json'):
        try:
            pkg_name = f.split('_', 1)[1].replace('.json', '').lower()
            with open(os.path.join('captures/benign', f), 'r') as file:
                features = extract_features(json.load(file))
                benign_data.append(features)
                benign_names.append(pkg_name)
        except: pass

malware_data, malware_names = [], []
for f in os.listdir('captures/malware'):
    if f.endswith('.json'):
        try:
            pkg_name = f.split('_', 1)[1].replace('.json', '').lower()
            with open(os.path.join('captures/malware', f), 'r') as file:
                features = extract_features(json.load(file))
                malware_data.append(features)
                malware_names.append(pkg_name)
        except: pass

print(f"Loaded {len(benign_data)} benign, {len(malware_data)} malware")

# Train model
feature_names = list(benign_data[0].keys())
X_benign = np.array([[d[f] for f in feature_names] for d in benign_data])
X_malware = np.array([[d[f] for f in feature_names] for d in malware_data])
X = np.vstack([X_benign, X_malware])
y = np.array([0]*len(benign_data) + [1]*len(malware_data))
all_names = benign_names + malware_names

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
model.fit(X_scaled, y)
proba = model.predict_proba(X_scaled)
pred = model.predict(X_scaled)

# Build comparison
comparison_results = []
for i, pkg in enumerate(all_names):
    if pkg in guarddog_packages:
        gd_fail = pkg in guarddog_fails
        is_benign = i < len(benign_data)
        ml_pred = pred[i]
        
        gd_correct = (not gd_fail and is_benign) or (gd_fail and not is_benign)
        ml_correct = (ml_pred == 0 and is_benign) or (ml_pred == 1 and not is_benign)
        
        comparison_results.append({
            'package': pkg,
            'guarddog_result': 'FAIL' if gd_fail else 'PASS',
            'ml_prediction': 'MALICIOUS' if ml_pred == 1 else 'BENIGN',
            'ml_confidence_pct': round(proba[i][1] * 100, 1),
            'ground_truth': 'BENIGN' if is_benign else 'MALWARE',
            'guarddog_correct': 1 if gd_correct else 0,
            'ml_correct': 1 if ml_correct else 0
        })

df = pd.DataFrame(comparison_results)
df.to_csv('ml_analysis/comparison_results.csv', index=False)

print("\nComparison Results Summary:")
print("="*50)
print(f"Total packages compared: {len(df)}")
print(f"GuardDog accuracy: {df['guarddog_correct'].sum()}/{len(df)} ({100*df['guarddog_correct'].mean():.1f}%)")
print(f"ML Model accuracy: {df['ml_correct'].sum()}/{len(df)} ({100*df['ml_correct'].mean():.1f}%)")
print(f"\nGuardDog false positives: {len(df[(df['guarddog_result']=='FAIL') & (df['ground_truth']=='BENIGN')])}")
print(f"ML Model false positives: {len(df[(df['ml_prediction']=='MALICIOUS') & (df['ground_truth']=='BENIGN')])}")
print("\nSaved to: ml_analysis/comparison_results.csv")
