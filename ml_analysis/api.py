"""
ML Prediction API for npm Package Malware Detection
====================================================

This API provides real-time predictions for the eBPF monitor.
It accepts JSON captures from the Go monitor and returns predictions.

Endpoints:
- POST /predict - Predict from raw eBPF JSON capture
- POST /predict/features - Predict from pre-extracted features
- POST /predict/batch - Batch predictions
- GET /health - Health check
- GET /model/info - Model information

Usage:
    pip install fastapi uvicorn scikit-learn pandas numpy
    uvicorn ml_analysis.api:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import numpy as np
import json
import os
import pickle
from datetime import datetime

# Initialize FastAPI app
app = FastAPI(
    title="npm Malware Detection API",
    description="ML-based malware detection for npm packages using behavioral analysis",
    version="1.0.0"
)

# ============================================================================
# MODELS
# ============================================================================

class FileOperation(BaseModel):
    path: str = ""
    operation: str = ""
    timestamp: Optional[float] = None

class NetworkConnection(BaseModel):
    domain: str = ""
    direction: str = ""
    protocol: str = ""
    port: Optional[int] = None

class ProcessEvent(BaseModel):
    event_type: str = ""
    comm: str = ""
    pid: Optional[int] = None

class DNSQuery(BaseModel):
    domain: str = ""

class CaptureInput(BaseModel):
    """Raw eBPF capture JSON from the Go monitor"""
    session_id: str = ""
    package_name: str = ""
    file_operations: List[Dict[str, Any]] = []
    network_connections: List[Dict[str, Any]] = []
    process_events: List[Dict[str, Any]] = []
    dns_queries: List[Dict[str, Any]] = []

class FeatureInput(BaseModel):
    """Pre-extracted feature vector (16 features)"""
    features: List[float]

class PredictionResponse(BaseModel):
    """Response from prediction endpoint"""
    prediction: str  # "benign" or "malicious"
    confidence: float  # 0.0 to 1.0
    label: int  # 0 = benign, 1 = malicious
    package_name: str
    session_id: str
    features_extracted: Dict[str, float]
    recommendation: str  # "ALLOW" or "BLOCK"
    timestamp: str

class BatchPredictionResponse(BaseModel):
    """Response from batch prediction endpoint"""
    predictions: List[PredictionResponse]
    total: int
    malicious_count: int
    benign_count: int

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    model_loaded: bool
    timestamp: str

class ModelInfoResponse(BaseModel):
    """Model information response"""
    model_type: str
    features_count: int
    feature_names: List[str]
    training_samples: int
    accuracy: float
    recall: float
    precision: float
    version: str

# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

FEATURE_NAMES = [
    "num_file_operations",
    "num_network_connections", 
    "num_process_events",
    "num_dns_queries",
    "file_reads",
    "file_writes",
    "file_deletes",
    "sensitive_file_access",
    "outbound_connections",
    "unique_domains",
    "http_requests",
    "child_processes",
    "exec_calls",
    "shell_invocations",
    "curl_wget_calls",
    "dns_query_count"
]

SENSITIVE_PATTERNS = [
    '/etc/passwd', '/etc/shadow', '.ssh', '.env', '.npmrc',
    'credentials', 'password', 'secret', 'token', 'api_key',
    '.aws', '.docker', '.kube', '.gitconfig'
]

def extract_features(data: dict) -> dict:
    """Extract 16 behavioral features from raw capture JSON"""
    features = {}
    
    # Basic counts
    file_ops = data.get('file_operations', [])
    net_conns = data.get('network_connections', [])
    proc_events = data.get('process_events', [])
    dns_queries = data.get('dns_queries', [])
    
    features['num_file_operations'] = len(file_ops)
    features['num_network_connections'] = len(net_conns)
    features['num_process_events'] = len(proc_events)
    features['num_dns_queries'] = len(dns_queries)
    
    # File operation details
    features['file_reads'] = sum(1 for op in file_ops if op.get('operation') == 'read')
    features['file_writes'] = sum(1 for op in file_ops if op.get('operation') == 'write')
    features['file_deletes'] = sum(1 for op in file_ops if op.get('operation') == 'delete')
    
    # Sensitive file access
    sensitive_count = 0
    for op in file_ops:
        path = op.get('path', '').lower()
        if any(p in path for p in SENSITIVE_PATTERNS):
            sensitive_count += 1
    features['sensitive_file_access'] = sensitive_count
    
    # Network details
    features['outbound_connections'] = sum(1 for conn in net_conns if conn.get('direction') == 'outbound')
    features['unique_domains'] = len(set(conn.get('domain', '') for conn in net_conns))
    features['http_requests'] = sum(1 for conn in net_conns if conn.get('protocol', '').lower() in ['http', 'https'])
    
    # Process events
    features['child_processes'] = sum(1 for e in proc_events if e.get('event_type') == 'fork')
    features['exec_calls'] = sum(1 for e in proc_events if e.get('event_type') == 'exec')
    
    # Suspicious indicators
    features['shell_invocations'] = sum(1 for e in proc_events if 'sh' in str(e.get('comm', '')).lower())
    features['curl_wget_calls'] = sum(1 for e in proc_events if any(x in str(e.get('comm', '')).lower() for x in ['curl', 'wget']))
    
    # DNS
    features['dns_query_count'] = len(dns_queries)
    
    return features

# ============================================================================
# MODEL LOADING
# ============================================================================

# Global model state
MODEL = None
SCALER = None
MODEL_INFO = {
    "model_type": "RandomForestClassifier",
    "features_count": 16,
    "feature_names": FEATURE_NAMES,
    "training_samples": 307,
    "accuracy": 0.951,
    "recall": 0.768,
    "precision": 0.956,
    "version": "1.0.0"
}

def load_model():
    """Load the trained model from disk or train a new one"""
    global MODEL, SCALER
    
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
    
    if os.path.exists(model_path) and os.path.exists(scaler_path):
        with open(model_path, 'rb') as f:
            MODEL = pickle.load(f)
        with open(scaler_path, 'rb') as f:
            SCALER = pickle.load(f)
        return True
    
    # If no saved model, train one from captures
    return train_model_from_captures()

def train_model_from_captures():
    """Train model from capture files in captures/ directory"""
    global MODEL, SCALER, MODEL_INFO
    
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    
    # Find captures directory
    base_path = os.path.dirname(os.path.dirname(__file__))
    benign_path = os.path.join(base_path, 'captures', 'benign')
    malware_path = os.path.join(base_path, 'captures', 'malware')
    
    if not os.path.exists(benign_path) or not os.path.exists(malware_path):
        return False
    
    # Load and extract features
    X_data = []
    y_data = []
    
    # Load benign
    for f in os.listdir(benign_path):
        if f.endswith('.json'):
            try:
                with open(os.path.join(benign_path, f), 'r') as file:
                    data = json.load(file)
                    features = extract_features(data)
                    X_data.append([features[fn] for fn in FEATURE_NAMES])
                    y_data.append(0)
            except:
                pass
    
    # Load malware
    for f in os.listdir(malware_path):
        if f.endswith('.json'):
            try:
                with open(os.path.join(malware_path, f), 'r') as file:
                    data = json.load(file)
                    features = extract_features(data)
                    X_data.append([features[fn] for fn in FEATURE_NAMES])
                    y_data.append(1)
            except:
                pass
    
    if len(X_data) == 0:
        return False
    
    X = np.array(X_data)
    y = np.array(y_data)
    
    # Train
    SCALER = StandardScaler()
    X_scaled = SCALER.fit_transform(X)
    
    MODEL = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    MODEL.fit(X_scaled, y)
    
    # Update model info
    MODEL_INFO['training_samples'] = len(X_data)
    
    # Save model
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(MODEL, f)
    with open(scaler_path, 'wb') as f:
        pickle.dump(SCALER, f)
    
    return True

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Load model on startup"""
    load_model()

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Check if the API is running and model is loaded"""
    return HealthResponse(
        status="ok" if MODEL is not None else "degraded",
        model_loaded=MODEL is not None,
        timestamp=datetime.now().isoformat()
    )

@app.get("/model/info", response_model=ModelInfoResponse)
async def model_info():
    """Get information about the loaded model"""
    return ModelInfoResponse(**MODEL_INFO)

@app.post("/predict", response_model=PredictionResponse)
async def predict_from_json(capture: CaptureInput):
    """
    Predict maliciousness from raw eBPF capture JSON.
    
    This is the main endpoint for the Go monitor to call.
    """
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    # Convert to dict
    data = capture.dict()
    
    # Extract features
    features = extract_features(data)
    feature_vector = np.array([[features[fn] for fn in FEATURE_NAMES]])
    
    # Scale and predict
    feature_scaled = SCALER.transform(feature_vector)
    prediction = MODEL.predict(feature_scaled)[0]
    proba = MODEL.predict_proba(feature_scaled)[0]
    
    confidence = proba[1] if prediction == 1 else proba[0]
    
    return PredictionResponse(
        prediction="malicious" if prediction == 1 else "benign",
        confidence=float(confidence),
        label=int(prediction),
        package_name=capture.package_name,
        session_id=capture.session_id,
        features_extracted=features,
        recommendation="BLOCK" if prediction == 1 else "ALLOW",
        timestamp=datetime.now().isoformat()
    )

@app.post("/predict/features", response_model=PredictionResponse)
async def predict_from_features(input: FeatureInput):
    """
    Predict from pre-extracted feature vector.
    
    Expects a list of 16 float values in the order defined by FEATURE_NAMES.
    """
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    if len(input.features) != 16:
        raise HTTPException(status_code=400, detail=f"Expected 16 features, got {len(input.features)}")
    
    feature_vector = np.array([input.features])
    feature_scaled = SCALER.transform(feature_vector)
    prediction = MODEL.predict(feature_scaled)[0]
    proba = MODEL.predict_proba(feature_scaled)[0]
    
    confidence = proba[1] if prediction == 1 else proba[0]
    
    # Create features dict
    features_dict = {fn: input.features[i] for i, fn in enumerate(FEATURE_NAMES)}
    
    return PredictionResponse(
        prediction="malicious" if prediction == 1 else "benign",
        confidence=float(confidence),
        label=int(prediction),
        package_name="unknown",
        session_id="manual",
        features_extracted=features_dict,
        recommendation="BLOCK" if prediction == 1 else "ALLOW",
        timestamp=datetime.now().isoformat()
    )

@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(captures: List[CaptureInput]):
    """
    Batch prediction for multiple captures.
    """
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    predictions = []
    malicious_count = 0
    
    for capture in captures:
        result = await predict_from_json(capture)
        predictions.append(result)
        if result.label == 1:
            malicious_count += 1
    
    return BatchPredictionResponse(
        predictions=predictions,
        total=len(predictions),
        malicious_count=malicious_count,
        benign_count=len(predictions) - malicious_count
    )

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
