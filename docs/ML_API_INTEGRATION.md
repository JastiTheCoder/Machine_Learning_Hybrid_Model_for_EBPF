# ML API Integration Guide

**For: Aniruddha (Go Monitor Integration)**  
**Author: Karthik (ML Team)**  
**Date: October 2026**

---

## Overview

This document explains how to integrate the ML prediction API with the eBPF monitor for real-time malware detection.

---

## Quick Start

### 1. Start the ML API Server

```bash
# Install dependencies
cd capstone
pip install -r ml_analysis/api_requirements.txt

# Start the server
python -m uvicorn ml_analysis.api:app --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

### 2. Test the API

```bash
# Health check
curl http://localhost:8000/health

# Model info
curl http://localhost:8000/model/info
```

---

## API Endpoints

### `POST /predict` - Main Prediction Endpoint

This is the primary endpoint for the Go monitor to call when a session completes.

**Request:**
```json
{
  "session_id": "npm-1234567890",
  "package_name": "suspicious-package",
  "file_operations": [
    {"path": "/home/user/.ssh/id_rsa", "operation": "read"},
    {"path": "/tmp/data.txt", "operation": "write"}
  ],
  "network_connections": [
    {"domain": "evil.com", "direction": "outbound", "protocol": "https"}
  ],
  "process_events": [
    {"event_type": "exec", "comm": "node"},
    {"event_type": "fork", "comm": "sh"}
  ],
  "dns_queries": [
    {"domain": "registry.npmjs.org"}
  ]
}
```

**Response:**
```json
{
  "prediction": "malicious",
  "confidence": 0.92,
  "label": 1,
  "package_name": "suspicious-package",
  "session_id": "npm-1234567890",
  "features_extracted": {
    "num_file_operations": 2,
    "sensitive_file_access": 1,
    "outbound_connections": 1,
    "shell_invocations": 1,
    ...
  },
  "recommendation": "BLOCK",
  "timestamp": "2026-10-18T08:00:00"
}
```

### `POST /predict/features` - Predict from Feature Vector

If the Go monitor pre-extracts features, use this endpoint.

**Request:**
```json
{
  "features": [5, 2, 10, 1, 3, 2, 0, 1, 2, 3, 2, 5, 8, 1, 0, 1]
}
```

**Feature Order (16 features):**
1. `num_file_operations`
2. `num_network_connections`
3. `num_process_events`
4. `num_dns_queries`
5. `file_reads`
6. `file_writes`
7. `file_deletes`
8. `sensitive_file_access`
9. `outbound_connections`
10. `unique_domains`
11. `http_requests`
12. `child_processes`
13. `exec_calls`
14. `shell_invocations`
15. `curl_wget_calls`
16. `dns_query_count`

### `POST /predict/batch` - Batch Predictions

For processing multiple captures at once.

**Request:**
```json
[
  { "session_id": "npm-1", "package_name": "pkg1", ... },
  { "session_id": "npm-2", "package_name": "pkg2", ... }
]
```

**Response:**
```json
{
  "predictions": [...],
  "total": 2,
  "malicious_count": 1,
  "benign_count": 1
}
```

### `GET /health` - Health Check

```json
{
  "status": "ok",
  "model_loaded": true,
  "timestamp": "2026-10-18T08:00:00"
}
```

### `GET /model/info` - Model Information

```json
{
  "model_type": "RandomForestClassifier",
  "features_count": 16,
  "feature_names": [...],
  "training_samples": 307,
  "accuracy": 0.951,
  "recall": 0.768,
  "precision": 0.956,
  "version": "1.0.0"
}
```

---

## Go Integration Example

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type MLPrediction struct {
    Prediction     string             `json:"prediction"`
    Confidence     float64            `json:"confidence"`
    Label          int                `json:"label"`
    Recommendation string             `json:"recommendation"`
}

func predictMalware(sessionJSON []byte) (*MLPrediction, error) {
    resp, err := http.Post(
        "http://localhost:8000/predict",
        "application/json",
        bytes.NewBuffer(sessionJSON),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var prediction MLPrediction
    if err := json.NewDecoder(resp.Body).Decode(&prediction); err != nil {
        return nil, err
    }
    
    return &prediction, nil
}

// Usage in session completion handler:
func onSessionComplete(session *Session) {
    // Convert session to JSON
    sessionJSON, _ := json.Marshal(session)
    
    // Get ML prediction
    pred, err := predictMalware(sessionJSON)
    if err != nil {
        log.Printf("ML prediction failed: %v", err)
        return
    }
    
    // Combine with rule engine verdict
    if pred.Label == 1 || session.Verdict.Level == "malicious" {
        fmt.Printf("[BLOCKED] Package %s is malicious (ML: %s, confidence: %.2f)\n",
            session.PackageName, pred.Prediction, pred.Confidence)
    } else {
        fmt.Printf("[ALLOWED] Package %s is safe\n", session.PackageName)
    }
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     npm install <package>                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   eBPF Monitor (Go)                             │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Syscall    │  │    File     │  │    TCP      │             │
│  │  Tracer     │  │   Monitor   │  │   Monitor   │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         └────────────────┴────────────────┘                     │
│                          │                                      │
│                 Session Aggregator                              │
│                          │                                      │
│              ┌───────────┴───────────┐                          │
│              │    Verdict Engine     │                          │
│              │     (12 Rules)        │                          │
│              └───────────┬───────────┘                          │
└──────────────────────────┼──────────────────────────────────────┘
                           │
                      HTTP POST /predict
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ML API (Python)                              │
│                                                                 │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────┐       │
│  │   Feature    │──>│ RandomForest  │──>│   Response   │       │
│  │  Extraction  │   │    Model      │   │  Generator   │       │
│  └──────────────┘   └───────────────┘   └──────────────┘       │
│                                                                 │
│  Model Stats: 76.8% recall, 95.6% precision                    │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FINAL DECISION                               │
│                                                                 │
│  Rule Engine MALICIOUS  OR  ML MALICIOUS  →  BLOCK INSTALL     │
│  Both BENIGN                              →  ALLOW INSTALL     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Model Details

### Training Data
- **Benign packages:** 251 real npm packages (lodash, express, chalk, etc.)
- **Malicious packages:** 56 known malicious packages (typosquats, stealers)
- **Total:** 307 samples

### Performance (5-fold Cross-Validation)
| Metric | Value |
|--------|-------|
| Accuracy | 95.1% |
| Recall | 76.8% |
| Precision | 95.6% |
| F1 Score | 85.1% |

### Features Used (16 total)
The model analyzes behavioral patterns during npm install:
- File operations (reads, writes, deletes)
- Sensitive file access (.ssh, .env, credentials)
- Network connections (outbound, unique domains)
- Process spawning (shells, curl/wget)
- DNS queries

---

## Error Handling

| HTTP Code | Meaning | Action |
|-----------|---------|--------|
| 200 | Success | Use prediction |
| 400 | Bad request | Check input format |
| 503 | Model not loaded | Wait and retry |
| 500 | Server error | Log and fallback to rules only |

**Recommended fallback:**
```go
if mlPrediction == nil {
    // Fallback to rule engine only
    if ruleVerdict.Level == "malicious" {
        blockInstall()
    }
}
```

---

## Deployment

### Local Development
```bash
uvicorn ml_analysis.api:app --host 127.0.0.1 --port 8000 --reload
```

### Production
```bash
uvicorn ml_analysis.api:app --host 0.0.0.0 --port 8000 --workers 4
```

### Docker (Future)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY ml_analysis/ ./ml_analysis/
COPY captures/ ./captures/
RUN pip install -r ml_analysis/api_requirements.txt
CMD ["uvicorn", "ml_analysis.api:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Questions?

Contact: Karthik (ML Team)
Repository: https://github.com/JastiTheCoder/Machine_Learning_Hybrid_Model_for_EBPF
