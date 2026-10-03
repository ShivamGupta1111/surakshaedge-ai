# SurakshaEdge AI — AI-Powered Safety & Threat Detection System

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Privacy-Preserving](https://img.shields.io/badge/Privacy-Local--First-green.svg)](#security-and-privacy-behaviour)

SurakshaEdge AI is a privacy-preserving, edge-ready cybersecurity assistant designed for local execution on ARM-based edge devices (such as Raspberry Pi 5) or standard Linux/Windows/macOS nodes. It performs multi-vector threat analysis without sending user data, text messages, URLs, or network telemetries to third-party cloud services.

> **Disclaimer:** Generated datasets and local models included for demonstration purposes are synthetic demo artifacts. They are provided for testing and evaluation and should not be presented as real research corpora or enterprise safety guarantees.

---

## 1. Project Overview

SurakshaEdge AI operates completely offline by default, combining fast deterministic rule heuristics with lightweight `scikit-learn` machine learning classifiers to assess security threats across four major vectors:

1. **SMS / Message Spam & Scam Detection:** Identifies phishing, credential harvesting, lottery scams, urgent financial demands, impersonation, and obfuscated text.
2. **URL & Phishing Detection:** Safely extracts host/path features, detects suspicious TLDs, IP hostnames, punycode, URL shorteners, and performs local threat intelligence matching.
3. **Network Flow Anomaly Detection:** Analyzes structured netflow metadata (packet rates, port risks, failed connections, TCP flags, burst transfers) using CICIDS-style feature vectors.
4. **Malware Telemetry Heuristics:** Evaluates system telemetry indicators (abnormal process spawning, persistence, suspicious binary locations, privilege escalation indicators).
5. **Deterministic Risk Engine:** Merges multi-vector signals into a unified risk score (`low`, `medium`, `high`, `critical`) with explicit score explanation.
6. **Llama Advisory Layer:** Generates human-readable explanation and remediation guidance via local templates, with an optional **ExecuTorch** runtime boundary.

---

## 2. Architecture Diagram

```mermaid
flowchart TD
    subgraph Client Layer
        CLI[Local CLI / app.py]
        HTTP[FastAPI REST API / uvicorn]
    end

    subgraph Security Guardrails
        VAL[Input Validation & Length Limits]
        SSRF[SSRF & Private Network Guard]
        RED[Redacting Logger & Storage Guard]
    end

    subgraph Threat Detectors
        SMS[SMS Detector\n(TF-IDF + LogisticRegression / Fallback)]
        URL[URL Detector\n(Feature Extraction + RandomForest / Intel)]
        NET[Network Detector\n(Netflow Vector + RandomForest / Anomaly)]
        MAL[Malware Detector\n(Telemetry Heuristics)]
    end

    subgraph Core Engine
        RE[Risk Engine\n(Weighted Multi-Vector Fusion)]
        ADV[Llama Advisor Layer\n(ExecuTorch Adapter / Local Template)]
    end

    subgraph Persistence & Audit
        DB[(Local SQLite DB\nOne-Way Hash + Redacted Evidence)]
    end

    HTTP --> VAL
    CLI --> VAL
    VAL --> SSRF
    SSRF --> SMS & URL & NET & MAL
    SMS & URL & NET & MAL --> RE
    RE --> ADV
    RE --> RED
    RED --> DB
```

---

## 3. Folder Structure

```text
surakshaedge-ai/
├── README.md                      # Complete documentation
├── LICENSE                        # Open source license
├── .env.example                   # Environment configuration template
├── .gitignore                     # Git exclusion rules
├── pyproject.toml                 # Tool configuration (ruff, pytest)
├── requirements.txt               # Dependency pins
├── Makefile                       # Development & test automation shortcuts
├── Dockerfile                     # Containerization build setup
├── docker-compose.yml             # Local docker compose definition
├── app.py                         # Application entrypoint & CLI wrapper
├── train_models.py                # Local scikit-learn model trainer
├── evaluate_models.py             # Evaluation & confusion matrix reporter
├── data/
│   ├── README.md                  # Dataset directory description
│   ├── sms_spam.csv               # Synthetic SMS dataset
│   ├── url_dataset.csv            # Synthetic URL dataset
│   └── network_flows.csv          # Synthetic network flow dataset
├── models/
│   ├── README.md                  # Trained model directory description
│   ├── sms_model.joblib           # Trained SMS model artifact
│   ├── url_model.joblib           # Trained URL model artifact
│   ├── network_model.joblib       # Trained network flow model artifact
│   └── model_metadata.json        # Artifact checksums & schemas
├── src/
│   ├── __init__.py                # Package initializer
│   ├── config.py                  # Pydantic environment configuration
│   ├── schemas.py                 # Request / Response Pydantic models
│   ├── logging_config.py          # Structured redacting logger
│   ├── exceptions.py              # Domain error definitions
│   ├── api.py                     # FastAPI application endpoints
│   ├── health.py                  # Health check & system status
│   ├── sms_detector.py            # SMS & chat spam detector
│   ├── url_detector.py            # Phishing & malicious URL detector
│   ├── network_detector.py        # Network flow anomaly detector
│   ├── malware_detector.py        # Safe telemetry heuristic analyzer
│   ├── risk_engine.py             # Deterministic risk scoring engine
│   ├── advisor.py                 # Plain-language advisory layer
│   ├── executorch_adapter.py      # ExecuTorch Llama integration boundary
│   ├── storage.py                 # SQLite alert persistence layer
│   ├── metrics.py                 # Lightweight system performance counters
│   └── security.py                # Hashing, redaction & SSRF defenses
├── tests/
│   ├── conftest.py                # Pytest fixtures & setup
│   ├── test_sms_detector.py       # SMS detector test suite
│   ├── test_url_detector.py       # URL detector test suite
│   ├── test_network_detector.py   # Network detector test suite
│   ├── test_risk_engine.py        # Risk engine unit tests
│   ├── test_advisor.py            # Advisory layer unit tests
│   ├── test_api.py                # FastAPI HTTP endpoint tests
│   ├── test_security.py           # SSRF & redaction security tests
│   └── test_pipeline.py           # End-to-end integration tests
└── scripts/
    ├── generate_sample_data.py    # Synthetic demo data generator
    ├── train_local_models.py      # Wrapper script for model training
    └── smoke_test.py              # End-to-end health verification
```

---

## 4. Installation Steps

### Prerequisites
- **Python:** 3.11 or higher
- **OS:** Linux (Ubuntu/Debian/Raspberry Pi OS), macOS, or Windows

### Linux / Raspberry Pi OS / macOS
```bash
# Clone or navigate to the repository
cd surakshaedge-ai

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Windows (PowerShell)
```powershell
cd surakshaedge-ai

# Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install -r requirements.txt
```

---

## 5. Virtual Environment Setup

Always ensure your virtual environment is active before generating data, training models, or launching the server:

```bash
# Verify python location points to .venv
which python   # On Linux/macOS
where python   # On Windows
```

---

## 6. Dataset Format Examples

Synthetic datasets are located under `data/`:

### SMS Dataset (`data/sms_spam.csv`)
```csv
text,label
"Meeting moved to 4pm in conference room B.",legitimate
"URGENT: your bank account will be suspended. Confirm password now.",phishing
"Congratulations you won a lottery prize. Claim now or lose it.",scam
```

### URL Dataset (`data/url_dataset.csv`)
```csv
url,label
"https://example.com/docs/help",benign
"http://192.0.2.55/login/verify-account/wallet",malicious
"http://secure-login-verify-account.xyz/wallet/update",phishing_suspected
```

### Network Flow Dataset (`data/network_flows.csv`)
```csv
duration,protocol,src_port,dst_port,fwd_packets,bwd_packets,bytes_transferred,packet_rate,failed_count,repeated_dst,conn_freq,syn_count,rst_count,label
0.5,tcp,49152,443,8,10,1500,20.0,0,1,2,1,0,normal
0.1,tcp,1234,4444,40,0,800,2500.0,12,25,60,40,5,likely_intrusion
```

To regenerate sample CSV files:
```bash
python scripts/generate_sample_data.py
```

---

## 7. Model Training Commands

To train local scikit-learn models from CSV datasets:

```bash
# Generate fresh sample datasets first
python scripts/generate_sample_data.py

# Train models and save artifacts to models/
python train_models.py --data-dir data --model-dir models --allow-overwrite

# Evaluate trained models and print metrics & confusion matrices
python evaluate_models.py --data-dir data --model-dir models
```

---

## 8. API Startup Commands

Start the local FastAPI server:

```bash
# Standard startup (runs on 127.0.0.1:8000 by default)
python app.py

# Or launch directly using uvicorn
uvicorn src.api:app --host 127.0.0.1 --port 8000 --reload
```

---

## 9. API Usage Examples with `curl`

### Health Check
```bash
curl -s http://127.0.0.1:8000/health
```

### System Info & Model Status
```bash
curl -s http://127.0.0.1:8000/api/v1/info
```

### Analyze SMS / Message
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/analyze/message \
  -H "Content-Type: application/json" \
  -d '{"message": "URGENT: Your account password expires in 10 minutes. Click http://bit.ly/update-now"}'
```

### Analyze URL
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure-login.top/verify"}'
```

### Analyze Network Flow
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/analyze/network-flow \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 0.1,
    "protocol": "tcp",
    "src_port": 1234,
    "dst_port": 4444,
    "fwd_packets": 40,
    "bwd_packets": 0,
    "packet_rate": 2500,
    "failed_count": 12,
    "repeated_dst": 25,
    "conn_freq": 60,
    "syn_count": 40
  }'
```

### Fetch Local Alert Logs
```bash
curl -s http://127.0.0.1:8000/api/v1/alerts
```

---

## 10. CLI Usage Examples

You can test threat analysis directly from the terminal without starting the web server:

```bash
# Analyze SMS message
python app.py analyze-message "Your package delivery failed. Verify details here http://bit.ly/pkg-claim"

# Analyze URL
python app.py analyze-url "http://192.0.2.55/login/wallet"

# Run network flow demo analysis
python app.py analyze-flow-demo
```

---

## 11. ExecuTorch Integration Instructions

SurakshaEdge AI includes a clean adapter interface (`src/executorch_adapter.py`) for running Llama models via PyTorch's **ExecuTorch** runtime on edge hardware:

1. **Install ExecuTorch** (if supported on your target OS/architecture):
   ```bash
   pip install executorch
   ```
2. **Export or Place a `.pte` Llama Model:**
   Place the compiled ExecuTorch model (e.g. `llama3_8b.pte`) in `models/` or a custom directory.
3. **Configure Environment Variables:**
   ```bash
   export SURAKSHA_ADVISOR_BACKEND="executorch_llama"
   export SURAKSHA_EXECUTORCH_MODEL_PATH="models/llama3_8b.pte"
   ```
4. **Fallback Behavior:**
   If ExecuTorch is not installed or the model file is absent, `Advisor` automatically falls back to the local template engine (`local_template`), ensuring zero runtime crashes.

---

## 12. Offline Operation Instructions

SurakshaEdge AI is **100% offline-first**:
- No external HTTP requests are made during threat detection or URL analysis.
- URLs are parsed safely using `urllib.parse` without sending network requests to the target host.
- Local threat intelligence matches against `data/url_threat_intel.csv`.
- SQLite storage operates locally (`surakshaedge.db`).

---

## 13. Security & Privacy Behaviour

- **Local Storage Privacy:** Raw message text, full URLs, and network payloads are **never saved** to disk by default. Only SHA-256 content hashes, detector types, risk scores, and redacted evidence are persisted.
- **Log Sanitization:** Sensitive credentials, passwords, OTPs, PINs, phone numbers, and emails are scrubbed before writing to logs.
- **SSRF Defense:** Prevents SSRF attacks by rejecting private IPs (10.x, 192.168.x, 172.16.x), loopback (`localhost`, `127.0.0.1`), link-local (`169.254.x`), and cloud metadata endpoints (`169.254.169.254`).
- **Deserialization Safety:** Loads `joblib` artifacts strictly from the trusted local `models/` directory with optional SHA-256 checksum verification.

---

## 14. Performance Benchmarking

Run the built-in CPU latency benchmark:

```bash
python scripts/benchmark.py
```

Typical performance on CPU hardware:
- **Startup / Import Latency:** ~180 ms
- **Warm Inference Latency:** ~7–12 ms per request

---

## 15. Troubleshooting

- **`ModuleNotFoundError`:** Ensure your virtual environment is active (`source .venv/bin/activate` or `.venv\Scripts\Activate.ps1`).
- **Missing Models Warning:** Run `python scripts/generate_sample_data.py && python train_models.py --allow-overwrite` to train local demo models.
- **Port Already in Use:** Change the port in `.env` or set `SURAKSHA_PORT=8005 python app.py`.

---

## 16. Limitations

- **Research Prototype:** This project is a defensive research prototype and does not provide an absolute security guarantee.
- **Heuristic Boundaries:** Detection is based on trained demo models and transparent heuristics; advanced evasion techniques may require periodic retraining on real threat data.

---

## 17. Testing Commands

Execute the automated test suite with `pytest`:

```bash
# Run all unit and integration tests
python -m pytest -q

# Run end-to-end smoke test script
python scripts/smoke_test.py
```

---

## 18. Research Data & Dataset Disclaimer

> **IMPORTANT NOTICE:** All datasets generated by `scripts/generate_sample_data.py` and pre-packaged under `data/` are synthetic demo datasets created exclusively for functional verification and testing of the SurakshaEdge AI pipeline. They must **NOT** be represented as real-world research corpora or production threat intelligence.
