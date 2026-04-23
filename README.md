# LLM-IOT-Security-Framework
LLM Enhanced Security Framework for IOT Networks - Anomaly detection and malicious device identification using Isolation Forest and Mistral 7B
# LLM-Enhanced Security Framework for IoT Networks
### Anomaly Detection and Malicious Device Identification

![Python](https://img.shields.io/badge/Python-3.14-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.56.0-red)
![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.8.0-orange)
![Mistral](https://img.shields.io/badge/LLM-Mistral%207B-purple)
![Dataset](https://img.shields.io/badge/Dataset-TON__IoT-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Overview

This project builds an end-to-end intelligent security framework for IoT networks that combines **machine learning anomaly detection** with **LLM-powered threat explanation** — a combination not explored in existing IoT security literature.

The system detects malicious devices, assigns severity levels (CRITICAL/HIGH/MEDIUM/LOW), generates plain-English threat explanations using Mistral 7B, and presents everything through a **real-time interactive security dashboard**.

> **Novel contribution:** While existing work applies ML/DL to IoT anomaly detection, no prior work uses LLMs to explain and interpret IoT network threats. This project fills that gap.

---

## Demo

![Dashboard Demo](assets/dashboard_screenshot.png)

---

## Architecture

```
TON_IoT Dataset (211,043 rows)
        ↓
Module 1: Data Preprocessing Pipeline
        ↓
Module 2: Isolation Forest Anomaly Detection
        ↓
Module 3: LLM Integration (Mistral 7B via Ollama)
        ↓
Module 4: Real-Time Streamlit Dashboard
```

---

## Key Results

| Metric | Value |
|---|---|
| Accuracy | 82.54% |
| Precision | 88.30% |
| Recall | 75.02% |
| F1 Score | 0.81 |
| False Alarm Rate | 9.94% |

---

## Features

- **Real-time alert streaming** — live IoT network monitoring simulation
- **LLM threat explanation** — Mistral 7B generates plain-English reports per alert
- **Severity scoring** — CRITICAL / HIGH / MEDIUM / LOW classification
- **Attack-specific prompts** — 10 tailored prompt templates for different attack types
- **Device risk profiling** — tracks each IP address across multiple alerts
- **Interactive dashboard** — built with Streamlit and Plotly
- **Fully local** — runs entirely on CPU, no GPU or cloud required

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.14 |
| Data processing | pandas, numpy |
| Anomaly detection | scikit-learn (Isolation Forest) |
| LLM runtime | Ollama |
| LLM model | Mistral 7B |
| Dashboard | Streamlit |
| Charts | Plotly |
| Dataset | TON_IoT (IEEE IoT Journal, 2021) |

---

## Project Structure

```
llm-iot-security-framework/
│
├── preprocessing.py          # Module 1: Data preprocessing pipeline
├── isolation_forest.py       # Module 2: Anomaly detection model
├── module3_llm.py            # Module 3: LLM integration
├── dashboard.py              # Module 4: Streamlit dashboard
│
├── assets/
│   └── dashboard_screenshot.png
│
├── requirements.txt          # All dependencies
└── README.md
```

---

## Installation and Setup

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com) installed

### Step 1 — Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/llm-iot-security-framework.git
cd llm-iot-security-framework
```

### Step 2 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 3 — Download Mistral model
```bash
ollama pull mistral
```

### Step 4 — Download the dataset
Download the TON_IoT Network dataset from [Kaggle](https://www.kaggle.com) and place the CSV file in the project folder.

### Step 5 — Run the pipeline

**Module 1 — Preprocess data:**
```bash
python preprocessing.py
```

**Module 2 — Train anomaly detector:**
```bash
python isolation_forest.py
```

**Module 3 — Generate LLM threat reports:**
```bash
# Make sure Ollama is running first
ollama serve

# Then in a new terminal:
python module3_llm.py
```

**Module 4 — Launch dashboard:**
```bash
streamlit run dashboard.py
```

Open your browser at `http://localhost:8501`

---

## How It Works

### Module 1 — Data Preprocessing
- Loads TON_IoT dataset (211,043 rows, 44 columns)
- Selects 17 relevant network flow features
- Fixes class imbalance via undersampling (100,000 balanced rows)
- Applies Label Encoding to categorical features
- Applies log transformation to skewed byte columns
- Scales features using StandardScaler
- Splits into 80/20 train/test sets

### Module 2 — Isolation Forest
- Trains exclusively on benign traffic (40,000 rows)
- Produces continuous anomaly score per connection
- Achieves 82.54% accuracy with 88% precision
- Saves 8,496 flagged suspicious connections

### Module 3 — LLM Integration
- Assigns severity using anomaly score + attack type + port
- Builds attack-specific prompts for 10 attack categories
- Sends top 50 most suspicious rows to Mistral 7B via Ollama
- Generates structured threat reports with behavior explanation and recommended action

### Module 4 — Dashboard
- Streams flagged rows live every 3 seconds
- Displays severity-coded alerts with timestamps
- Shows Mistral LLM explanations on alert selection
- Updates charts live (attack distribution, severity breakdown, score over time)
- Tracks device risk profile per IP address
  <img width="1904" height="829" alt="image" src="https://github.com/user-attachments/assets/fe84da5f-7b9c-4fab-91d5-879bd18c12a8" />
  <img width="1917" height="863" alt="image" src="https://github.com/user-attachments/assets/ba0ed255-61eb-4918-b397-521822bb2f37" />
  <img width="1910" height="868" alt="image" src="https://github.com/user-attachments/assets/b4196ad4-c620-4991-a4f3-704349de014d" />
  <img width="1430" height="667" alt="image" src="https://github.com/user-attachments/assets/6660f5a7-5c38-4267-8a54-8363674830a8" />
  <img width="1457" height="451" alt="image" src="https://github.com/user-attachments/assets/f9ff680c-eb5c-4ea4-8c28-62cd6cd5cf61" />



---

## Dataset

**TON_IoT** — Telemetry, Operating System, and Network IoT Dataset

Published by the University of New South Wales (UNSW) in the IEEE Internet of Things Journal (Moustafa et al., 2021). Contains real IoT network traffic with labeled attack categories.

Attack types: Normal, Backdoor, DDoS, DoS, Injection, Password, Ransomware, Scanning, XSS, MitM

---

## References

- Guntupalli, R. (2025). 5G and AI-powered cloud security. *IEEE AIMV 2025*
- Moustafa, N., et al. (2021). TON_IoT telemetry dataset. *IEEE IoT Journal*, 8(14)
- Mahmood, M. A. I., et al. (2025). LLM-enhanced security framework for IoT. *IEEE Access*, 13

---

## Author

**Janani Arunprasad**
Master's Student — Information Security and Privacy
University of Pittsburgh
JAA554@pitt.edu

---

## License

This project is licensed under the MIT License.
