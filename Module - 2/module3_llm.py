import pandas as pd
import numpy as np
import requests
import json
import os
import time

# ─────────────────────────────────────────
# SET YOUR PROJECT FOLDER
# ─────────────────────────────────────────
os.chdir(r"C:\Users\madha\OneDrive\LLM IN SECURITY PROJECT")
print("Working directory:", os.getcwd())


# ─────────────────────────────────────────
# STEP 1: Load flagged anomalies from Module 2
# ─────────────────────────────────────────
df = pd.read_csv("flagged_anomalies.csv")
print(f"Loaded {len(df)} flagged anomalies")

# Work on top 50 most suspicious rows only
df_top = df.head(50).copy()
print(f"Processing top {len(df_top)} most suspicious rows\n")


# ─────────────────────────────────────────
# STEP 2: Severity scoring
# Combines anomaly score + attack type + port
# ─────────────────────────────────────────
CRITICAL_ATTACKS = ["ddos", "ransomware", "mitm"]
HIGH_ATTACKS     = ["backdoor", "scanning", "dos"]
MEDIUM_ATTACKS   = ["injection", "password", "xss"]
CRITICAL_PORTS   = [22, 23, 53, 443, 3389, 8080]

def calculate_severity(row):
    score       = float(row["anomaly_score"])
    attack_type = str(row["type"]).lower().strip()
    dst_port    = int(row["dst_port"]) if str(row["dst_port"]).isdigit() else 0

    if score > 0.35 or attack_type in CRITICAL_ATTACKS:
        return "CRITICAL"
    elif score > 0.25 or attack_type in HIGH_ATTACKS:
        return "HIGH"
    elif score > 0.15 or attack_type in MEDIUM_ATTACKS:
        return "MEDIUM"
    elif dst_port in CRITICAL_PORTS:
        return "HIGH"
    else:
        return "LOW"

df_top["severity"] = df_top.apply(calculate_severity, axis=1)

print("Severity distribution across top 50 alerts:")
print(df_top["severity"].value_counts())
print()


# ─────────────────────────────────────────
# STEP 3: Attack-specific context + behavior
# hints for each attack type
# ─────────────────────────────────────────
ATTACK_PROFILES = {
    "ddos": {
        "name"    : "Distributed Denial of Service (DDoS)",
        "context" : "volumetric flood attack overwhelming network resources",
        "behavior": "Look for extremely high packet counts, large src_bytes, short duration bursts targeting a single destination.",
        "risk"    : "Can bring down network infrastructure and disrupt all connected IoT devices."
    },
    "dos": {
        "name"    : "Denial of Service (DoS)",
        "context" : "single-source attack disrupting service availability",
        "behavior": "Look for high connection rate from one source, repeated failed connection states.",
        "risk"    : "Disrupts availability of targeted IoT services and connected systems."
    },
    "backdoor": {
        "name"    : "Backdoor Attack",
        "context" : "unauthorized persistent remote access attempt",
        "behavior": "Look for unusual outbound connections on ports 4444, 1234 or non-standard ports with sustained duration.",
        "risk"    : "Allows attacker persistent control over the compromised IoT device."
    },
    "scanning": {
        "name"    : "Network Scanning / Reconnaissance",
        "context" : "systematic port and network reconnaissance activity",
        "behavior": "Look for sequential port connections, many short-duration connections to different destinations.",
        "risk"    : "Reconnaissance is typically the first phase before a targeted attack."
    },
    "injection": {
        "name"    : "Injection Attack",
        "context" : "SQL or command injection exploiting input vulnerabilities",
        "behavior": "Look for unusual payload sizes in HTTP traffic, abnormal request patterns.",
        "risk"    : "Can compromise backend systems, databases, and expose sensitive IoT data."
    },
    "password": {
        "name"    : "Password Brute Force",
        "context" : "repeated credential attack targeting authentication services",
        "behavior": "Look for many repeated connections to port 22 (SSH) or 23 (Telnet) with short durations.",
        "risk"    : "Successful credential compromise gives full device access."
    },
    "ransomware": {
        "name"    : "Ransomware",
        "context" : "file encryption malware spreading across the network",
        "behavior": "Look for unusual file transfer volumes, connections to unknown external IPs, high dst_bytes.",
        "risk"    : "Can encrypt critical IoT operational data and demand ransom for restoration."
    },
    "xss": {
        "name"    : "Cross-Site Scripting (XSS)",
        "context" : "script injection targeting web interfaces of IoT devices",
        "behavior": "Look for unusual HTTP request patterns with abnormal payload sizes.",
        "risk"    : "Can hijack IoT device web interfaces and steal session credentials."
    },
    "mitm": {
        "name"    : "Man-in-the-Middle (MitM)",
        "context" : "traffic interception between two communicating devices",
        "behavior": "Look for ARP anomalies, unusual relay patterns, duplicate flows between devices.",
        "risk"    : "All communications between devices may be intercepted and modified."
    },
    "normal": {
        "name"    : "Anomalous Normal Traffic",
        "context" : "legitimate traffic with unusual characteristics",
        "behavior": "Look for unusually high byte volumes or long durations that deviate from baseline.",
        "risk"    : "May indicate data exfiltration disguised as normal traffic or misconfigured device."
    }
}

def get_attack_profile(attack_type):
    key = str(attack_type).lower().strip()
    return ATTACK_PROFILES.get(key, ATTACK_PROFILES["normal"])


# ─────────────────────────────────────────
# STEP 4: Build combined severity-aware
# attack-specific prompt for each row
# ─────────────────────────────────────────
def build_prompt(row):
    profile  = get_attack_profile(row["type"])
    severity = row["severity"]

    # Severity-specific instruction tone
    urgency = {
        "CRITICAL": "This is a CRITICAL threat requiring IMMEDIATE action.",
        "HIGH"    : "This is a HIGH severity threat requiring prompt investigation.",
        "MEDIUM"  : "This is a MEDIUM severity alert requiring scheduled review.",
        "LOW"     : "This is a LOW severity anomaly for logging and monitoring."
    }.get(severity, "Review this alert.")

    prompt = f"""You are a senior IoT network security analyst. Analyze the following network alert and produce a structured threat report.

ALERT INFORMATION:
- Source Device IP   : {row['src_ip']}
- Source Port        : {row['src_port']}
- Destination IP     : {row['dst_ip']}
- Destination Port   : {row['dst_port']}
- Protocol           : {row['proto']}
- Service            : {row['service']}
- Connection State   : {row['conn_state']}
- Bytes Sent         : {row['src_bytes']}
- Bytes Received     : {row['dst_bytes']}
- Duration           : {row['duration']:.2f} seconds
- Anomaly Score      : {row['anomaly_score']} (higher = more suspicious)
- Detected Type      : {profile['name']}
- Attack Context     : {profile['context']}
- Severity Level     : {severity}

ANALYST GUIDANCE:
{profile['behavior']}
Risk: {profile['risk']}
{urgency}

Write the threat report in EXACTLY this format, no extra text:

THREAT TYPE: {profile['name']}
SEVERITY: {severity}
BEHAVIOR: [2 sentences describing what this device is doing and why it is suspicious based on the traffic data above]
RISK REASON: [1 sentence explaining why the anomaly score and traffic pattern confirm this as a {severity} threat]
ACTION: [1 specific recommended action for the security team]"""

    return prompt


# ─────────────────────────────────────────
# STEP 5: Call Mistral via Ollama API
# ─────────────────────────────────────────
def call_mistral(prompt, retries=3):
    url     = "http://localhost:11434/api/generate"
    payload = {
        "model"  : "mistral",
        "prompt" : prompt,
        "stream" : False,
        "options": {
            "temperature": 0.3,
            "num_predict": 350
        }
    }

    for attempt in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=120)
            if response.status_code == 200:
                return response.json().get("response", "").strip()
            else:
                print(f"  API error {response.status_code}, retrying...")
        except requests.exceptions.Timeout:
            print(f"  Timeout on attempt {attempt+1}, retrying...")
        except requests.exceptions.ConnectionError:
            print("  Cannot connect to Ollama.")
            print("  Open a new terminal and run: ollama serve")
            return None
        time.sleep(2)

    return "LLM analysis unavailable after retries"


# ─────────────────────────────────────────
# STEP 6: Process each flagged row
# ─────────────────────────────────────────
print("Starting LLM analysis...")
print("Each row takes ~20-40 seconds on CPU.")
print("Total estimated time: 20-30 minutes.")
print("Do NOT close this terminal.\n")

results = []

for idx, (_, row) in enumerate(df_top.iterrows()):
    print(f"[{idx+1}/{len(df_top)}] {row['src_ip']} → {row['dst_ip']} "
          f"| {row['type'].upper()} | {row['severity']} "
          f"| Score: {row['anomaly_score']}")

    prompt   = build_prompt(row)
    response = call_mistral(prompt)

    results.append({
        "src_ip"        : row["src_ip"],
        "src_port"      : row["src_port"],
        "dst_ip"        : row["dst_ip"],
        "dst_port"      : row["dst_port"],
        "proto"         : row["proto"],
        "service"       : row["service"],
        "conn_state"    : row["conn_state"],
        "src_bytes"     : row["src_bytes"],
        "dst_bytes"     : row["dst_bytes"],
        "duration"      : row["duration"],
        "attack_type"   : row["type"],
        "anomaly_score" : row["anomaly_score"],
        "severity"      : row["severity"],
        "true_label"    : row["label"],
        "llm_report"    : response
    })

    time.sleep(1)

print("\nLLM analysis complete!")


# ─────────────────────────────────────────
# STEP 7: Save results
# ─────────────────────────────────────────
df_results = pd.DataFrame(results)
df_results.to_csv("llm_threat_reports.csv", index=False)
print(f"\nSaved {len(df_results)} threat reports → llm_threat_reports.csv")


# ─────────────────────────────────────────
# STEP 8: Print sample reports
# ─────────────────────────────────────────
print("\n" + "="*60)
print("           SAMPLE THREAT REPORTS")
print("="*60)

for _, row in df_results.head(3).iterrows():
    print(f"\nDevice     : {row['src_ip']} → {row['dst_ip']}")
    print(f"Attack Type: {row['attack_type'].upper()}")
    print(f"Severity   : {row['severity']}")
    print(f"Score      : {row['anomaly_score']}")
    print("-"*40)
    print(row["llm_report"])
    print("="*60)

# Summary statistics
print("\n--- SEVERITY SUMMARY ---")
print(df_results["severity"].value_counts())
print("\n--- ATTACK TYPE SUMMARY ---")
print(df_results["attack_type"].value_counts())
print("\nModule 3 complete — ready for Streamlit dashboard!")
