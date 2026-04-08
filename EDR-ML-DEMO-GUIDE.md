# EDR + Traffic Analyzer + Response Controller Demo Guide

This guide shows how to demonstrate that:

1. The 8 role-based EDR agents are running
2. They collect runtime telemetry
3. Telemetry is centralized in the collector
4. The traffic analyzer applies rule-based detection and ML-based detection
5. The response controller receives alerts and records actions

Use this as a viva/demo checklist.

---

## 1. Start the Stack

Run:

```powershell
cd d:\FINAL_YEAR\fypmodif-main
docker compose -f docker-compose.sdp.yml up -d
```

Optional status check:

```powershell
docker compose -f docker-compose.sdp.yml ps
```

What this proves:

- The full environment is up
- Backend, monitor, response controller, ML engine, and EDR containers are available

---

## 2. Prove the 8 EDR Role Containers Exist

Run:

```powershell
docker ps --format "table {{.Names}}\t{{.Status}}" | findstr edr-
```

What to show:

- `edr-admin-workstation`
- `edr-doctor-workstation`
- `edr-nurse-workstation`
- `edr-receptionist-workstation`
- `edr-labtech-workstation`
- `edr-pharmacist-workstation`
- `edr-accountant-workstation`
- `edr-patient-terminal`

What this proves:

- The 8 EDR role endpoints are deployed
- Each role has its own telemetry-producing agent

---

## 3. Prove Telemetry Is Being Centralized

Run:

```powershell
curl.exe http://localhost:9090/telemetry
```

What to show in the JSON:

- `hostId`
- `userRole`
- `userEmail`
- `processes`
- `files`
- `network`
- `logs`
- `dbActivity` if present

What this proves:

- The EDR agents are collecting runtime telemetry
- The telemetry is being sent to the centralized collector on port `9090`

---

## 4. Keep Real-Time Outputs Visible

Open 2 extra terminals.

Terminal 1:

```powershell
docker logs -f hospital-monitor
```

Terminal 2:

```powershell
docker logs -f hospital-response-controller
```

What this shows:

- `hospital-monitor` displays traffic analyzer activity and alerts
- `hospital-response-controller` displays received alerts and response actions

What this proves:

- The pipeline is working in real time, not just via stored data

---

## 5. Prove the ML Engine Is Running

Run:

```powershell
curl.exe http://localhost:5000/health
```

What to show:

- `rf_loaded: true`
- `status: healthy`
- `features`
- `rf_threshold`

What this proves:

- The ML model is loaded
- The ML inference service is active

---

## 6. Prove Direct ML Prediction Works

Run:

```powershell
curl.exe -X POST http://localhost:5000/predict -H "Content-Type: application/json" -d "{\"hostId\":\"demo-host\",\"userRole\":\"doctor\",\"userEmail\":\"doctor@hospital.com\",\"network\":{\"bytes_sent\":900000,\"bytes_recv\":5000,\"duration\":15,\"packets_per_sec\":450},\"processes\":[{\"pid\":1},{\"pid\":2},{\"pid\":3}],\"files\":[{\"type\":\"SUSPICIOUS_FILE\"}],\"logs\":[{\"type\":\"SECURITY_EVENT\",\"message\":\"auth failed multiple times\"}],\"dbActivity\":{\"alerts\":[{\"type\":\"DB_BULK_DATA_READ\"}],\"activeQueries\":4}}"
```

What to show:

- `classification`
- `is_anomaly`
- `anomaly_score`
- `confidence`
- `model_scores`

What this proves:

- The ML engine can classify telemetry independently
- The anomaly detector is active

---

## 7. Prove Rule-Based Detection via a Ransomware-Style Trigger

Create a suspicious file inside one role container:

```powershell
docker exec edr-pharmacist-workstation sh -c "touch /tmp/demo.locked"
```

Then check centralized telemetry:

```powershell
curl.exe http://localhost:9090/telemetry
```

What to show:

- the relevant `hostId`
- file activity with suspicious extension such as `.locked`

At the same time, point to Terminal 1:

```powershell
docker logs -f hospital-monitor
```

Expected visible proof:

- ransomware-related alert or suspicious file detection

Then point to Terminal 2:

```powershell
docker logs -f hospital-response-controller
```

Expected visible proof:

- response action handling

What this proves:

- EDR collected runtime file activity
- telemetry reached the collector
- traffic analyzer applied a rule-based detection
- response controller received the alert

---

## 8. Prove Response Actions Are Persisted

Run:

```powershell
curl.exe http://localhost:4100/isolations
```

What to show:

- entries with:
  - `hostId`
  - `action`
  - `reason`
  - `ts`

Examples:

- `isolate`
- `restrict`
- `revoke_tokens`

What this proves:

- The response controller is not only printing logs
- It is persisting response actions

---

## 9. Prove the Five Rule-Based Detection Families

In `traffic-analyzer.js`, the main rule families are:

1. Exfiltration
2. Role access violation
3. Ransomware indicator
4. Brute force attempt
5. Database activity alerts

What to say:

"The traffic analyzer applies five rule-based detectors over centralized telemetry: exfiltration, role violation, ransomware indicators, brute-force behavior, and suspicious database activity."

Best proof during demo:

- Show monitor logs while triggering one of these, especially ransomware or role violation
- Explain the remaining rule families are implemented in the analyzer code and can be triggered similarly

---

## 10. Prove Rule + ML Together

Watch the monitor logs:

```powershell
docker logs -f hospital-monitor
```

What to look for:

- `ML_ANOMALY`
- `ML_RULE_CORRELATED`

What this means:

- `ML_ANOMALY`: ML detected suspicious behavior
- `ML_RULE_CORRELATED`: both the rule engine and ML engine flagged the same telemetry item

Then check:

```powershell
curl.exe http://localhost:4100/isolations
```

What this proves:

- The analyzer can use rule-based detection alone
- The analyzer can use ML-based detection alone
- When both agree, the system escalates confidence and response

---

## 11. Best Order for Live Demo

Run these in order:

1. `docker compose -f docker-compose.sdp.yml up -d`
2. `docker ps --format "table {{.Names}}\t{{.Status}}" | findstr edr-`
3. `curl.exe http://localhost:9090/telemetry`
4. `curl.exe http://localhost:5000/health`
5. Open:
   - `docker logs -f hospital-monitor`
   - `docker logs -f hospital-response-controller`
6. Run direct ML `/predict`
7. Trigger ransomware-style suspicious file:
   - `docker exec edr-pharmacist-workstation sh -c "touch /tmp/demo.locked"`
8. Show monitor logs
9. Show response controller logs
10. Show `curl.exe http://localhost:4100/isolations`

---

## 12. Viva Summary

Use this explanation:

"The 8 EDR agents simulate hospital roles and collect real runtime telemetry such as processes, files, network, logs, and database activity. That telemetry is sent to the centralized collector on port 9090. The traffic analyzer then processes it using five rule-based detections plus the ML engine. If suspicious behavior is confirmed, the response controller records and executes containment actions, which can be seen in the live logs and in `/isolations`."

