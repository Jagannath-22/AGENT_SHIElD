# AgentShield

AgentShield is an autonomous host-defense agent that senses kernel/network behavior, reasons over it with hybrid ML + signature detection, and acts without human-in-the-loop for immediate containment.

## Why This Is An Agent (Not Just A Script)

A normal project executes fixed steps and exits.

An agent continuously runs a closed control loop:

1. Sense: collect telemetry
2. Think: build context + infer risk
3. Decide: choose a policy action
4. Act: enforce and record outcomes
5. Learn/Adapt: update metrics, drift state, and runtime config

In this repository, that loop is explicitly implemented in [agentshield/runtime/agent_runtime.py](agentshield/runtime/agent_runtime.py).

## The Exact Code That Makes It Agentic

- Agent loop orchestrator: [agentshield/runtime/agent_runtime.py](agentshield/runtime/agent_runtime.py)
- Sensor (kernel/user telemetry): [agentshield/collector/collector.py](agentshield/collector/collector.py)
- Context and feature reasoning: [agentshield/feature_engine/features.py](agentshield/feature_engine/features.py)
- ML reasoning: [agentshield/ml_engine/model.py](agentshield/ml_engine/model.py)
- Signature reasoning: [agentshield/signature_engine/signatures.py](agentshield/signature_engine/signatures.py)
- Decision policy: [agentshield/decision_engine/decision.py](agentshield/decision_engine/decision.py)
- Autonomous action/response: [agentshield/response_engine/response.py](agentshield/response_engine/response.py)
- Runtime adaptation via config reload: [agentshield/config/settings.py](agentshield/config/settings.py)


## Agentic Flow (Explained for Viva / College Demo)

AgentShield is agentic because it continuously runs a closed loop and can take action without a manual operator.

- **Sense**: Collector streams telemetry (eBPF when available, synthetic fallback otherwise).
- **Think**: Feature engine builds behavior windows; ML model scores anomaly; signature engine checks known threat patterns.
- **Decide**: Decision engine applies threshold/policy and outputs `allow` / `alert` / `kill`.
- **Act**: Response engine executes containment and writes forensic incident records.
- **Adapt**: Config manager can reload policy at runtime; model can be retrained from fresh telemetry.

This maps directly to:
- Agent loop orchestrator: `agentshield/runtime/agent_runtime.py`
- Sensing: `agentshield/collector/collector.py`
- Thinking: `agentshield/feature_engine/features.py`, `agentshield/ml_engine/model.py`, `agentshield/signature_engine/signatures.py`
- Deciding: `agentshield/decision_engine/decision.py`
- Acting: `agentshield/response_engine/response.py`

## End-to-End Training + Tuning (Local + Public Dataset)

### 1) Generate local telemetry baseline

```bash
timeout 35s python main.py
```

### 2) Retrain on local telemetry features

```bash
python -m agentshield.ml_engine.retrain --prefer auto --min-samples 50
```

### 3) Convert CIC/public CSV into AgentShield feature JSONL

```bash
python -m agentshield.ml_engine.dataset_converter   --input-csv path/to/cic.csv   --output-jsonl agentshield/logs/public_eval.jsonl   --dataset-name cic_ids2017   --label-column Label
```

### 4) Evaluate the model on labeled data

```bash
python -m agentshield.ml_engine.evaluate   --dataset agentshield/logs/public_eval.jsonl   --label-key __is_attack
```

### 5) Tune threshold (important for low false positives)

```bash
python -m agentshield.ml_engine.tune_threshold   --dataset agentshield/logs/public_eval.jsonl   --label-key __is_attack   --max-fpr 0.10
```

Use the suggested threshold in `agentshield/config/config.yaml` (`anomaly_threshold`).

## Architecture

- eBPF BCC path (fallback-compatible): [agentshield/ebpf](agentshield/ebpf)
- eBPF CO-RE libbpf path (ring buffer): [agentshield/ebpf_core](agentshield/ebpf_core)
- Collector: [agentshield/collector](agentshield/collector)
- Feature engine: [agentshield/feature_engine](agentshield/feature_engine)
- ML engine: [agentshield/ml_engine](agentshield/ml_engine)
- Signature engine: [agentshield/signature_engine](agentshield/signature_engine)
- Decision engine: [agentshield/decision_engine](agentshield/decision_engine)
- Response engine: [agentshield/response_engine](agentshield/response_engine)
- Dashboard: [agentshield/dashboard/app.py](agentshield/dashboard/app.py)
- Config: [agentshield/config/config.yaml](agentshield/config/config.yaml)

## WSL Ubuntu Local Run

### 1. Install Ubuntu packages

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool gcc make
```

### 2. Create and activate venv

```bash
cd /mnt/c/Users/Jagannath\ sahoo/Desktop/PROJECTS/AgentShield
python3 -m venv .venv-wsl
source .venv-wsl/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Run AgentShield

```bash
python main.py
```

If kernel hooks are unavailable, AgentShield automatically falls back to synthetic telemetry mode.

### 4. Run dashboard

```bash
streamlit run agentshield/dashboard/app.py
```

## CO-RE Build (Optional)

```bash
cd agentshield/ebpf_core
make
```

Then set in [agentshield/config/config.yaml](agentshield/config/config.yaml):

```yaml
use_core_ebpf: true
```

## Config-Driven Runtime

All behavior is controlled from [agentshield/config/config.yaml](agentshield/config/config.yaml).

Important keys:

- anomaly_threshold
- kill_process
- whitelisted_processes
- protected_pids
- use_core_ebpf
- signature_rules
- core_ebpf

## Quick Smoke Test

```bash
python -m compileall agentshield main.py
python main.py
```

Check generated logs:

- [agentshield/logs/agentshield.jsonl](agentshield/logs/agentshield.jsonl)
- [agentshield/logs/metrics.jsonl](agentshield/logs/metrics.jsonl)
- [agentshield/logs/incidents.jsonl](agentshield/logs/incidents.jsonl)

## Model Retraining

AgentShield uses an Isolation Forest anomaly model and supports retraining from local logs.

### One-command retrain

```bash
python -m agentshield.ml_engine.retrain --prefer auto --min-samples 50
```

This command:

1. Loads feature rows from incidents (`agentshield/logs/incidents.jsonl`) and raw events (`agentshield/logs/agentshield.jsonl`)
2. Picks the richer source (or one you force via `--prefer`)
3. Exports the final retraining dataset to `agentshield/logs/retrain_dataset.jsonl`
4. Retrains and saves the model at `agentshield/ml_engine/isolation_forest.joblib`

### Useful options

```bash
python -m agentshield.ml_engine.retrain --prefer incidents --min-samples 100
python -m agentshield.ml_engine.retrain --prefer events --contamination 0.03
python -m agentshield.ml_engine.retrain --export-dataset agentshield/logs/my_dataset.jsonl
```

## RAG / Retrieve / Remember

Current repository state:

- No vector database or embedding-based retrieval pipeline is implemented yet.
- No long-term memory module exists beyond JSONL log history.

What is available now:

- Structured event and incident history in `agentshield/logs/*.jsonl`
- Retraining from those logs via the retrain CLI above

If needed, a retrieval layer can be added later (for example: embed incident summaries and retrieve nearest historical matches during decisioning).
