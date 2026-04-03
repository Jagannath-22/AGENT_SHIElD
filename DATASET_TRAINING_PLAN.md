# AgentShield Dataset and Training Strategy

## Short Answer

Yes, public datasets are useful, including CIC datasets.

But for this project's current model (unsupervised Isolation Forest over host/network behavior windows), the best training baseline is still your own benign environment data. Public datasets are best for stress-testing and threshold/signature tuning.

## How AgentShield Is Different from Firewall and IDS

Firewall:

- Rule-based allow/deny at network boundaries (IP, port, protocol, ACL)
- Prevents by policy, does not deeply reason about host process behavior

Traditional IDS:

- Mostly signature/rule matching or network anomaly at packet/flow level
- Good detection visibility, often alert-only (no local process-level response)

AgentShield (this repo):

- Host-level telemetry + behavior features + anomaly model + signatures + response actions
- Can reason from process context and enforce local action (alert/kill policy)
- Works as an autonomous closed loop (sense -> infer -> decide -> act)

## Is It Really Helpful and Scalable?

Helpful:

- Yes, especially for unknown behavior and host-local suspicious activity where pure network controls miss context
- Gives a second layer to firewall/IDS, not a replacement

Scalability impact:

- Yes, real impact is possible if deployed as a layered control with:
  1. strict rollback-safe response policy,
  2. central telemetry,
  3. staged rollout (observe -> alert -> enforce),
  4. continuous retraining and drift checks.

## Which Datasets for Which Attack Types

Use this as a practical mapping for evaluation and feature/signature calibration.

DoS / DDoS:

- CIC-DDoS2019
- CIC-IDS2017 (DoS/DDoS subsets)
- CSE-CIC-IDS2018

Brute force / credential abuse:

- CIC-IDS2017 (Brute Force)
- CSE-CIC-IDS2018

Botnet / C2 / reverse-shell-like traffic:

- CIC-IDS2017 (Botnet, Infiltration)
- CTU-13 (botnet scenarios)
- UNSW-NB15 (mixed modern attacks)

Port scanning / reconnaissance:

- CIC-IDS2017 (PortScan)
- UNSW-NB15

Web attacks (SQLi, XSS, command injection patterns):

- CIC-IDS2017 (Web Attack subsets)
- CSE-CIC-IDS2018

IoT-oriented attacks (if you target IoT endpoints):

- CICIoT2023
- TON_IoT

DNS abuse / tunneling behavior (if DNS feature set is expanded):

- CIC DNS datasets

## Is CIC Dataset Index Useful?

Yes. The CIC index is useful because it organizes datasets by domain and provides references to papers and generation methodology.

Important caveat:

- Use CIC data for benchmarking and tuning, but do not rely only on it for production training.
- Your local environment baseline and workload-specific telemetry are mandatory to reduce false positives.

## Best Training Approach for Current AgentShield Model

Current model uses these feature keys:

- connection_frequency
- unique_ip_count
- byte_transfer_rate
- interval_variance
- high_risk_port_ratio
- lineage_depth
- dns_resolution_ratio

Recommended pipeline:

1. Collect benign local telemetry first (long enough to represent normal workload).
2. Build retrain dataset from local logs.
3. Retrain model.
4. Replay/evaluate against public attack datasets converted to the same feature schema.
5. Tune thresholds and signatures.
6. Deploy in alert-only mode first, then controlled enforcement.

## What to Train with Public Internet Datasets vs Local Logs

Train baseline model weights:

- Primarily local benign data

Tune and validate detection behavior:

- Public datasets (CIC and others)

Calibrate response policy (kill/alert boundaries):

- Staged tests with attack subsets + safe sandbox validation

## Immediate Next Steps

1. Build a converter that maps selected public dataset rows/pcaps to AgentShield feature schema.
2. Create benchmark splits: benign baseline, mixed traffic, attack-specific subsets.
3. Track precision/recall/FPR and incident action quality before enabling aggressive response.

## Implemented in This Repo

The following utilities are now implemented:

1. Public dataset converter:

- `python -m agentshield.ml_engine.dataset_converter --input-csv <cic.csv> --output-jsonl agentshield/logs/public_eval.jsonl --dataset-name cic_ids2017`

2. Model evaluator:

- `python -m agentshield.ml_engine.evaluate --dataset agentshield/logs/public_eval.jsonl --label-key __is_attack`

3. Retrieval memory query:

- `python -m agentshield.runtime.query_memory --query "reverse shell 4444" --k 5`

## Metric Meaning (to know it is real, not random)

Use these together, not one metric alone:

- Precision: of all predicted attacks, how many are truly attacks.
- Recall (TPR): of all true attacks, how many you caught.
- FPR: of all benign samples, how many were wrongly flagged.
- FNR: of all attack samples, how many were missed.
- Accuracy: total correct / total samples.
- Balanced Accuracy: average of TPR and TNR, better when classes are imbalanced.

How to detect random-like behavior:

1. Compare model accuracy to majority-class baseline.
2. If model accuracy is only marginally above baseline (around <= baseline + 0.02), it is weak/random-like for that dataset.
3. If precision and recall both collapse while FPR remains high, threshold/features are poorly aligned.
4. Strong behavior usually means:

- materially above baseline accuracy,
- acceptable FPR for operations,
- recall high enough for your threat objective.

Practical target for this project:

- Keep FPR low enough to avoid killing benign processes.
- Prioritize recall for critical attacks (reverse-shell/DoS signatures).
- Use alert-only first, then enforce after stable metrics across multiple datasets.
