# 02 — Anomaly Detection on Network Traffic

**Domain**: Unsupervised ML / Network Intrusion Detection  
**Status**: Planned  
**Techniques**: Isolation Forest, Autoencoders, LSTM on packet sequences

---

## Problem Statement

Signature-based IDS (Snort, Suricata) fail against zero-day attacks and APTs. Anomaly detection learns "normal" network behavior and flags deviations — critical for detecting unknown threats.

This project implements three complementary approaches:
1. **Statistical** — Isolation Forest on flow features (fast, interpretable)
2. **Deep learning** — LSTM Autoencoder on packet sequences (temporal patterns)
3. **Hybrid** — Ensemble of both with feedback loop for analyst labeling

---

## Architecture

```
NetFlow / PCAP Input
    ├── Feature Engineering ─────────┐
    │   └── bytes/sec, duration, flags│
    │                                 ├── Isolation Forest (real-time)
    ├── Flow-level Features ─────────┤   └── Anomaly Score
    │                                 ├── LSTM Autoencoder (batch)
    └── Sequence Features ───────────┘   └── Reconstruction Error
```

## Dataset

- **NSL-KDD** (standardized version of KDD Cup 1999)
- **CICIDS2017** (modern, realistic traffic with labeled attacks)

## Interview Talking Points

**Q: How do you handle concept drift in network traffic?**  
A: Retrain autoencoder weekly on sliding window. Isolation Forest updated incrementally. Drift detection via KL-divergence between feature distributions.

**Q: False positive rate in production?**  
A: Network anomaly is inherently noisy. We cluster anomalies and prioritize by: (1) rarity of feature combination, (2) severity of deviation, (3) time-of-day anomaly. FP rate target: <2% of flows.

## Metrics Target

| Metric | Target |
|--------|--------|
| AUC-ROC | >0.92 |
| Detection Rate (DR) | >85% |
| False Positive Rate | <2% |

---

## License
MIT
