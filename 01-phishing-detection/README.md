# 01 — Phishing Detection Engine

**Domain**: NLP / Email Security  
**Status**: In Progress  
**Techniques**: BERT fine-tuning, TF-IDF + ensemble, URL lexical features

---

## Problem Statement

Phishing accounts for ~36% of all data breaches (Verizon DBIR 2023). Enterprises lose $4.9M per breach on average. Traditional rule-based filters miss polymorphic phishing that mutates URLs, uses homoglyphs, and social-engineers content.

This project builds a multi-modal phishing detector that combines:
1. **Text analysis** — Email body + subject NLP (BERT sentiment + intent classification)
2. **URL analysis** — Lexical + host-based features (age, reputation, SSL)
3. **Ensemble scoring** — Stacked classifier combining fast heuristics with deep model confidence

---

## Architecture

```
Email Input
    ├── Text Pipeline (BERT-base) ──┐
    │   └── [CLS] token → Phishing/Not   │
    │                                  ├── Ensemble (XGBoost)
    ├── URL Pipeline (Random Forest) ──┤   └── Final Score 0-1
    │   └── lexical + host features    │
    └── Heuristic Rules ──────────────┘
```

---

## Dataset

- **Primary**: Enron + Public Phishing Corpus (reproducible synthetic augmentation)
- **Augmentation**: Back-translation, synonym replacement (controlled to preserve semantic integrity)
- **Ethical note**: No real user emails; synthetic labels verified by pattern matching

---

## Key Files

| File | Purpose |
|------|---------|
| `src/data_preprocessing.py` | Text cleaning, URL extraction, tokenization |
| `src/text_model.py` | BERT fine-tuning pipeline |
| `src/url_features.py` | URL lexical + host feature engineering |
| `src/ensemble.py` | Stacked classifier training & inference |
| `src/api.py` | FastAPI serving endpoint |
| `tests/` | Unit tests for all modules |

---

## Interview Talking Points

**Q: Why BERT over simpler models?**  
A: Contextual embeddings capture semantic intent ("verify your account" vs. "your account statement"). Static embeddings miss polysemy. We use DistilBERT for 40% faster inference with <2% accuracy drop.

**Q: How do you handle adversarial phishing?**  
A: URL obfuscation (punycoding, IDN homoglyphs) — we normalize Unicode and flag suspicious TLDs. For text, we include adversarial training examples (character-level perturbations) during fine-tuning.

**Q: False positive impact?**  
A: In email, FPs block legitimate business. We tune threshold to target <0.5% FP rate at 95% recall, and use human-in-the-loop for borderline cases (score 0.4-0.7).

---

## Running It

```bash
cd 01-phishing-detection
python -m src.train_text_model --epochs 3 --batch_size 16
python -m src.train_ensemble --text_model outputs/bert_model
python -m src.api  # serves on localhost:8000
```

## Metrics Target

| Metric | Target | Rationale |
|--------|--------|-----------|
| Accuracy | >97% | Standard for phishing benchmarks |
| Precision@95% Recall | >92% | Business cost of FPs > FNs in most cases |
| Inference Latency | <50ms | Real-time email gateway requirement |
| F1 Score | >94% | Balanced metric for imbalanced data |

---

## License
MIT
