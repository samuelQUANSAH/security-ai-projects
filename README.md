# Security AI Projects

A curated collection of production-grade AI/ML security projects built for real-world application and technical interview defense.

Each project is a self-contained, end-to-end system with:
- Clean architecture & modular code
- Training pipelines & reproducible experiments
- Evaluation metrics & benchmark results
- Interview-ready talking points & design rationale

---

## Projects

| # | Project | Domain | Status |
|---|---------|--------|--------|
| 1 | [Phishing Detection Engine](./01-phishing-detection/) | NLP / Email Security | In Progress |
| 2 | [Anomaly Detection on Network Traffic](./02-network-anomaly/) | Unsupervised ML / NIDS | Planned |
| 3 | [Malware Classification with CNN](./03-malware-cnn/) | Deep Learning / Static Analysis | Planned |
| 4 | [AI-Powered SIEM Log Intelligence](./04-siem-intelligence/) | LLM / Log Analysis | Planned |
| 5 | [Vulnerability Scanner Assistant](./05-vuln-scanner/) | NLP + Static Analysis | Planned |

---

## Tech Stack

- **Languages**: Python 3.11+
- **ML/DL**: PyTorch, scikit-learn, Transformers (HuggingFace)
- **LLMs**: LangChain, LangGraph, OpenAI / local models via Ollama
- **Data**: pandas, numpy, SQLite, BigQuery
- **Infra**: Docker, GitHub Actions CI/CD, FastAPI
- **Cloud**: Cloudflare Workers, R2, D1 (serverless deployment)

---

## Quick Start

```bash
git clone https://github.com/samuelQUANSAH/security-ai-projects.git
cd security-ai-projects
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

---

## Interview Defense Checklist

Every project includes:
1. **Problem Statement** — Why this matters in enterprise security
2. **Dataset & Preprocessing** — Real or synthetic data with ethical sourcing
3. **Model Architecture** — Diagrams and design trade-offs
4. **Training Strategy** — Hyperparameters, validation approach, reproducibility
5. **Evaluation** — Metrics, confusion matrices, ROC/AUC, business impact
6. **Deployment** — API, containerization, edge cases handled
7. **Limitations & Future Work** — Critical self-awareness interviewers love

---

## License

MIT
