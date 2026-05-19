# 05 — Vulnerability Scanner Assistant

**Domain**: NLP + Static Analysis  
**Status**: Planned  
**Techniques**: CodeBERT for vulnerability detection, AST analysis, OWASP mapping, CVSS scoring

---

## Problem Statement

SAST tools (Semgrep, SonarQube) find syntax-level bugs but miss semantic vulnerabilities (e.g., custom auth bypasses). LLM + static analysis hybrid combines precise AST paths with semantic understanding of vulnerable patterns.

## Architecture

```
Source Code Input
    ├── AST Parsing (tree-sitter) ─────────┐
    │   └── Control & Data Flow Graphs     │
    │                                      ├── CodeBERT + GNN
    ├── Code Tokenization ─────────────────┤   └── Vulnerability Class
    │   └── Function-level chunks          │
    └── OWASP Knowledge Base ──────────────┘   └── CVSS Score + Fix Suggestion
```

## Interview Talking Points

**Q: How is this different from Semgrep?**  
A: Semgrep uses regex + AST patterns — great for known CVEs. Our model generalizes to novel patterns by learning semantic representations of "unsafe" code. Complementary: we use Semgrep rules as training data augmentation.

**Q: False positives in code analysis?**  
A: Major issue — flagging sanitization routines as vulnerable. We use data flow analysis to verify taint propagation. No alert without confirmed source→sink path.

## Metrics Target

| Metric | Target |
|--------|--------|
| Precision | >80% |
| Recall (Top-10 CWEs) | >75% |
| Mean Fix Suggestion Relevance | >3.5/5 (human rated) |

---

## License
MIT
