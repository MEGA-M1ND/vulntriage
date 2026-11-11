# VulnTriage

AI-assisted vulnerability triage and remediation for small and mid-sized companies.
A non-expert operator plus an AI agent produces a prioritised, plain-English patch plan; a senior reviewer signs off.

## Pipeline (LangGraph)
1. **Parse** scanner output (Trivy JSON first; OpenVAS, Nessus, Qualys later)
2. **Enrich** with NVD (CVSS), FIRST EPSS, CISA KEV
3. **Context**: asset criticality, internet exposure, fix availability
4. **Rank** by real risk, not raw CVSS
5. **Remediate**: LLM-generated fix step + "why this matters"
6. **Review gate**: low-confidence items flagged for a human

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
trivy image --format json -o scan.json vulnerables/web-dvwa
vulntriage scan.json --out report.md
streamlit run app/streamlit_app.py
```

## Layout
- `src/vulntriage/parsers` – scanner parsers → common `Finding` model
- `src/vulntriage/enrich` – EPSS / KEV / NVD clients
- `src/vulntriage/graph` – LangGraph nodes and workflow
- `app/` – Streamlit operator UI
- `evals/` – expert-labelled cases and accuracy harness
- `docs/` – roadmap

## Guardrails
Public data and personal lab environments only. Recommend first; no automated patching in the MVP.
