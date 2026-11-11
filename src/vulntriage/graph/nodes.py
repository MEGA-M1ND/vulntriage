import json
import os

from ..enrich.epss import fetch_epss
from ..enrich.kev import fetch_kev
from ..parsers import parse_trivy
from ..scoring import risk_score
from .state import TriageState

THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.7"))

def parse(state: TriageState) -> TriageState:
    return {"findings": parse_trivy(state["scan_path"])}

def enrich(state: TriageState) -> TriageState:
    fs, errors = state["findings"], list(state.get("errors", []))
    cves = [f.cve for f in fs if f.cve and f.cve.startswith("CVE-")]
    try:
        epss = fetch_epss(cves)
    except Exception as e:  # keep going offline
        epss, _ = {}, errors.append(f"epss: {e}")
    try:
        kev = fetch_kev()
    except Exception as e:
        kev, _ = set(), errors.append(f"kev: {e}")
    for f in fs:
        f.epss, f.kev = epss.get(f.cve or ""), (f.cve in kev)
    return {"findings": fs, "errors": errors}

def add_context(state: TriageState) -> TriageState:
    ctx = state.get("asset_context", {})
    for f in state["findings"]:
        c = ctx.get(f.asset, {})
        f.internet_facing = c.get("internet_facing", False)
        f.asset_criticality = c.get("criticality", 2)
    return {"findings": state["findings"]}

def rank(state: TriageState) -> TriageState:
    for f in state["findings"]:
        f.risk_score = risk_score(f)
    return {"findings": sorted(state["findings"], key=lambda f: f.risk_score, reverse=True)}

PROMPT = """You are a vulnerability remediation advisor. For the finding below, reply in JSON with keys:
"remediation" (one concrete step a non-expert can run), "why_it_matters" (one plain-English sentence),
"confidence" (0-1, how sure you are the step is correct and safe).
Finding: {finding}"""

def _llm():
    if os.getenv("AZURE_OPENAI_ENDPOINT"):
        from langchain_openai import AzureChatOpenAI
        return AzureChatOpenAI(azure_deployment=os.environ["AZURE_OPENAI_DEPLOYMENT"], api_version="2024-08-01-preview")
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(model="gpt-4o-mini")

def remediate(state: TriageState, top_n: int = 10) -> TriageState:
    fs = state["findings"]
    llm = _llm().bind(response_format={"type": "json_object"})
    for f in fs[:top_n]:
        if f.fixed_version and not os.getenv("OPENAI_API_KEY") and not os.getenv("AZURE_OPENAI_ENDPOINT"):
            f.remediation, f.confidence = f"Upgrade {f.package} to {f.fixed_version}", 0.9
            continue
        out = json.loads(llm.invoke(PROMPT.format(finding=f.model_dump_json())).content)
        f.remediation, f.why_it_matters = out.get("remediation"), out.get("why_it_matters")
        f.confidence = float(out.get("confidence", 0))
    return {"findings": fs}

def review_gate(state: TriageState) -> TriageState:
    for f in state["findings"]:
        f.needs_review = f.remediation is not None and (f.confidence or 0) < THRESHOLD
    return {"findings": state["findings"]}
