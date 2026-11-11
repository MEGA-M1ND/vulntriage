import json
import tempfile

import streamlit as st
from dotenv import load_dotenv

from vulntriage.graph.workflow import build_graph

load_dotenv()
st.title("VulnTriage – Operator Console")
up = st.file_uploader("Upload Trivy JSON scan", type="json")
facing = st.checkbox("Asset is internet-facing")
crit = st.select_slider("Asset criticality", options=[1, 2, 3], value=2)
if up and st.button("Triage"):
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as t:
        t.write(up.getvalue())
    asset = json.loads(up.getvalue()).get("ArtifactName", "unknown")
    state = build_graph().invoke({"scan_path": t.name, "asset_context": {asset: {"internet_facing": facing, "criticality": crit}}})
    st.dataframe([f.model_dump(include={"risk_score", "cve", "package", "kev", "epss", "remediation", "needs_review"}) for f in state["findings"][:10]])
    for f in [f for f in state["findings"] if f.needs_review]:
        st.warning(f"Needs senior review: {f.cve} – {f.remediation}")
