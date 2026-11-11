from typing import TypedDict

from ..models import Finding


class TriageState(TypedDict, total=False):
    scan_path: str
    findings: list[Finding]
    asset_context: dict[str, dict]  # asset -> {"internet_facing": bool, "criticality": 1-3}
    errors: list[str]
