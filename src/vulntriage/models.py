from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    cve: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str = "UNKNOWN"
    title: str = ""
    asset: str = "unknown"
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    internet_facing: bool = False
    asset_criticality: int = Field(2, ge=1, le=3)  # 1 low, 3 high
    risk_score: float = 0.0
    remediation: str | None = None
    why_it_matters: str | None = None
    confidence: float | None = None
    needs_review: bool = False
