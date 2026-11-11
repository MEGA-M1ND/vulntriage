from .models import Finding

SEV = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "UNKNOWN": 4.0}

def risk_score(f: Finding) -> float:
    """0-100. Weights are a starting point; tune them against evals/."""
    base = (f.cvss if f.cvss is not None else SEV.get(f.severity, 4.0)) / 10
    score = 40 * base + 30 * (f.epss or 0.0)
    score += 20 if f.kev else 0
    score += 5 if f.internet_facing else 0
    score += {1: 0, 2: 2.5, 3: 5}[f.asset_criticality]
    return round(min(score, 100), 1)
