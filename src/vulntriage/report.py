from .models import Finding


def to_markdown(findings: list[Finding], top_n: int = 10) -> str:
    lines = ["# Patch Plan", "", "| # | Risk | CVE | Package | KEV | EPSS | Action | Review |", "|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(findings[:top_n], 1):
        lines.append(f"| {i} | {f.risk_score} | {f.cve} | {f.package} | {'yes' if f.kev else ''} | "
                     f"{f.epss if f.epss is not None else '-'} | {f.remediation or '-'} | {'FLAG' if f.needs_review else ''} |")
    return "\n".join(lines) + "\n"
