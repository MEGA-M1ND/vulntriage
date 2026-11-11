import json
from pathlib import Path

from ..models import Finding


def parse_trivy(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    asset = data.get("ArtifactName", "unknown")
    seen, out = set(), []
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            key = (v.get("VulnerabilityID"), v.get("PkgName"))
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                id=f"{key[0]}:{key[1]}", cve=v.get("VulnerabilityID"), package=v.get("PkgName"),
                installed_version=v.get("InstalledVersion"), fixed_version=v.get("FixedVersion"),
                severity=v.get("Severity", "UNKNOWN"), title=v.get("Title", ""), asset=asset,
                cvss=(v.get("CVSS", {}).get("nvd", {}) or {}).get("V3Score"),
            ))
    return out
