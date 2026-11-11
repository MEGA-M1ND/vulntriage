from pathlib import Path

from vulntriage.parsers import parse_trivy
from vulntriage.scoring import risk_score

FIX = Path(__file__).parent / "fixtures" / "trivy_sample.json"

def test_parse_dedupes():
    fs = parse_trivy(FIX)
    assert len(fs) == 2 and fs[0].cvss == 10.0

def test_kev_boosts_risk():
    f = parse_trivy(FIX)[0]
    base = risk_score(f)
    f.kev = True
    assert risk_score(f) > base
