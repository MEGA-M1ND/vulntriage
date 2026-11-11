import httpx

URL = "https://api.first.org/data/v1/epss"

def fetch_epss(cves: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for i in range(0, len(cves), 100):
        r = httpx.get(URL, params={"cve": ",".join(cves[i:i + 100])}, timeout=30)
        r.raise_for_status()
        scores.update({d["cve"]: float(d["epss"]) for d in r.json().get("data", [])})
    return scores
