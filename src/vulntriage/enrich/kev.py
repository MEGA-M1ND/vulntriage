import httpx

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev() -> set[str]:
    r = httpx.get(URL, timeout=60)
    r.raise_for_status()
    return {v["cveID"] for v in r.json().get("vulnerabilities", [])}
