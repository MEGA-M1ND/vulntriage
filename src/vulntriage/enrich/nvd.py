import os

import httpx

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cvss(cve: str) -> float | None:
    headers = {"apiKey": k} if (k := os.getenv("NVD_API_KEY")) else {}
    r = httpx.get(URL, params={"cveId": cve}, headers=headers, timeout=30)
    if r.status_code != 200:
        return None
    try:
        m = r.json()["vulnerabilities"][0]["cve"]["metrics"]
        return m["cvssMetricV31"][0]["cvssData"]["baseScore"]
    except (KeyError, IndexError):
        return None
