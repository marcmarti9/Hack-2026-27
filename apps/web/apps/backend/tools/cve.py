"""CVE: cruza vulnerabilidades.csv con CISA KEV (explotadas de verdad) y EPSS (probabilidad de explotación)."""
import json
from apps.backend.config import ROOT
from apps.backend.tools import db

CACHE = ROOT / "data" / "cache"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="

def descargar():
    """Ejecutar UNA vez con Internet: guarda KEV y EPSS de nuestras CVE en data/cache/."""
    import requests
    CACHE.mkdir(parents=True, exist_ok=True)
    kev = requests.get(KEV_URL, timeout=30).json()
    (CACHE / "kev.json").write_text(json.dumps(kev), encoding="utf-8")
    cves = sorted({v["id"] for v in db._rows("SELECT id FROM vulns") if v["id"].startswith("CVE-")})
    epss = requests.get(EPSS_URL + ",".join(cves), timeout=30).json().get("data", [])
    (CACHE / "epss.json").write_text(json.dumps(epss), encoding="utf-8")
    print(f"KEV: {len(kev.get('vulnerabilities', []))} CVE | EPSS: {len(epss)} de {len(cves)} nuestras")

def _carga():
    kev = json.loads((CACHE / "kev.json").read_text(encoding="utf-8")) if (CACHE / "kev.json").exists() else {}
    epss = json.loads((CACHE / "epss.json").read_text(encoding="utf-8")) if (CACHE / "epss.json").exists() else []
    return {v["cveID"]: v for v in kev.get("vulnerabilities", [])}, {e["cve"]: e for e in epss}
KEV, EPSS = _carga()

def cve_de_equipo(host: str) -> list[dict]:
    a = db.asset(host)
    if not a:
        return []
    out = []
    for v in a["vulnerabilities"]:
        k, e = KEV.get(v["id"]), EPSS.get(v["id"])
        out.append({**v, "internet_facing": a.get("internet_facing"),
                    "kev": {"explotada": True, "desde": k.get("dateAdded"), "ransomware": k.get("knownRansomwareCampaignUse")} if k else {"explotada": False},
                    "epss": float(e["epss"]) if e else None,
                    "nota": "" if (k or e or not v["id"].startswith("CVE-")) else "sin datos externos (la CVE puede no existir públicamente)"})
    return out

if __name__ == "__main__":
    descargar()
