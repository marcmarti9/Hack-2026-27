"""Agrupa alertas en incidentes: dos alertas van juntas si comparten una entidad poco común en <= 10 días."""
import json, collections
from datetime import datetime, timedelta

def entidades(a):
    E, out = a.get("entities", {}), set()
    for h in E.get("hosts", []):  out.add(("host", h.get("hostname", "").lower()))
    for u in E.get("users", []):
        v = u.get("upn", "").lower()
        if "@" in v: out.add(("user", v.split("@")[0]))
    for i in E.get("ips", []):    out.add(("ip", i))
    for d in E.get("domains", []): out.add(("domain", d.lower()))
    for f in E.get("files", []):
        if f.get("sha256"): out.add(("hash", f["sha256"]))
    c = E.get("cloud", {})
    for k in ("identity", "new_user", "access_key"):
        if c.get(k): out.add(("cloud", c[k].lower()))
    if E.get("ai_session"): out.add(("session", E["ai_session"]))
    ev = a.get("evidence", {})
    for k in ("message_id", "src_ip", "dst_ip", "submitted_from_ip", "created_from_ip", "sender"):
        if isinstance(ev.get(k), str) and ev[k]: out.add((k.replace("submitted_from_", "").replace("created_from_", ""), ev[k].lower()))
    # Campañas: misma regla + mismo patrón (ATO con el mismo dominio de correo temporal, phishing con el mismo asunto)
    if a["rule_id"] == "UC-WEB-003": out.add(("campaña", "ato:" + str(ev.get("new_email_domain"))))
    if a["rule_id"].startswith("UC-EML") and ev.get("subject"): out.add(("campaña", "asunto:" + ev["subject"].lower()))
    return out

def agrupar(alertas, todas, max_dias=10, max_freq=25):
    freq = collections.Counter(e for a in todas for e in entidades(a))
    padre = {a["alert_id"]: a["alert_id"] for a in alertas}
    def raiz(x):
        while padre[x] != x: padre[x] = padre[padre[x]]; x = padre[x]
        return x
    por_ent = collections.defaultdict(list)
    for a in alertas:
        for e in entidades(a):
            if freq[e] <= max_freq: por_ent[e].append(a)
    t = lambda a: datetime.fromisoformat(a["created_at"].replace("Z", ""))
    for e, xs in por_ent.items():
        xs.sort(key=t)
        for x, y in zip(xs, xs[1:]):
            if t(y) - t(x) <= timedelta(days=max_dias): padre[raiz(y["alert_id"])] = raiz(x["alert_id"])
    grupos = collections.defaultdict(list)
    for a in alertas: grupos[raiz(a["alert_id"])].append(a)
    return sorted(grupos.values(), key=lambda g: min(x["created_at"] for x in g))

if __name__ == "__main__":
    import sys
    from pathlib import Path
    from apps.backend.rules.engine import Contexto, decidir
    D = Path(sys.argv[1]); ctx = Contexto(D)
    A = [json.loads(l) for l in open(D / "03_alertas/alertas.jsonl", encoding="utf-8")]
    rest = [a for a in A if not decidir(ctx, a)]
    G = agrupar(rest, A)
    print(len(rest), "alertas ->", len(G), "grupos")
    for g in G:
        if len(g) > 1 or g[0]["severity"] in ("high", "critical"):
            print(len(g), g[0]["created_at"][:10], sorted(collections.Counter(a["rule_id"] for a in g).items()))
