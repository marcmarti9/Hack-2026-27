"""Dashboard (Streamlit).  Arranque:  streamlit run frontend/app.py"""
import os

import requests
import streamlit as st

BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000")
ICON = {"red": "🔴", "yellow": "🟡", "green": "🟢", None: "⚪"}
VERDICT = {"true_positive": "TP · ataque real", "benign_true_positive": "BTP · legítimo/autorizado",
           "false_positive": "FP · falsa alarma", "undetermined": "Duda · revisión humana"}

st.set_page_config(page_title="Vigía · Tarvia Group", layout="wide")


def api(method: str, path: str, **kw):
    try:
        r = requests.request(method, BACKEND + path, timeout=120, **kw)
    except requests.RequestException as exc:
        st.error(f"No se pudo conectar con el backend ({BACKEND}): {exc}")
        st.stop()
    try:
        body = r.json()
    except ValueError:
        st.error(f"El backend devolvió una respuesta no válida (HTTP {r.status_code}).")
        return None
    if r.status_code >= 400:
        st.error(f"{r.status_code}: {body.get('detail', 'Error del backend')}")
        return None
    return body


st.title("Vigía · Triaje de alertas SOC")
health = api("GET", "/health")
if health:
    st.caption(f"Fuente de datos: **{health['soc_mode']}** · Juez: **{health['judge']}**"
               + (" · ⚠️ datos de ejemplo, no de Deloitte" if health["soc_mode"] == "fixture" else ""))

tab_queue, tab_case, tab_metrics = st.tabs(["Cola de alertas", "Expediente", "Resultados"])

with tab_queue:
    rows = api("GET", "/alerts") or []
    todo = [r["alert_id"] for r in rows if not r["processed"]]
    if st.button("Procesar todas las pendientes", disabled=not todo):
        bar = st.progress(0.0)
        failed = False
        for i, aid in enumerate(todo, 1):
            if api("POST", f"/alerts/{aid}/triage") is None:
                failed = True
            bar.progress(i / len(todo))
        if failed:
            rows = api("GET", "/alerts") or rows
        else:
            st.rerun()
    for r in rows:
        c1, c2, c3, c4, c5 = st.columns([1, 3, 3, 2, 2])
        c1.write(ICON[r["light"]])
        c2.write(r["alert_id"])
        c3.write(VERDICT.get(r["verdict"], "Sin procesar"))
        c4.write(r["severity"] or "—")
        c5.write(r["status"])

with tab_case:
    ids = [r["alert_id"] for r in rows if r["processed"]]
    if not ids:
        st.info("Procesa alguna alerta en la pestaña «Cola de alertas».")
    else:
        aid = st.selectbox("Alerta", ids)
        res = api("GET", f"/alerts/{aid}")
        if res:
            st.subheader(f"{ICON[res['light']]} {VERDICT[res['verdict']]}")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Confianza", f"{res['confidence']:.2f}")
            m2.metric("Prioridad", res["severity"] or "—")
            m3.metric("SLA", res["sla"] or "—")
            m4.metric("Tiempo agente", f"{res['processing_seconds']} s")
            st.text(res["summary"])
            for w in res["warnings"]:
                st.warning(w)
            if res["light"] == "yellow":
                st.markdown("**Motivos de la duda:** " + ", ".join(res["yellow_reasons"]))
                for m in res["missing_information"]:
                    st.text(f"• {m}")
                if res.get("ai_suggested_verdict"):
                    st.caption(f"El juez sugirió: {VERDICT[res['ai_suggested_verdict']]} (no concluyente)")

            t_ev, t_trace, t_act = st.tabs(["Evidencias", "Consultas", "Decisión humana"])
            with t_ev:
                for e in res["evidence"] or []:
                    st.text(f"{e['reference']} ({e['source']}) · {e['finding']}")
                if not res["evidence"]:
                    st.info("Sin evidencias suficientes.")
            with t_trace:
                for c in res["tool_trace"]:
                    mark = {"ok": "✅", "empty": "➖", "error": "❌"}[c["outcome"]]
                    st.text(f"{mark} Paso {c['step']} · {c['tool']} {c['params']} → {c['outcome']} ({c['duration_ms']} ms)"
                             + (f" — {c['error']}" if c["error"] else ""))
            with t_act:
                if res["status"] != "pending_human_review":
                    st.success(f"Estado: {res['status']}")
                    for d in res["human_decisions"]:
                        st.text(f"{d['reviewer']} · {d['action']} · {d['final_verdict'] or ''} · {d['comment'] or ''}")
                else:
                    reviewer = st.text_input("Analista", key="rev")
                    comment = st.text_input("Comentario", key="com")
                    final = st.selectbox("Veredicto final (para corregir/clasificar)",
                                         ["true_positive", "benign_true_positive", "false_positive"])
                    a1, a2, a3 = st.columns(3)
                    if res["light"] != "yellow" and a1.button("✔ Aceptar"):
                        if reviewer and api("POST", f"/alerts/{aid}/decision",
                                            json={"reviewer": reviewer, "action": "accept", "comment": comment}):
                            st.rerun()
                    if a2.button("✎ Corregir / clasificar"):
                        if reviewer and api("POST", f"/alerts/{aid}/decision", json={
                                "reviewer": reviewer, "action": "correct", "final_verdict": final, "comment": comment}):
                            st.rerun()
                    if a3.button("⬆ Escalar a N2"):
                        if reviewer and api("POST", f"/alerts/{aid}/decision",
                                            json={"reviewer": reviewer, "action": "escalate", "comment": comment}):
                            st.rerun()
                    if not reviewer:
                        st.caption("Indica tu nombre para registrar la decisión.")

                c = res.get("containment")
                if c:
                    st.divider()
                    st.markdown(f"**Contención propuesta (simulada):** `{c['operation']}` sobre `{c['target']}`")
                    if c["approved"]:
                        st.success("Contención aprobada y ejecutada (simulada).")
                    elif res["final_verdict"] == "true_positive":
                        approver = st.text_input("Analista que aprueba la contención", key=f"approver-{aid}").strip()
                        ok = st.checkbox("Apruebo expresamente esta contención", key=f"ok-cont-{aid}")
                        if st.button("Aprobar y ejecutar contención simulada", key=f"contain-{aid}",
                                     disabled=not (ok and approver)):
                            if api("POST", f"/alerts/{aid}/containment",
                                   json={"reviewer": approver, "confirm": True}):
                                st.rerun()
                    else:
                        st.info("El veredicto vigente bloquea la contención.")

with tab_metrics:
    m = api("GET", "/metrics")
    if m:
        c1, c2, c3 = st.columns(3)
        c1.metric("Alertas procesadas", m["processed"])
        c2.metric("Pendientes de revisión humana", m["pending_human_review"])
        c3.metric("Correcciones humanas", m["human_corrections"])
        st.write("Por color:", m["by_light"])
        st.write("Por estado:", m["by_status"])
        st.write("Tiempo medio del agente (s):", m["avg_processing_seconds"])
        st.caption(m["note"])
