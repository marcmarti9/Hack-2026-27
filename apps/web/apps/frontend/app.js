// VIGÍA · web de la demo. Vistas por hash: #panel, #bandeja, #caso/<id>, #playbooks[/RB-xx], #mapa, #descartado, #chat
const $ = s => document.querySelector(s);
const api = p => fetch('/api/' + p).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
const post = (p, body, method = 'POST') => fetch('/api/' + p, {method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const severidades = {critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', informational: 'Informativa'};
const sev = s => `<span class="sev ${esc(s)}">${esc(severidades[s] || s || 'Sin evaluar')}</span>`;
const enlace = (vista, id) => `#${vista}/${encodeURIComponent(id)}`;
const fmt = n => Number(n || 0).toLocaleString('de-DE');   // 3.386 (es-ES no agrupa 4 cifras)
const hora = iso => iso ? new Date(iso).toLocaleString('es-ES', {timeZone: 'Europe/Madrid', weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'}) : '';
const VERDICTO = {true_positive: 'Ataque real', benign_true_positive: 'Actividad autorizada', false_positive: 'Falso positivo',
  false_negative: 'Falso negativo', true_negative: 'Verdadero negativo', needs_more_info: 'Falta información'};
const veredicto = v => VERDICTO[v] || v || 'Sin veredicto';
const confianza = n => typeof n === 'number' && Number.isFinite(n) ? `${Math.round(n * 100)} % de confianza` : 'Sin estimación de confianza';
const disposicion = d => ({close: 'Cierre recomendado', review: 'Revisión humana', escalate: 'Escalar a N2',
  automatic: 'Cierre automático registrado', accepted: 'Aceptada por el analista', corrected: 'Corregida por el analista'})[d] || d;
const mensajeError = j => typeof j.detail === 'string' ? j.detail : 'Revisa los datos y vuelve a intentarlo.';
const CONTENCIONES = ['isolate_host', 'disable_user', 'revoke_sessions', 'reset_password', 'block_ioc', 'purge_email', 'disable_access_key'];
const ACCION = {isolate_host: 'Aislar equipo', disable_user: 'Deshabilitar cuenta', revoke_sessions: 'Revocar sesiones', reset_password: 'Forzar cambio de contraseña',
  block_ioc: 'Bloquear indicador', purge_email: 'Purgar correo', disable_access_key: 'Desactivar clave cloud', escalar_dpo: 'Escalar al DPO', escalar_operaciones: 'Escalar a Operaciones'};
const MOTIVO = {waf_bloqueado: 'Escaneos de Internet bloqueados por el WAF', newsletter: 'Newsletters legítimas reportadas por error', sccm: 'Inventario de SCCM (cambio aprobado CHG-2026-1031)',
  viaje_dispositivo: 'Viajes con dispositivo corporativo conocido', dominio_corporativo: 'Software corporativo conocido', spam_sin_clic: 'Spam sin clics: purgado y remitente bloqueado',
  cdn: 'Subdominios de CDN y nube', sap: 'Excel abriendo SAP (firmado)', vela_cliente: 'Clientes de Vela corrigiendo su pedido', edr_bloqueado: 'Software no deseado bloqueado por el EDR',
  dns_seguridad: 'Consultas de antivirus y DNSBL', stuffing_sin_exito: 'Credential stuffing sin accesos correctos', spray_sin_exito: 'Password spraying sin accesos correctos',
  terraform: 'Cambios de terraform desde el CI', pentest: 'Pentest autorizado (CHG-2026-1042)', nessus: 'Escáner NESSUS01 en su ventana', paquete_conocido: 'Paquetes npm conocidos',
  ot_autorizado: 'ENG-WS01 hablando con OT (autorizado)', cambio_aprobado: 'Dentro de un cambio aprobado', psexec_jump: 'PsExec desde JUMP01 (CHG-2026-1057)',
  nominas: 'Nóminas a la gestoría (flujo aprobado)', ot_mantenimiento: 'Mantenimiento del clasificador (CHG-2026-1063)', dlp_sin_datos: 'Subidas sin datos personales'};
const rol = () => $('#rol').value;
try { $('#rol').value = localStorage.getItem('vigia_rol') || 'N2'; } catch (e) {}
$('#rol').onchange = () => { try { localStorage.setItem('vigia_rol', rol()); } catch (e) {} ruta(); };

const menuToggle = $('#plegar-menu');
function setMenuCollapsed(collapsed) {
  document.body.classList.toggle('menu-plegado', collapsed);
  menuToggle.setAttribute('aria-expanded', String(!collapsed));
  menuToggle.title = collapsed ? 'Desplegar menú' : 'Plegar menú';
  menuToggle.querySelector('span').textContent = menuToggle.title;
}
try { setMenuCollapsed(localStorage.getItem('vigia_menu_plegado') === '1'); } catch {}
menuToggle.onclick = () => {
  const collapsed = menuToggle.getAttribute('aria-expanded') === 'true';
  setMenuCollapsed(collapsed);
  try { localStorage.setItem('vigia_menu_plegado', collapsed ? '1' : '0'); } catch {}
};

const tarjetaCaso = t => `<a class="caso" href="${enlace('caso', t.ticket_id)}" style="display:block;color:inherit;text-decoration:none">
  <div class="meta">${sev(t.severity)} <span>${confianza(t.confidence)}</span>
    ${t.out_of_hours ? '<span>· fuera de horario</span>' : ''} ${t.manipulation_detected?.detected ? '<span class="warn">· ⚠ intento de engaño</span>' : ''}
    ${t.human_review ? '<span class="warn">· revisar</span>' : ''}</div>
  <div class="t">${esc(t.title)}</div><p>${esc(veredicto(t.verdict))}${t.alert_id ? ` · ${esc(t.alert_id)}` : ''}
    ${t.alert_ids?.length ? ` · ${t.alert_ids.length} alerta(s)` : ''}${t.primera ? ` · desde ${esc(hora(t.primera))}` : ''}</p>
    ${t.disposition ? `<p>${esc(disposicion(t.disposition))}</p>` : ''}${t.triage_seconds != null ? `<small class="sub">${esc(t.triage_seconds)} s</small>` : ''}</a>`;

const vistas = {
  async panel() {
    const [r, ts, rg] = await Promise.all([api('resumen'), api('tickets'), api('rgpd')]);
    const graves = ts.filter(t => t.escalation?.escalate && ['critical', 'high'].includes(t.severity));
    $('#vista').innerHTML = `<section aria-labelledby="guardia-titulo">
      <div class="guardia-encabezado">
        <div><h2 id="guardia-titulo">Parte de guardia</h2><p class="sub">5 de octubre al 1 de noviembre de 2026</p></div>
        <div class="guardia-enlaces">
          <a class="prueba" href="#presentar">Recorrido para el jurado</a>
          <a class="prueba" href="#relevo">Relevo de guardia</a>
          <a class="guardia-cta" href="#directo">Analizar alertas <span aria-hidden="true">→</span></a>
        </div>
      </div>
      <dl class="guardia-metricas">
        <div><dt>Alertas del SIEM</dt><dd>${fmt(r.alertas)}</dd></div>
        <div><dt>Expedientes generados</dt><dd>${fmt(r.investigadas)}</dd></div>
        <div><dt>Cierres registrados</dt><dd>${fmt(r.cierres_ejecutados)}</dd></div>
        <div><dt>Escalados</dt><dd class="guardia-escaladas">${fmt(r.escaladas)}</dd></div>
      </dl>
      <p class="guardia-alcance">${r.corpus_completo
        ? `Barrido del dataset oficial · ${fmt(r.cerradas_por_reglas)} alertas aptas para cierre según las reglas.`
        : 'Expedientes y escalados de esta mesa.'}
        ${fmt(r.abstenciones)} sin evidencia suficiente para un veredicto.</p>
      <section class="guardia-casos">
        <h3>Casos graves escalados</h3>
        <div class="casos3">${graves.slice(0, 6).map(tarjetaCaso).join('') || '<p class="sub">Todavía no hay casos graves escalados en esta mesa.</p>'}</div>
      </section>
      <div class="dos guardia-bloques">
        <div class="tarjeta"><h3>Revisión de brechas por el DPO</h3>${rg.map(x => `<div class="reloj">
          <div><a class="prueba" href="${enlace('caso', x.ticket_id)}"><b>${esc(x.title)}</b></a><br><small>Alerta ${esc(hora(x.inicio))} · referencia +72 h ${esc(hora(x.limite))}<br>
          El DPO confirma si hubo brecha y cuándo se tuvo constancia.</small></div>
          <div class="h">${x.horas_sin_vigia > 0 ? esc(x.horas_sin_vigia) + ' h<br><small>hasta la apertura</small>' : '<small>SOC abierto</small>'}</div></div>`).join('') || '<p class="sub">Sin casos registrados para revisión por el DPO.</p>'}</div>
        <div class="tarjeta"><h3>Fuera del horario del SOC</h3>
          <p><strong class="guardia-fuera">${esc(Number(r.fuera_de_horario_total).toLocaleString('es-ES'))} %</strong> de las alertas del SIEM.</p>
          ${r.benchmark?.p50_ms != null ? `<p>Barrido local · mediana ${esc(r.benchmark.p50_ms)} ms y p95 ${esc(r.benchmark.p95_ms)} ms por alerta.</p>` : ''}
          <a class="prueba" href="#descartado">Ver alertas descartadas</a></div>
      </div>
    </section>`;
  },

  async bandeja() {
    const ts = await api('tickets');
    $('#vista').innerHTML = `<h2>Casos</h2><p class="sub">Ya investigados por VIGÍA, de más a menos grave. Tú decides.</p>
      <form class="botones" id="buscar-caso"><label>ID de alerta <input name="consulta" maxlength="80"></label><button>Buscar</button></form>
      <div class="casos3" id="resultados-caso">${ts.map(tarjetaCaso).join('') || '<p>Sin casos en esta mesa.</p>'}</div>`;
    $('#buscar-caso').onsubmit = async event => {
      event.preventDefault();
      const result = $('#resultados-caso');
      try {
        const casos = await api('tickets?q=' + encodeURIComponent(event.currentTarget.elements.consulta.value.trim()));
        result.innerHTML = casos.map(tarjetaCaso).join('') || '<p>Sin expedientes con ese ID.</p>';
      } catch { result.textContent = 'No se pudo completar la búsqueda.'; }
    };
  },

  async caso(id) {
    if (window._pbCaso !== id) { window._pbTab = 0; window._pbCaso = id; }
    const t = await api('tickets/' + encodeURIComponent(id)), inc = t.incidente;
    const informe = t.expediente, evidencias = informe?.evidence || t.evidence || [];
    const n2 = rol() !== 'N1';
    $('#vista').innerHTML = `<p class="sub"><a class="prueba" href="${informe && t.alert_id ? '#directo' : '#bandeja'}">← ${informe && t.alert_id ? 'Analizar en directo' : 'Casos'}</a></p>
      <h2>${esc(t.title)}</h2>
      <div class="meta" style="margin:6px 0 18px">${sev(t.severity)} <span>${esc(veredicto(t.verdict))}</span> <span>· ${confianza(t.confidence)}</span>
        <span>· ${t.alert_ids?.length || 1} alerta(s)</span> ${t.alert_id ? `<span class="mono">· ${esc(t.alert_id)}</span>` : ''} ${t.out_of_hours ? '<span>· empezó con el SOC cerrado</span>' : ''}
        <span>· escalado: ${esc(t.escalation?.escalate ? t.escalation.to : 'no')}</span></div>
      ${t.manipulation_detected?.detected ? `<div class="aviso"><b>El atacante intentó engañar a la IA.</b> ${esc(t.manipulation_detected.where)}<br>
        <small>VIGÍA lo trata como una prueba más contra el atacante.</small></div>` : ''}
      ${expedienteHTML(t)}
      <div class="dos">
        <div class="tarjeta"><h3>Qué ha pasado</h3><p>${esc(t.summary)}</p>
          <p class="sub" style="margin:0"><small>Severidad: ${esc(t.severity_rationale)}</small></p></div>
        <div class="tarjeta"><h3>Quién y qué está implicado</h3>${informe ? registroHTML(informe.affected) : ''}<div id="grafo"></div></div>
      </div>
      ${historiaHTML(t.linea) || (informe?.timeline?.length ? `<div class="tarjeta"><h3>Línea de tiempo</h3>
        ${(informe.alert_ids || []).length > 1 ? `<p class="sub">Alertas vinculadas · ${esc(informe.alert_ids.join(' · '))}</p>` : ''}
        ${informe.timeline.map(p => `<div class="paso"><b>${esc(hora(p.timestamp))}</b> · ${esc(p.source || p.stage)}${p.event_id ? ` · <button class="sec prueba mono" data-ev="${esc(p.event_id)}">${esc(p.event_id)}</button>` : ''}<br>${esc(p.finding)}</div>`).join('')}</div>` : '')}
      ${inc ? `<div class="aviso info"><b>A quién avisar (informe N2):</b> ${esc((inc.notifications || []).join(' · '))}</div>` : ''}
      ${(t.playbooks || []).length ? `<h3 class="seccion">Playbook aplicado <small class="suave">· lo que dice el procedimiento del SOC y lo que ya ha hecho VIGÍA</small></h3>${playbooksCasoHTML(t.playbooks, t.ticket_id)}` : ''}
      <div class="dos">
        <div class="tarjeta">${informe ? '' : `<h3>Cómo lo investigó VIGÍA</h3>${(t.trace || []).map(p => p.tipo === 'herramienta'
          ? `<div class="paso tool"><b>${esc(pasoTxt(p))}</b> <span class="mono suave">${esc(p.nombre)}</span></div>`
          : `<div class="paso">${esc(p.texto)}</div>`).join('')}`}
          <h3>Pruebas</h3>${evidencias.map(e => `<div class="paso"><button class="sec prueba mono" data-ev="${esc(e.event_id)}">${esc(e.event_id)}</button>
            · ${esc(e.source)}${e.relation ? ` · ${esc(e.relation)}${e.cited ? ' · citada' : ' · sin citar'}` : ''}<br><small>${esc(e.finding)}</small></div>`).join('') || '<p class="sub">Sin pruebas recuperadas.</p>'}
          <div id="evento" class="raw" hidden></div>
          ${informe?.declared_evidence && Object.keys(informe.declared_evidence).length ? `<details><summary>Evidencia declarada por el sensor</summary>${registroHTML(informe.declared_evidence)}</details>` : ''}</div>
        <div>
          ${informe ? '' : `<div class="tarjeta"><h3>La IA revisora (fiscal)</h3>${t.fiscal ? `<p class="${t.fiscal.agrees ? 'ok' : 'warn'}">${t.fiscal.agrees ? '✓ No ha podido tumbar el veredicto.' : '⚠ Tiene objeciones: decide el humano.'}</p>
            ${(t.fiscal.objections || []).map(o => `<div class="paso">${esc(o)}</div>`).join('')}<p class="sub"><small>${esc(t.fiscal.comment)}</small></p>` : '<p class="sub">Sin revisión registrada.</p>'}
            ${(t.open_questions || []).length ? `<h3>Lo que VIGÍA no sabe</h3>${t.open_questions.map(q => `<div class="paso">${esc(q)}</div>`).join('')}` : ''}</div>`}
          <div class="tarjeta"><h3>Acciones propuestas</h3><p class="sub"><small>Estás como <b>${esc(rol())}</b>.</small></p>
            <table>${(t.recommended_actions || []).map((a, i) => {
              return `<tr><td><b>${esc(ACCION[a.action] || a.action)}</b> <span class="mono">${esc(a.target)}</span><br><small class="sub">${esc(a.justification)}</small></td>
                <td><small class="warn">lo gestiona una persona</small></td></tr>`; }).join('')}</table>
            ${n2 && informe?.isolation_proposal ? aislamientoHTML(informe.isolation_proposal) : ''}
            <p id="resultado" role="status"></p>${(t.executed_actions || []).map(x => `<p class="sub"><b>${esc(x.target)}</b> · ${esc(x.result || x.status)} · ${esc(x.actor || x.approver)}</p>`).join('')}</div>
          ${decisionHTML(t)}
          <div class="tarjeta"><button id="reinv">Reinvestigar en directo</button> <button class="sec" id="dl-t">Descargar expediente</button> ${inc ? '<button class="sec" id="dl-i">Descargar informe N2</button>' : ''}</div>
        </div>
      </div>`;
    document.querySelectorAll('[data-ev]').forEach(el => el.onclick = async () => {
      const evento = $('#evento'); await mostrarEvento(el.dataset.ev, evento); evento.scrollIntoView({block: 'nearest'}); });
    if ($('#aislar-alerta')) activarAislamiento(t);
    const bajar = (url, nombre) => { const a = document.createElement('a'); a.href = url; a.download = nombre; a.click(); };
    $('#reinv').onclick = async () => {
      if (t.alert_id) { location.hash = enlace('directo/nueva', t.alert_id); return; }
      const r = await post('reinvestigar/' + encodeURIComponent(t.ticket_id), {}), j = await r.json();
      if (r.ok) location.hash = enlace('directo', j.trabajo);
      else $('#resultado').textContent = mensajeError(j);
    };
    $('#dl-t').onclick = () => {
      if (informe && t.alert_id) { bajar('/api/expediente/' + encodeURIComponent(t.alert_id), `${t.alert_id}.json`); return; }
      const {alertas, incidente, ...caso} = t;
      descargarRegistro(caso, t.ticket_id + '.json');
    };
    if (inc) $('#dl-i').onclick = () => descargarRegistro(inc, inc.incident_id + '.json');
    grafo(t); activarHistoria(); activarPlaybooks(); activarDecision(t);
  },

  async mapa() {
    const m = await api('mapa');
    const W = 1100, H = 700, BW = 240, BH = 150;
    const sitio = {'HQ-USERS': [40, 60], 'MAD-USERS': [40, 240], 'VPN-POOL': [40, 420], 'IDENTIDAD': [300, 60], 'CORREO': [300, 240],
      'DC-SERVERS': [560, 60], 'DEV': [560, 240], 'DMZ': [820, 60], 'AWS-PROD': [820, 240], 'STORES': [300, 420], 'LOGISTICS-IT': [560, 420],
      'LOGISTICS-OT': [820, 420], 'OTROS': [40, 600]};
    const nombre = {'HQ-USERS': 'Oficinas Barcelona', 'MAD-USERS': 'Oficina Madrid', 'VPN-POOL': 'VPN', 'IDENTIDAD': 'Identidad', 'CORREO': 'Correo',
      'DC-SERVERS': 'Servidores (CPD)', 'DEV': 'Desarrollo', 'DMZ': 'Tienda online (DMZ)', 'AWS-PROD': 'AWS', 'STORES': 'Tiendas', 'LOGISTICS-IT': 'Almacén Martorell',
      'LOGISTICS-OT': 'Red OT (clasificador)', 'OTROS': 'Otros'};
    const t0 = Date.parse('2026-10-04T22:00:00Z'), t1 = Date.parse('2026-11-01T23:00:00Z'), HORA = 3600e3;
    const cambio = Date.parse('2026-10-25T01:00:00Z');
    const local = ms => new Date(ms + (ms < cambio ? 2 : 1) * HORA);
    const cerradoEn = ms => { const l = local(ms), h = l.getUTCHours(), d = l.getUTCDay(); return d === 0 || d === 6 || h < 8 || h >= 20; };
    m.puntos.forEach(p => { p.t = Date.parse(p.ts); const s = sitio[p.zona] || sitio.OTROS, alto = p.zona === 'OTROS' ? 50 : BH - 50;
      p.x = s[0] + 14 + p.px * (BW - 28); p.y = s[1] + 38 + p.py * alto; });
    $('#vista').innerHTML = `<h2>Mapa de Tarvia</h2><p class="sub">Cuatro semanas de alertas, hora a hora. Las flechas rojas son el atacante moviéndose por la empresa.</p>
      <div class="mapa-ctrl"><button id="play">▶ Reproducir</button><input type="range" id="t" min="0" max="${(t1 - t0) / HORA}" value="125">
        <span id="reloj-mapa"></span></div>
      <svg id="svg" viewBox="0 0 ${W} ${H}" width="100%"></svg>
      <p class="sub"><small>● gris: cerrada por VIGÍA · ● rojo: escalada · ● naranja: pendiente · se ven las alertas de las últimas 24 h · pasa el ratón por una flecha para ver el caso</small></p>`;
    const svg = $('#svg');
    const pinta = () => {
      const ahora = t0 + $('#t').value * HORA, cerrado = cerradoEn(ahora);
      let cubiertas = 0; for (let x = t0; x <= ahora; x += HORA) if (cerradoEn(x)) cubiertas++;
      $('#reloj-mapa').innerHTML = local(ahora).toISOString().slice(0, 16).replace('T', ' ') + (cerrado ? ' · <span class="cerrado">SOC CERRADO · VIGÍA de guardia</span>' : ' · SOC abierto') +
        `<br><small class="sub">SOC cerrado: ${fmt(cubiertas)} h de vigilancia cubiertas por VIGÍA</small>`;
      const vis = m.puntos.filter(p => p.t <= ahora && p.t > ahora - 24 * HORA);
      const tramos = m.saltos.flatMap(s => s.camino.slice(1).map((c, i) => ({de: s.camino[i], a: c, title: s.title})).filter(x => Date.parse(x.a.ts) <= ahora));
      svg.innerHTML = `<defs><marker id="fl" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="#ff5c5c"/></marker></defs>
        <rect width="${W}" height="${H}" rx="12" fill="${cerrado ? '#050505' : '#111111'}"/>` +
        m.zonas.filter(z => sitio[z.zona]).map(z => { const [x, y] = sitio[z.zona], h = z.zona === 'OTROS' ? 80 : BH;
          return `<rect x="${x}" y="${y}" width="${z.zona === 'OTROS' ? 1020 : BW}" height="${h}" rx="10" fill="#161616" stroke="${cerrado ? '#1e1e1e' : '#2e2e2e'}"/>
          <text x="${x + 14}" y="${y + 24}" font-size="13" font-weight="600" fill="#f2f2f2">${esc(nombre[z.zona] || z.zona)}</text>`; }).join('') +
        vis.map(p => `<circle cx="${p.x}" cy="${p.y}" r="${p.estado === 'escalada' ? 5.5 : 2.6}" fill="${p.estado === 'escalada' ? '#ff5c5c' : p.estado === 'pendiente' ? '#ffa62b' : '#5e5e5e'}" opacity="${p.estado === 'escalada' ? 1 : .8}"/>`).join('') +
        tramos.map(({de, a, title}) => { const A = sitio[de.zona] || sitio.OTROS, B = sitio[a.zona] || sitio.OTROS;
          return `<g style="cursor:help"><title>${esc(title)}: ${esc(de.host)} → ${esc(a.host)}</title>
            <line x1="${A[0] + BW / 2}" y1="${A[1] + BH / 2}" x2="${B[0] + BW / 2}" y2="${B[1] + BH / 2}" stroke="#ff5c5c" stroke-width="10" opacity="0"/>
            <line x1="${A[0] + BW / 2}" y1="${A[1] + BH / 2}" x2="${B[0] + BW / 2}" y2="${B[1] + BH / 2}" stroke="#ff5c5c" stroke-width="2.5" marker-end="url(#fl)"/></g>`; }).join('');
    };
    $('#t').oninput = pinta; pinta();
    let timer = null;
    $('#play').onclick = () => { if (timer) { clearInterval(timer); timer = null; $('#play').textContent = '▶ Reproducir'; return; }
      $('#play').textContent = '⏸ Pausa'; timer = setInterval(() => { const s = $('#t'); s.value = (+s.value + 1) % (+s.max + 1); pinta(); }, 110); };
    window.addEventListener('hashchange', () => clearInterval(timer), {once: true});
  },

  async descartado() { await vistaDescartado(); },

  async playbooks(id) { await vistaPlaybooks(id); },

  async directo(jid) { await vistaMesaDirecto(jid); },

  async relevo() {
    const r = await api('relevo');
    $('#vista').innerHTML = `<h2>Relevo de guardia</h2><p class="sub">Expedientes guardados en el turno de guardia.</p>
      <div class="tarjeta parte"><b>${fmt(r.investigadas)} investigadas</b> · ${fmt(r.cierres)} cierres registrados · ${fmt(r.pendientes)} pendientes de revisión.</div>
      <h3>Escalados</h3><div class="casos3">${r.casos.map(t => `<div>${tarjetaCaso(t)}<p class="sub">${esc(t.responsables.join(' · '))}
        ${t.plazo ? ' · plazo ' + esc(hora(t.plazo)) : ''}</p></div>`).join('') || '<p>Analiza un lote en Guardia para ver aquí sus escalados.</p>'}</div>`;
  },

  presentar() {
    $('#vista').innerHTML = `<h2>Vigía en cuatro minutos</h2><p class="sub">Tarvia · Del dato a la decisión del SOC</p>
      <div class="tarjeta parte">El SOC recibe alertas también cuando el equipo está fuera de turno. Vigía cruza registros, inventario y cambios para preparar la decisión con sus evidencias.</div>
      <div class="casos3">
        <a class="caso" href="#panel"><div class="meta">01 · 30 s</div><div class="t">El turno completo</div><p>Parte de guardia, alertas y escalados del barrido.</p></a>
        <a class="caso" href="#caso/VIG-ALR-20261005-000301"><div class="meta">02 · 40 s</div><div class="t">Un cierre comprobable</div><p>SCCM, cambio autorizado y registros que explican el cierre.</p></a>
        <a class="caso" href="#caso/VIG-ALR-20261010-011795"><div class="meta">03 · 60 s</div><div class="t">Una cadena de preransomware</div><p>Abre la cronología y muestra cómo se vinculan las alertas.</p></a>
        <a class="caso" href="#directo"><div class="meta">04 · 90 s</div><div class="t">La alerta del jurado</div><p>Carga la entrada y sigue las fases del agente hasta el expediente.</p></a>
        <a class="caso" href="#relevo"><div class="meta">05 · 20 s</div><div class="t">Quién decide</div><p>Responsables y plazos de guardia en un solo lugar.</p></a>
      </div>`;
  },

  chat() {
    $('#vista').innerHTML = `<h2>Pregúntale a VIGÍA</h2><p class="sub">Responde con datos de los logs y cita los eventos.</p>
      <div class="tarjeta"><input type="text" id="q" placeholder="Ej.: ¿Qué hizo marta.puig? · ¿Qué pasó en WMS01? · ¿Quién es ext.logisoft?"><div id="resp"></div></div>`;
    $('#q').focus();
    $('#q').onkeydown = async e => { if (e.key !== 'Enter' || !e.target.value.trim()) return;
      $('#resp').innerHTML = '<p class="sub">Consultando…</p>';
      const r = await post('chat', {pregunta: e.target.value}).then(r => r.json());
      $('#resp').innerHTML = `<p>${esc(r.respuesta).replace(/\n/g, '<br>')}</p>` + (r.pasos || []).map(p => `<div class="paso tool"><b>${esc(p.herramienta)}</b> <span class="mono">${esc(JSON.stringify(p.entrada))}</span></div>`).join(''); };
  },
};

function grafo(t) {
  const el = $('#grafo');
  if (!window.cytoscape) { el.innerHTML = '<p style="padding:14px" class="sub">El grafo necesita conexión a Internet para cargar.</p>'; return; }
  const nodos = new Map(), aristas = [];
  const add = (id, tipo) => id && nodos.set(id, {data: {id, label: id, tipo}});
  (t.alertas || []).forEach(a => {
    const E = a.entities || {}, ids = [];
    (E.users || []).forEach(u => { add(u.upn, 'usuario'); ids.push(u.upn); });
    (E.hosts || []).forEach(h => { add(h.hostname, 'equipo'); ids.push(h.hostname); });
    (E.ips || []).slice(0, 4).forEach(i => { add(i, 'ip'); ids.push(i); });
    (E.domains || []).forEach(d => { add(d, 'dominio'); ids.push(d); });
    (E.customers || []).slice(0, 4).forEach(c => { add(c.customer_id, 'cliente'); ids.push(c.customer_id); });
    if (E.cloud?.identity) { add(E.cloud.identity, 'cloud'); ids.push(E.cloud.identity); }
    ids.filter(Boolean).slice(1).forEach(x => aristas.push({data: {id: a.alert_id + x, source: ids[0], target: x}}));
  });
  cytoscape({container: el, elements: [...nodos.values(), ...aristas], layout: {name: 'cose', animate: false},
    style: [{selector: 'node', style: {label: 'data(label)', color: '#f2f2f2', 'font-size': 10, 'background-color': '#86BC25', 'text-valign': 'bottom', 'text-margin-y': 4}},
            {selector: 'node[tipo="ip"], node[tipo="dominio"]', style: {'background-color': '#ff5c5c'}},
            {selector: 'node[tipo="usuario"]', style: {'background-color': '#ffa62b'}},
            {selector: 'edge', style: {width: 1.5, 'line-color': '#3a3a3a', 'curve-style': 'bezier'}}]});
}

async function ruta() {
  const [v, raw, prefill] = (location.hash.slice(1) || 'panel').split('/');
  document.querySelectorAll('nav a').forEach(a => {
    const current = a.getAttribute('href') === '#' + (v === 'caso' ? 'bandeja' : v);
    a.classList.toggle('activo', current);
    if (current) {
      a.setAttribute('aria-current', 'page');
      if (a.parentElement.scrollWidth > a.parentElement.clientWidth) {
        a.scrollIntoView({block: 'nearest', inline: 'nearest'});
      }
    } else {
      a.removeAttribute('aria-current');
    }
  });
  try {
    if (v === 'directo' && raw === 'nueva') await vistaMesaDirecto(undefined, decodeURIComponent(prefill || ''));
    else await (vistas[v] || vistas.panel)(raw && decodeURIComponent(raw));
    window.scrollTo(0, 0);
  }
  catch (e) { $('#vista').innerHTML = `<p>No se pudo cargar (${esc(e.message)}). ¿Está arrancado el backend y has ejecutado el orquestador?</p>`; }
}
api('estado').then(s => {
  const status = $('#demo');
  $('#proveedor').innerHTML = s.openai_disponible ? 'OpenAI<span class="shell-connection"> disponible</span>' : 'Motor local';
  status.title = s.openai_disponible ? 'OpenAI disponible' : 'Motor local';
  $('#modelo').textContent = s.openai_disponible ? s.modelo : '';
  status.classList.toggle('vivo', s.openai_disponible);
  status.hidden = false;
}).catch(() => {});
window.onhashchange = ruta; ruta();
