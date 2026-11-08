// VIGÍA · web de la demo. Vistas por hash: #panel, #bandeja, #caso/<id>, #playbooks[/RB-xx], #mapa, #descartado, #chat
const $ = s => document.querySelector(s);
const api = p => fetch('/api/' + p).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });
const post = (p, body) => fetch('/api/' + p, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
const sev = s => `<span class="sev ${s}">${s}</span>`;
const fmt = n => Number(n || 0).toLocaleString('de-DE');   // 3.386 (es-ES no agrupa 4 cifras)
const hora = iso => iso ? new Date(iso).toLocaleString('es-ES', {timeZone: 'Europe/Madrid', weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'}) : '';
const VERDICTO = {true_positive: 'Ataque real', benign_true_positive: 'Actividad autorizada', false_positive: 'Falsa alarma', needs_more_info: 'Falta información'};
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

function contar(el, hasta) {      // números que cuentan hacia arriba
  const t0 = performance.now(), dur = 900;
  const paso = t => { const k = Math.min(1, (t - t0) / dur); el.textContent = fmt(Math.round(hasta * (1 - Math.pow(1 - k, 3)))); if (k < 1) requestAnimationFrame(paso); };
  requestAnimationFrame(paso);
}
const tarjetaCaso = t => `<div class="caso" onclick="location.hash='caso/${t.ticket_id}'">
  <div class="meta">${sev(t.severity)} <span>${Math.round(t.confidence * 100)}% confianza</span>
    ${t.out_of_hours ? '<span>· fuera de horario</span>' : ''} ${t.manipulation_detected?.detected ? '<span class="warn">· ⚠ intento de engaño</span>' : ''}
    ${t.human_review ? '<span class="warn">· revisar</span>' : ''}</div>
  <div class="t">${esc(t.title)}</div><p>${esc(VERDICTO[t.verdict])} · ${t.alert_ids.length} alerta(s) · desde ${esc(hora(t.primera))}</p></div>`;

const vistas = {
  async panel() {
    const [r, ts, rg] = await Promise.all([api('resumen'), api('tickets'), api('rgpd')]);
    const reales = ts.filter(t => t.verdict === 'true_positive');
    const graves = reales.filter(t => ['critical', 'high'].includes(t.severity));
    const noche = graves.filter(t => t.out_of_hours).length;
    $('#vista').innerHTML = `<h2>Parte de guardia</h2><p class="sub">Del 5 de octubre al 1 de noviembre de 2026 · SOC de Tarvia</p>
      <div class="tarjeta parte">He revisado <b>${fmt(r.alertas)} alertas</b>. <b>${fmt(r.cerradas_por_reglas)}</b> eran ruido o actividad autorizada y las he cerrado con su motivo.
        He investigado las <b>${fmt(r.al_agente)}</b> restantes y las he agrupado en <b>${fmt(r.grupos)} casos</b>: ${reales.length} son ataques reales,
        <b>${graves.length} graves</b>, y ${noche} de ellos empezaron con el SOC cerrado. He detectado <b>${r.manipulaciones} intentos de engañar a la IA</b>
        y ${r.hallazgos_caza} actividades sospechosas que no generaron ninguna alerta. <b>Necesitas decidir en ${graves.length} casos.</b></div>
      <div class="embudo">
        <div class="paso-e"><b data-n="${r.alertas}">0</b><small>alertas del SIEM</small></div>
        <div class="paso-e"><b data-n="${r.cerradas_por_reglas}">0</b><small>cerradas con su explicación</small></div>
        <div class="paso-e"><b data-n="${r.al_agente}">0</b><small>investigadas por la IA</small></div>
        <div class="paso-e final"><b data-n="${r.grupos}">0</b><small>casos para el humano</small></div>
      </div>
      <h3>Los casos más graves</h3><div class="casos3">${graves.slice(0, 6).map(tarjetaCaso).join('') || '<p>Sin casos todavía: ejecuta el orquestador.</p>'}</div>
      <div class="dos" style="margin-top:16px">
        <div class="tarjeta"><h3>Reloj RGPD · 72 h para notificar a la AEPD</h3>${rg.map(x => `<div class="reloj">
          <div><b>${esc(x.title)}</b><br><small>Empieza ${esc(hora(x.inicio))} · límite ${esc(hora(x.limite))}<br>VIGÍA lo detectó en segundos.
          ${x.horas_sin_vigia > 0 ? `Sin VIGÍA, el SOC lo habría visto el ${esc(x.apertura_soc)}, perdiendo ${x.horas_sin_vigia} h del plazo.` : 'Ocurrió con el SOC abierto: VIGÍA lo entregó ya investigado al analista.'}</small></div>
          <div class="h">${x.horas_sin_vigia > 0 ? x.horas_sin_vigia + ' h<br><small style="font-size:11px;color:var(--suave)">ganadas</small>' : '<small style="font-size:12px;color:var(--suave)">SOC abierto</small>'}</div></div>`).join('') || '<p>Ninguna fuga de datos personales.</p>'}</div>
        <div class="tarjeta"><h3>Lo que el turno de noche no habría visto</h3>
          <p><b class="ok">${r.fuera_de_horario_al_agente}%</b> de lo que llega a la IA es de noche o fin de semana, frente al ${r.fuera_de_horario_total}% del total de alertas.</p>
          <p><b>${fmt(Math.round(r.cerradas_por_reglas * 15 / 60))} h</b> de analista ahorradas (15 min por alerta cerrada).</p>
          <p><a class="prueba" href="#descartado">Ver todo lo que he descartado y por qué →</a></p></div>
      </div>
      <div class="tarjeta listo"><h3>Listo para un SOC gestionado</h3><div class="listo-g">
        <div><b>Cualquier SIEM</b><small>Lee alertas en JSON: Splunk, Microsoft Sentinel, QRadar o Wazuh cambiando solo el conector.</small></div>
        <div><b>Vuestros procedimientos</b><small>Los runbooks del cliente se convierten en playbooks que VIGÍA aplica y deja auditados.</small></div>
        <div><b>El humano decide</b><small>Ninguna contención sin aprobación por rol; cada acción queda registrada con token.</small></div>
        <div><b>Multicliente</b><small>Un VIGÍA por cliente con su CMDB, su política y su calendario de cambios.</small></div></div></div>`;
    document.querySelectorAll('[data-n]').forEach(el => contar(el, +el.dataset.n));
  },

  async bandeja() {
    const ts = await api('tickets');
    $('#vista').innerHTML = `<h2>Casos</h2><p class="sub">Ya investigados por VIGÍA, de más a menos grave. Tú decides.</p>
      <div class="casos3">${ts.map(tarjetaCaso).join('') || '<p>Sin casos todavía: ejecuta el orquestador.</p>'}</div>`;
  },

  async caso(id) {
    if (window._pbCaso !== id) { window._pbTab = 0; window._pbCaso = id; }
    const t = await api('tickets/' + id), inc = t.incidente;
    const n2 = rol() !== 'N1';
    $('#vista').innerHTML = `<p class="sub"><a class="prueba" href="#bandeja">← Casos</a></p>
      <h2>${esc(t.title)}</h2>
      <div class="meta" style="margin:6px 0 18px">${sev(t.severity)} <span>${esc(VERDICTO[t.verdict])}</span> <span>· ${Math.round(t.confidence * 100)}% confianza</span>
        <span>· ${t.alert_ids.length} alerta(s)</span> ${t.out_of_hours ? '<span>· empezó con el SOC cerrado</span>' : ''}
        <span>· escalado: ${esc(t.escalation?.escalate ? t.escalation.to : 'no')}</span></div>
      ${t.manipulation_detected?.detected ? `<div class="aviso"><b>El atacante intentó engañar a la IA.</b> ${esc(t.manipulation_detected.where)}<br>
        <small>VIGÍA lo trata como una prueba más contra el atacante.</small></div>` : ''}
      <div class="dos">
        <div class="tarjeta"><h3>Qué ha pasado</h3><p>${esc(t.summary)}</p>
          <p class="sub" style="margin:0"><small>Severidad: ${esc(t.severity_rationale)}</small></p></div>
        <div class="tarjeta"><h3>Quién y qué está implicado</h3><div id="grafo"></div></div>
      </div>
      ${historiaHTML(t.linea)}
      ${inc ? `<div class="aviso info"><b>A quién avisar (informe N2):</b> ${esc((inc.notifications || []).join(' · '))}</div>` : ''}
      ${(t.playbooks || []).length ? `<h3 class="seccion">Playbook aplicado <small class="suave">· lo que dice el procedimiento del SOC y lo que ya ha hecho VIGÍA</small></h3>${playbooksCasoHTML(t.playbooks, t.ticket_id)}` : ''}
      <div class="dos">
        <div class="tarjeta"><h3>Cómo lo investigó VIGÍA</h3>${(t.trace || []).map(p => p.tipo === 'herramienta'
          ? `<div class="paso tool"><b>${esc(pasoTxt(p))}</b> <span class="mono suave">${esc(p.nombre)}</span></div>`
          : `<div class="paso">${esc(p.texto)}</div>`).join('')}
          <h3 style="margin-top:18px">Pruebas</h3>${t.evidence.map(e => `<div class="paso"><span class="prueba mono" data-ev="${esc(e.event_id)}">${esc(e.event_id)}</span>
            · ${esc(e.source)}<br><small>${esc(e.finding)}</small></div>`).join('') || '<p class="sub">Sin pruebas citadas.</p>'}
          <pre id="evento" hidden></pre></div>
        <div>
          <div class="tarjeta"><h3>La IA revisora (fiscal)</h3>${t.fiscal ? `<p class="${t.fiscal.agrees ? 'ok' : 'warn'}">${t.fiscal.agrees ? '✓ No ha podido tumbar el veredicto.' : '⚠ Tiene objeciones: decide el humano.'}</p>
            ${t.fiscal.objections.map(o => `<div class="paso">${esc(o)}</div>`).join('')}<p class="sub"><small>${esc(t.fiscal.comment)}</small></p>` : '<p class="sub">No aplica (severidad baja).</p>'}
            ${(t.open_questions || []).length ? `<h3>Lo que VIGÍA no sabe</h3>${t.open_questions.map(q => `<div class="paso">${esc(q)}</div>`).join('')}` : ''}</div>
          <div class="tarjeta"><h3>Acciones propuestas</h3><p class="sub"><small>Estás como <b>${esc(rol())}</b>. ${n2 ? '' : 'El N1 solo puede ejecutar purgar correo y bloquear indicadores.'}</small></p>
            <table>${t.recommended_actions.map((a, i) => {
              const cont = CONTENCIONES.includes(a.action), puede = cont && (n2 || !a.requires_approval);
              return `<tr><td><b>${esc(ACCION[a.action] || a.action)}</b> <span class="mono">${esc(a.target)}</span><br><small class="sub">${esc(a.justification)}</small></td>
                <td>${cont ? `<button data-i="${i}" ${puede ? '' : 'disabled'}>${a.requires_approval ? 'Aprobar' : 'Ejecutar'}</button>` : '<small class="warn">lo gestiona una persona</small>'}</td></tr>`; }).join('')}</table>
            <p id="resultado"></p>${(t.executed_actions || []).length ? `<p class="ok"><small>Ya ejecutadas: ${t.executed_actions.map(x => esc(x.action + ' → ' + x.target + ' (' + x.approver + ')')).join(' · ')}</small></p>` : ''}</div>
          <div class="tarjeta"><button id="reinv">🔁 Reinvestigar con IA en directo</button> <button class="sec" id="dl-t">Descargar ticket (JSON)</button> ${inc ? '<button class="sec" id="dl-i">Descargar informe N2 (JSON)</button>' : ''}</div>
        </div>
      </div>`;
    document.querySelectorAll('[data-ev]').forEach(el => el.onclick = async () => {
      const pre = $('#evento'); pre.hidden = false; pre.textContent = JSON.stringify(await api('evento/' + el.dataset.ev), null, 2); pre.scrollIntoView({block: 'nearest'}); });
    document.querySelectorAll('button[data-i]').forEach(b => b.onclick = async () => {
      const a = t.recommended_actions[b.dataset.i];
      const r = await post('aprobar', {ticket_id: t.ticket_id, action: a.action, target: a.target, approver: 'analista.' + rol().toLowerCase(), rol: rol(), reason: a.justification});
      const j = await r.json();
      $('#resultado').innerHTML = r.ok ? `<span class="ok">✓ Ejecutado en la API del SOC${j.requiere.length ? ' con aprobación de ' + esc(j.requiere.join(' + ')) : ''}.</span>`
                                       : `<span class="warn">✗ ${esc(j.detail || 'Rechazado')}</span>`; });
    const bajar = (obj, nombre) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], {type: 'application/json'})); a.download = nombre; a.click(); };
    $('#reinv').onclick = async () => { const j = await (await post('reinvestigar/' + t.ticket_id, {})).json(); location.hash = 'directo/' + j.trabajo; };
    $('#dl-t').onclick = () => { const c = {...t}; delete c.alertas; delete c.incidente; bajar(c, t.ticket_id + '.json'); };
    if (inc) $('#dl-i').onclick = () => bajar(inc, inc.incident_id + '.json');
    grafo(t); activarHistoria(); activarPlaybooks();
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

  async directo(jid) { await vistaDirecto(jid); },

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
  const [v, arg] = (location.hash.slice(1) || 'panel').split('/');
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('activo', a.getAttribute('href') === '#' + (v === 'caso' ? 'bandeja' : v)));
  try { await (vistas[v] || vistas.panel)(arg); window.scrollTo(0, 0); }
  catch (e) { $('#vista').innerHTML = `<p>No se pudo cargar (${esc(e.message)}). ¿Está arrancado el backend y has ejecutado el orquestador?</p>`; }
}
api('estado').then(s => { const d = $('#demo'); d.hidden = false; d.textContent = s.modo_demo ? 'MODO DEMO' : 'IA EN VIVO · ' + s.modelo; d.classList.toggle('vivo', !s.modo_demo); }).catch(() => {});
window.onhashchange = ruta; ruta();
