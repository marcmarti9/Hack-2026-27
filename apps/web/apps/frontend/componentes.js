// VIGÍA · componentes visuales: historia del ataque, playbooks guiados y lo descartado
const FASE_COLOR = {'Acceso inicial': '#86BC25', 'Ejecución': '#a78bfa', 'Persistencia': '#f472b6', 'Robo de credenciales': '#ff5c5c',
  'Descubrimiento': '#ffa62b', 'Movimiento lateral': '#ff7a45', 'Recogida de datos': '#e6cf4a', 'Mando y control': '#5eead4',
  'Exfiltración': '#ff3d71', 'Impacto': '#ff2d2d'};
const guardar = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} };
const cargar = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch (e) { return d; } };

function chipEntidad(e) {
  if (e.tipo === 'ip') {
    const i = e.info || {}, mala = i.reputacion === 'malicious', sosp = i.reputacion === 'suspicious';
    const tip = [i.pais, i.org, i.tipo, i.reputacion && `TIP: ${i.reputacion}${i.familia ? ' · ' + i.familia : ''}`].filter(Boolean).join(' · ');
    return `<span class="ent ip ${mala ? 'mala' : sosp ? 'sosp' : ''}" title="${esc(tip)}">🌍 ${esc(e.valor)}${i.pais ? ' · ' + esc(i.pais) : ''}${i.tipo ? ' · ' + esc(i.tipo) : ''}${mala ? ' · ' + esc(i.familia || 'maliciosa') : ''}</span>`;
  }
  return `<span class="ent ${e.tipo}">${e.tipo === 'usuario' ? '👤' : e.tipo === 'equipo' ? '💻' : '🛒'} ${esc(e.valor)}</span>`;
}

function historiaHTML(L) {
  if (!L || !L.pasos.length) return '';
  const alcanzadas = L.fases.filter(f => f.n).length;
  const hitos = L.pasos.filter(p => p.hito).length;
  return `<div class="tarjeta historia" id="historia">
    <div class="hist-cab"><div><h3>Historia del ataque</h3><p class="sub" style="margin:0">Pasa el ratón para ver detalles · pulsa un paso para ver el evento original · filtra por fase o por fuente</p></div>
      <div class="hist-kpis">
        <div><b>${esc(L.duracion || '—')}</b><small>de principio a fin</small></div>
        <div><b>${alcanzadas}/10</b><small>fases del ataque</small></div>
        <div><b>${L.pasos.length}</b><small>pasos · ${hitos} alertas</small></div>
        <div><b class="${L.fuera_de_horario ? 'rojo' : ''}">${L.fuera_de_horario}</b><small>con el SOC cerrado</small></div>
      </div></div>
    <div class="cadena">${L.fases.map(f => `<button class="fase ${f.n ? 'on' : ''}" data-fase="${esc(f.fase)}" style="--c:${FASE_COLOR[f.fase]}" ${f.n ? '' : 'disabled'}
        title="${f.n ? f.n + ' pasos · desde ' + esc(f.primera) : 'No alcanzada'}"><span>${esc(f.fase)}</span>${f.n ? `<b>${f.n}</b>` : ''}</button>`).join('<i class="flecha">›</i>')}</div>
    <div class="filtros"><button class="vista-btn" id="ver-todo">Ver los ${L.pasos.length} pasos</button><span class="sep"></span>
      <button class="filtro activo" data-fuente="">Todas las fuentes</button>${L.fuentes.map(f => `<button class="filtro" data-fuente="${esc(f)}">${esc(f)}</button>`).join('')}</div>
    <div class="tl2 resumen">${L.pasos.map((p, i) => {
      const prev = L.pasos[i - 1], salto = prev ? (Date.parse(p.ts) - Date.parse(prev.hasta || prev.ts)) / 36e5 : 0;
      return `${salto >= 3 ? `<div class="hueco">··· ${salto >= 48 ? Math.round(salto / 24) + ' días' : Math.round(salto) + ' h'} después ···</div>` : ''}
      <div class="paso2 ${p.hito ? 'hito' : ''} ${p.hito || !L.pasos.slice(0, i).some(q => q.fase === p.fase) ? 'clave' : ''}" data-f="${esc(p.fase)}" data-src="${esc(p.fuente_nombre)}" data-evr="${p.hito ? '' : esc(p.id)}" style="--c:${FASE_COLOR[p.fase]}">
        <div class="cuando">${esc(p.hora_local.slice(0, 5))}<b>${esc(p.hora_local.slice(6))}</b>${p.fuera_de_horario ? '<span title="SOC cerrado">🌙</span>' : ''}</div>
        <div class="nodo"></div>
        <div class="cuerpo">
          <div class="meta2"><span class="fuente">${p.icono} ${esc(p.fuente_nombre)}</span><span class="tag-fase">${esc(p.fase)}</span>
            ${p.mitre ? `<span class="mono suave">${esc(p.mitre)}</span>` : ''}${p.hito ? sev(p.severidad) : ''}
            ${p.repeticiones > 1 ? `<span class="rep">×${p.repeticiones}</span>` : ''}<span class="mono suave id">${esc(p.id)}</span></div>
          <div class="tit2">${esc(p.titulo)}</div>${p.detalle ? `<div class="det2">${esc(p.detalle)}</div>` : ''}
          ${p.entidades.length ? `<div class="ents">${p.entidades.slice(0, 4).map(chipEntidad).join('')}</div>` : ''}
          <pre class="raw" hidden></pre></div></div>`; }).join('')}</div></div>`;
}

function activarHistoria() {
  const box = document.getElementById('historia'); if (!box) return;
  let fase = '', fuente = '';
  const aplica = () => { if (fase || fuente) tl.classList.remove('resumen'); box.querySelectorAll('.paso2').forEach(p => p.classList.toggle('oculto', (fase && p.dataset.f !== fase) || (fuente && p.dataset.src !== fuente))); };
  const tl = box.querySelector('.tl2'), vt = box.querySelector('#ver-todo'), n = box.querySelectorAll('.paso2').length;
  vt.onclick = () => { tl.classList.toggle('resumen'); vt.textContent = tl.classList.contains('resumen') ? `Ver los ${n} pasos` : 'Ver solo lo importante'; };
  box.querySelectorAll('.fase.on').forEach(b => b.onclick = () => { fase = fase === b.dataset.fase ? '' : b.dataset.fase;
    box.querySelectorAll('.fase').forEach(x => x.classList.toggle('sel', x.dataset.fase === fase)); aplica(); });
  box.querySelectorAll('.filtro').forEach(b => b.onclick = () => { fuente = b.dataset.fuente;
    box.querySelectorAll('.filtro').forEach(x => x.classList.toggle('activo', x === b)); aplica(); });
  box.querySelectorAll('.paso2[data-evr]').forEach(p => { if (!p.dataset.evr) return; p.onclick = async () => {
    const pre = p.querySelector('.raw'); if (!pre.hidden) { pre.hidden = true; return; }
    pre.textContent = JSON.stringify(await api('evento/' + p.dataset.evr), null, 2); pre.hidden = false; }; });
}

function playbookHTML(pbk, tid) {
  const marcas = cargar(`vigia_pb_${tid}_${pbk.id}`, {});
  const hechos = pbk.pasos.filter(s => s.estado === 'hecho' || marcas[s.n]).length;
  return `<div class="tarjeta playbook" data-pb="${esc(pbk.id)}" data-t="${esc(tid)}">
    <div class="pb-cab"><span class="pb-icono">${pbk.icono}</span><div><small class="suave">PLAYBOOK ${esc(pbk.id)}</small><h3 style="margin:0">${esc(pbk.titulo)}</h3></div>
      <div class="pb-prog"><b>${hechos}/${pbk.total}</b><small>comprobaciones hechas</small><div class="barra"><i style="width:${100 * hechos / pbk.total}%"></i></div></div></div>
    <p class="sub" style="margin:10px 0 14px">VIGÍA ya hizo <b style="color:var(--verde)">${pbk.hechos}</b> comprobaciones con los datos. Te quedan las marcadas con ○: márcalas cuando las hagas.</p>
    <ol class="pasos-pb">${pbk.pasos.map(s => { const yo = marcas[s.n], hecho = s.estado === 'hecho';
      return `<li class="${hecho ? 'vigia' : yo ? 'yo' : 'pend'}"><span class="chk" data-n="${s.n}" title="${hecho ? 'Comprobado por VIGÍA' : 'Marcar como hecho'}">${hecho ? '✓' : yo ? '✓' : '○'}</span>
        <div><b>${esc(s.titulo)}</b> <span class="quien">${hecho ? 'VIGÍA' : yo ? 'Tú' : 'Te toca'}</span><div class="suave">${esc(s.texto)}</div>
        ${hecho && s.hallazgo ? `<div class="hallazgo">→ ${esc(s.hallazgo)} ${s.prueba ? `<span class="prueba mono" data-ev="${esc(s.prueba)}">${esc(s.prueba)}</span>` : ''}</div>` : ''}
        ${s.fuentes.length ? `<div class="srcs">${s.fuentes.map(f => `<span>${esc(f)}</span>`).join('')}</div>` : ''}</div></li>`; }).join('')}</ol>
    <h4 class="dec-tit">Decisión</h4>
    <div class="decisiones">${pbk.decisiones.map((d, i) => `<div class="dec ${d.color} ${i === pbk.elegida ? 'elegida' : ''}">
      ${i === pbk.elegida ? '<span class="reco">VIGÍA recomienda</span>' : ''}<div class="si">Si: ${esc(d.condicion)}</div><div class="ent2">→ ${esc(d.accion)}</div></div>`).join('')}</div></div>`;
}

function playbooksCasoHTML(pbs, tid) {
  if (!pbs || !pbs.length) return '';
  const act = Math.min(+(window._pbTab || 0), pbs.length - 1);
  return `<div class="pb-tabs">${pbs.map((p, i) => `<button class="pb-tab ${i === act ? 'activo' : ''}" data-i="${i}">${p.icono} ${esc(p.id)} · ${esc(p.titulo.split(/[:(]/)[0])}
      <small>${p.hechos}/${p.total}</small></button>`).join('')}</div>
    ${pbs.map((p, i) => `<div class="pb-panel" data-i="${i}" ${i === act ? '' : 'hidden'}>${playbookHTML(p, tid)}</div>`).join('')}`;
}

function activarPlaybooks() {
  document.querySelectorAll('.pb-tab').forEach(b => b.onclick = () => { window._pbTab = b.dataset.i;
    document.querySelectorAll('.pb-tab').forEach(x => x.classList.toggle('activo', x === b));
    document.querySelectorAll('.pb-panel').forEach(x => x.hidden = x.dataset.i !== b.dataset.i); });
  document.querySelectorAll('.playbook').forEach(box => box.querySelectorAll('.pend .chk, .yo .chk').forEach(c => c.onclick = () => {
    const k = `vigia_pb_${box.dataset.t}_${box.dataset.pb}`, m = cargar(k, {}); m[c.dataset.n] = !m[c.dataset.n]; guardar(k, m); ruta(); }));
}

async function vistaPlaybooks(id) {
  const P = await api('playbooks');
  if (id) {
    const p = P.find(x => x.id === id);
    $('#vista').innerHTML = `<p class="sub"><a class="prueba" href="#playbooks">← Playbooks</a></p>
      <div class="pb-hero"><span class="pb-icono grande">${p.icono}</span><div><small class="suave">PLAYBOOK ${esc(p.id)} · ${p.alertas} alertas este mes · ${p.casos.length} ${p.casos.length === 1 ? 'caso' : 'casos'}</small><h2>${esc(p.titulo)}</h2>
        <div class="srcs">${p.reglas.map(r => `<span>${esc(r)}</span>`).join('')}</div></div></div>
      <div class="dos">
        <div class="tarjeta"><h3>1 · Comprueba</h3><ol class="flujo">${p.pasos.map(s => `<li><span class="num">${s.n}</span><div><b>${esc(s.titulo)}</b><div class="suave">${esc(s.texto)}</div>
          ${s.fuentes.length ? `<div class="srcs">${s.fuentes.map(f => `<span>${esc(f)}</span>`).join('')}</div>` : ''}</div></li>`).join('')}</ol></div>
        <div><div class="tarjeta"><h3>2 · Decide</h3><div class="decisiones col">${p.decisiones.map(d => `<div class="dec ${d.color}"><div class="si">Si: ${esc(d.condicion)}</div><div class="ent2">→ ${esc(d.accion)}</div></div>`).join('')}</div>
          <p class="sub" style="margin-top:12px"><small>Verde: cerrar · Ámbar: vigilar · Rojo: contener y escalar</small></p></div>
          <div class="tarjeta"><h3>3 · Casos reales donde se ha usado</h3>${p.casos.map(c => `<div class="caso-mini" onclick="location.hash='caso/${c.ticket_id}'">${sev(c.severity)} ${esc(c.title)}</div>`).join('') || '<p class="sub">Ningún caso este mes.</p>'}</div></div>
      </div>`;
    return;
  }
  $('#vista').innerHTML = `<h2>Playbooks</h2><p class="sub">Los 10 runbooks del SOC convertidos en guías paso a paso. VIGÍA los aplica solo en cada caso; tú solo revisas lo pendiente.</p>
    <div class="como"><div><span>1</span><b>Llega una alerta</b><small>VIGÍA identifica qué playbook le toca según la regla del SIEM.</small></div><i>→</i>
      <div><span>2</span><b>VIGÍA hace las comprobaciones</b><small>Cruza logs, inventario, inteligencia y cambios, y marca cada paso con su prueba.</small></div><i>→</i>
      <div><span>3</span><b>Tú decides</b><small>Revisas lo pendiente (○) y confirmas la decisión que recomienda.</small></div></div>
    <div class="pb-grid">${P.map(p => `<div class="pb-card" onclick="location.hash='playbooks/${p.id}'"><div class="pb-icono">${p.icono}</div>
      <small class="suave">${esc(p.id)}</small><b>${esc(p.titulo)}</b>
      <div class="pb-nums"><span><b>${p.pasos.length}</b> pasos</span><span><b>${fmt(p.alertas)}</b> alertas</span><span><b>${p.casos.length}</b> ${p.casos.length === 1 ? 'caso' : 'casos'}</span></div>
      <div class="mini-dec">${p.decisiones.map(d => `<i class="${d.color}"></i>`).join('')}</div></div>`).join('')}</div>`;
}

async function vistaDescartado() {
  const d = await api('descartado');
  const color = {'Falsa alarma': '#5e5e5e', 'Ataque sin efecto': '#86BC25', 'Actividad autorizada': '#26890D'};
  const horas = d.grupos.reduce((s, g) => s + g.horas, 0);
  $('#vista').innerHTML = `<h2>Lo que he descartado</h2>
    <p class="sub">${fmt(d.cerradas)} de ${fmt(d.total)} alertas (${Math.round(100 * d.cerradas / d.total)}%) cerradas por reglas que se explican en una frase. Cada motivo dice el criterio exacto, en qué se apoya y cómo evitar que vuelva a saltar.</p>
    <div class="desc-kpis">
      <div class="tarjeta"><b>${fmt(d.cerradas)}</b><small>alertas cerradas</small></div>
      <div class="tarjeta"><b>${fmt(horas)} h</b><small>de analista ahorradas</small></div>
      <div class="tarjeta"><b>${d.grupos.length}</b><small>motivos distintos</small></div>
      <div class="tarjeta ancho"><small>Tipo de descarte</small><div class="apilada">${d.tipos.map(([t, n]) => `<i style="width:${100 * n / d.cerradas}%;background:${color[t]}" title="${esc(t)}: ${fmt(n)}"></i>`).join('')}</div>
        <div class="leyenda">${d.tipos.map(([t, n]) => `<span><i style="background:${color[t]}"></i>${esc(t)} · ${fmt(n)}</span>`).join('')}</div></div>
    </div>
    <div class="motivos">${d.grupos.map((g, i) => `<div class="motivo">
      <div class="m-cab"><span class="m-icono">${g.icono}</span><div class="m-t"><b>${esc(g.titulo)}</b><span class="m-tipo" style="--c:${color[g.tipo] || '#5e5e5e'}">${esc(g.tipo)}</span></div>
        <div class="m-num"><b>${fmt(g.n)}</b><small>${g.pct}% · ${fmt(g.horas)} h</small></div></div>
      <div class="m-barra"><i style="width:${Math.max(1.5, 100 * g.n / d.grupos[0].n)}%;background:${color[g.tipo] || '#5e5e5e'}"></i></div>
      <p class="m-por">${esc(g.por_que)}</p>
      <div class="m-fila"><span class="m-et">Criterio</span><code>${esc(g.criterio)}</code></div>
      <div class="m-fila"><span class="m-et">Respaldo</span><span>${esc(g.respaldo)}</span></div>
      <div class="m-fila"><span class="m-et">Reglas</span><span>${g.reglas.map(r => `<span class="chip-r" title="${esc(r.nombre)}">${esc(r.rule_id)} · ${fmt(r.n)}</span>`).join(' ')}</span></div>
      ${g.recomendacion && g.recomendacion !== '—' ? `<div class="m-reco">💡 <b>Para ingeniería de detección:</b> ${esc(g.recomendacion)}</div>` : ''}
      <button class="sec m-btn" data-n="${g.ejemplos.length}">Ver ${g.ejemplos.length} ejemplos ▾</button>
      <table class="m-ej" hidden><tr><th>Cuándo</th><th>Alerta</th><th>Quién</th><th>Dato clave</th></tr>${g.ejemplos.map(e => `<tr><td class="mono">${esc(e.cuando)}</td>
        <td class="mono">${esc(e.alert_id.slice(-6))}</td><td>${esc(e.quien)}</td><td class="suave">${Object.entries(e.datos).map(([k, v]) => `<b>${esc(k)}</b> ${esc(v)}`).join(' · ')}</td></tr>`).join('')}</table>
    </div>`).join('')}</div>`;
  document.querySelectorAll('.m-btn').forEach(b => b.onclick = () => { const t = b.nextElementSibling; t.hidden = !t.hidden;
    b.textContent = `${t.hidden ? 'Ver' : 'Ocultar'} ${b.dataset.n} ejemplos ${t.hidden ? '▾' : '▴'}`; });
}

// ---------- Análisis en directo: pegar alertas (las del jurado) y ver a VIGÍA trabajar ----------
const HERR_TXT = {get_asset: a => `Consulta la CMDB: ${a.key}`, get_user: a => `Consulta el directorio y RRHH: ${a.key}`,
  events_for_entity: a => `Busca en los logs la actividad de ${a.value}${a.horas ? ` (±${a.horas} h)` : ''}`, search_logs: a => `Busca "${a.text}" en los logs`,
  get_intel: a => `Consulta la inteligencia sobre ${a.indicator}`, get_sandbox: a => `Consulta la sandbox (${String(a.sha256).slice(0, 12)}…)`,
  get_changes: a => `Revisa el calendario de cambios: "${a.q}"`, get_cve: a => `Cruza las CVE de ${a.host} con KEV y EPSS`,
  alerts_for_entity: a => `Busca otras alertas de ${a.value}`, get_event: a => `Lee el evento ${a.event_id}`};
const pasoTxt = p => p.tipo === 'herramienta' ? (HERR_TXT[p.nombre] ? HERR_TXT[p.nombre](p.entrada || {}) : p.nombre) : (p.texto || '');
const PASO_ICONO = {herramienta: '⚙', pensamiento: '💭', motor: '🧹', escudo: '🛡', caso: '📁', fiscal: '⚖'};

async function vistaDirecto(jid) {
  const est = await api('estado');
  $('#vista').innerHTML = `<h2>Analizar en directo</h2>
    <p class="sub">Pega alertas nuevas (JSON o JSONL, el mismo formato que <span class="mono">alertas.jsonl</span>) y mira cómo VIGÍA las cierra o las investiga paso a paso.
      ${est.modo_demo ? '<b class="warn">Ahora está en MODO DEMO (agentes simulados).</b>' : `Agentes con <b class="ok">${esc(est.modelo)}</b>.`}</p>
    <div class="dos directo">
      <div class="tarjeta"><h3>1 · Alertas</h3>
        <textarea id="entrada" spellcheck="false" placeholder='{"alert_id": "ALR-...", "created_at": "2026-10-31T02:40:00Z", "rule_id": "UC-EDR-009", "entities": {...}, "evidence": {...}}'></textarea>
        <div class="botones"><button class="sec" id="ej">Cargar ejemplos del directo</button>
          <label class="sec boton-f">Subir fichero<input type="file" id="fich" accept=".json,.jsonl,.txt" hidden></label>
          <button id="go">▶ Analizar con IA</button></div>
        <p class="sub" style="margin:8px 0 0"><small>Basta con alert_id, created_at y rule_id: el resto lo completa con el catálogo de reglas.</small></p></div>
      <div class="tarjeta"><h3>2 · VIGÍA trabajando <span id="reloj-d" class="mono suave"></span></h3>
        <div id="estado-d" class="sub">Esperando alertas…</div><div id="feed" class="feed"></div><div id="res-d"></div></div>
    </div>`;
  $('#ej').onclick = async () => { $('#entrada').value = (await api('ejemplos_directo')).map(a => JSON.stringify(a)).join('\n'); };
  $('#fich').onchange = async e => { const f = e.target.files[0]; if (f) $('#entrada').value = await f.text(); };
  $('#go').onclick = async () => {
    const r = await post('analizar', {texto: $('#entrada').value}); const j = await r.json();
    if (!r.ok) { $('#estado-d').innerHTML = `<span class="warn">✗ ${esc(j.detail)}</span>`; return; }
    seguir(j.trabajo);
  };
  if (jid) seguir(jid);
}

function seguir(jid) {
  let desde = 0; $('#feed').innerHTML = ''; $('#res-d').innerHTML = ''; $('#go') && ($('#go').disabled = true);
  const tic = async () => {
    if (!document.getElementById('feed')) return;                      // el usuario cambió de pantalla
    const j = await api(`trabajo/${jid}?desde=${desde}`);
    desde = j.total_pasos;
    j.pasos.forEach(p => { const d = document.createElement('div'); d.className = 'fp ' + p.tipo;
      d.innerHTML = `<span>${PASO_ICONO[p.tipo] || '•'}</span><div>${esc(pasoTxt(p))}${p.tipo === 'herramienta' && p.resultado ? `<small>${esc(String(p.resultado).slice(0, 140))}</small>` : ''}</div>`;
      $('#feed').appendChild(d); $('#feed').scrollTop = 1e9; });
    $('#reloj-d').textContent = `${j.segundos} s`;
    $('#estado-d').innerHTML = j.estado === 'terminado' ? `<span class="ok">✓ Terminado: ${j.alertas} alerta(s) en ${j.segundos} s</span>`
      : j.estado === 'error' ? `<span class="warn">✗ ${esc(j.error)}</span>` : `<span class="pulso"></span> ${esc(j.estado)}…`;
    if (j.estado === 'terminado' || j.estado === 'error') {
      $('#go') && ($('#go').disabled = false);
      $('#res-d').innerHTML = (j.cerradas.length ? `<h4 class="dec-tit">Cerradas por el motor</h4>${j.cerradas.map(c => `<div class="paso"><span class="mono">${esc(c.alert_id)}</span> · ${esc(c.reason)}</div>`).join('')}` : '') +
        (j.tickets.length ? `<h4 class="dec-tit">Casos investigados</h4><div class="casos3">${j.tickets.map(t => `<div class="caso" onclick="location.hash='caso/${t.ticket_id}'">
          <div class="meta">${sev(t.severity)} <span>${Math.round(t.confidence * 100)}% confianza</span><span>· ${t.triage_seconds} s</span></div><div class="t">${esc(t.title)}</div>
          <p>${esc(VERDICTO[t.verdict])} · abrir el caso →</p></div>`).join('')}</div>` : '');
      return;
    }
    setTimeout(tic, 800);
  };
  tic();
}
