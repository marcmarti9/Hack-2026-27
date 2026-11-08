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
  return `<span class="ent ${esc(e.tipo)}">${e.tipo === 'usuario' ? '👤' : e.tipo === 'equipo' ? '💻' : '🛒'} ${esc(e.valor)}</span>`;
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
        <div><b class="${L.fuera_de_horario ? 'rojo' : ''}">${fmt(L.fuera_de_horario)}</b><small>con el SOC cerrado</small></div>
      </div></div>
    <div class="cadena">${L.fases.map(f => `<button class="fase ${f.n ? 'on' : ''}" data-fase="${esc(f.fase)}" style="--c:${FASE_COLOR[f.fase]}" ${f.n ? '' : 'disabled'}
        title="${f.n ? fmt(f.n) + ' pasos · desde ' + esc(f.primera) : 'No alcanzada'}"><span>${esc(f.fase)}</span>${f.n ? `<b>${fmt(f.n)}</b>` : ''}</button>`).join('<i class="flecha">›</i>')}</div>
    <div class="filtros"><button class="vista-btn" id="ver-todo">Ver los ${L.pasos.length} pasos</button><span class="sep"></span>
      <button class="filtro activo" data-fuente="">Todas las fuentes</button>${L.fuentes.map(f => `<button class="filtro" data-fuente="${esc(f)}">${esc(f)}</button>`).join('')}</div>
    <div class="tl2 resumen">${L.pasos.map((p, i) => {
      const prev = L.pasos[i - 1], salto = prev ? (Date.parse(p.ts) - Date.parse(prev.hasta || prev.ts)) / 36e5 : 0;
      return `${salto >= 3 ? `<div class="hueco">··· ${salto >= 48 ? Math.round(salto / 24) + ' días' : Math.round(salto) + ' h'} después ···</div>` : ''}
      <div class="paso2 ${p.hito ? 'hito' : ''} ${p.hito || !L.pasos.slice(0, i).some(q => q.fase === p.fase) ? 'clave' : ''}" data-f="${esc(p.fase)}" data-src="${esc(p.fuente_nombre)}" data-evr="${p.hito ? '' : esc(p.id)}" style="--c:${FASE_COLOR[p.fase]}">
        <div class="cuando">${esc(p.hora_local.slice(0, 5))}<b>${esc(p.hora_local.slice(6))}</b>${p.fuera_de_horario ? '<span title="SOC cerrado">🌙</span>' : ''}</div>
        <div class="nodo"></div>
        <div class="cuerpo">
          <div class="meta2"><span class="fuente">${esc(p.icono)} ${esc(p.fuente_nombre)}</span><span class="tag-fase">${esc(p.fase)}</span>
            ${p.mitre ? `<span class="mono suave">${esc(p.mitre)}</span>` : ''}${p.hito ? sev(p.severidad) : ''}
            ${p.repeticiones > 1 ? `<span class="rep">×${fmt(p.repeticiones)}</span>` : ''}<span class="mono suave id">${esc(p.id)}</span></div>
          <div class="tit2">${esc(p.titulo)}</div>${p.detalle ? `<div class="det2">${esc(p.detalle)}</div>` : ''}
          ${p.entidades.length ? `<div class="ents">${p.entidades.slice(0, 4).map(chipEntidad).join('')}</div>` : ''}
          <div class="raw" hidden></div></div></div>`; }).join('')}</div></div>`;
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
    const destino = p.querySelector('.raw'); if (!destino.hidden) { destino.hidden = true; return; }
    await mostrarEvento(p.dataset.evr, destino); }; });
}

const NOMBRES_CAMPO = {event_id: 'Evento', alert_id: 'Alerta', alert_ids: 'Alertas vinculadas', timestamp: 'Fecha', source: 'Fuente',
  hostname: 'Equipo', hosts: 'Equipos', users: 'Cuentas', upn: 'Cuenta', business_services: 'Servicios afectados',
  reason: 'Motivo', finding: 'Hallazgo', summary: 'Resumen', citations: 'Citas', context_citations: 'Citas de contexto',
  verdict: 'Veredicto', questions: 'Preguntas abiertas', actions: 'Acciones', scope: 'Alcance', confidence: 'Confianza',
  false_hypotheses: 'Hipótesis descartadas', recipient: 'Destinatario', requires_approval: 'Requiere aprobación'};

function registroHTML(value) {
  if (Array.isArray(value)) return value.length ? `<ul>${value.map(v => `<li>${registroHTML(v)}</li>`).join('')}</ul>` : 'Sin datos';
  if (value && typeof value === 'object') {
    return Object.entries(value).map(([key, dato]) => {
      const nombre = NOMBRES_CAMPO[key] || key.replaceAll('_', ' ');
      return `<div class="paso"><b>${esc(nombre)}</b> · ${registroHTML(key === 'verdict' ? veredicto(dato) : dato)}</div>`;
    }).join('') || 'Sin datos';
  }
  if (typeof value === 'boolean') return value ? 'Sí' : 'No';
  return esc(value == null || value === '' ? 'Sin datos' : value).replace(/\n/g, '<br>');
}

async function mostrarEvento(id, destino) {
  destino.hidden = false;
  destino.textContent = 'Consultando el evento…';
  try { destino.innerHTML = registroHTML(await api('evento/' + encodeURIComponent(id))); }
  catch { destino.textContent = 'No se pudo recuperar el evento del índice.'; }
}

function expedienteHTML(t) {
  const informe = t.expediente;
  if (!informe) return '';
  const ruta = t.routing || informe.routing || {};
  const crit = informe.criterio_verificado || {};
  const propuesta = informe.propuesta || {};
  const contraste = informe.contraste || {};
  const errores = t.provider_errors || informe.provider_errors || {};
  const consultas = informe.consultas || [];
  const decision = t.decision_actual || informe.decision_actual;
  const automatica = decision?.decision === 'automatic';
  const humana = ['accepted', 'corrected'].includes(decision?.decision);
  const cerrada = automatica || humana;
  const escalada = ruta.recommendation === 'escalate';
  const tono = !automatica && escalada ? 'escalada' : cerrada ? 'cerrada' : 'pendiente';
  const titulo = automatica ? 'Cerrada por Vigía'
    : humana ? disposicion(decision.decision) : disposicion(ruta.recommendation) || 'Revisión pendiente';
  const motivo = decision?.reason || ruta.reason;
  const veredictoActual = decision?.verdict || t.verdict || informe.verdict;
  const estimada = informe.confidence > 0 && Number.isFinite(informe.confidence);
  const corroborado = Boolean(crit.citations?.length || crit.sandbox_refs?.length);
  const recuperados = informe.evidence?.length || 0;
  const preguntas = informe.open_questions || [];
  const fuente = t.provider || informe.provider;
  const tienePropuesta = Object.keys(propuesta).length > 0;
  const tieneContraste = Object.keys(contraste).length > 0;
  const tieneLimites = Object.keys(errores).length > 0;
  const duracion = informe.timing_ms == null ? ''
    : informe.timing_ms < 1000 ? `${fmt(informe.timing_ms)} ms`
      : `${(informe.timing_ms / 1000).toLocaleString('es-ES', {maximumFractionDigits: 1})} s`;
  const desplegable = (nombre, contenido) => contenido
    ? `<details class="vigia-report-fold"><summary>${nombre}</summary><div class="vigia-report-fold-content">${contenido}</div></details>`
    : '';
  const registro = (nombre, dato) => desplegable(nombre, dato && Object.keys(dato).length ? registroHTML(dato) : '');
  const etiqueta = (nombre, valor, clase = '') => valor
    ? `<div${clase ? ` class="${clase}"` : ''}><dt>${nombre}</dt><dd>${esc(valor)}</dd></div>` : '';
  const icono = cerrada ? '<path d="m5 12 4 4 10-10"/>'
    : escalada ? '<path d="M12 19V5m-5 5 5-5 5 5"/>' : '<path d="M12 7v5l3 2m6-2a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/>';

  return `<div class="vigia-report">
    <section class="vigia-report-decision ${tono}">
      <div class="vigia-report-decision-lead">
        <span class="vigia-report-glyph" aria-hidden="true"><svg viewBox="0 0 24 24" width="21" height="21" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${icono}</svg></span>
        <div>
          <p class="vigia-report-label">${cerrada ? 'Decisión registrada' : 'Resultado de la investigación'}</p>
          <h3>${esc(titulo)}</h3>
          <p class="vigia-report-verdict">${esc(veredicto(veredictoActual))}${automatica ? '<span>Sin intervención pendiente</span>' : ''}</p>
          ${motivo ? `<p class="vigia-report-muted">${esc(motivo)}</p>` : ''}
          ${informe.confidence_basis ? `<p class="vigia-report-confidence-note">${esc(informe.confidence_basis)}</p>` : ''}
        </div>
      </div>
      <dl class="vigia-report-meta">
        ${etiqueta('Confianza del triaje', estimada ? `${Math.round(informe.confidence * 100)} %` : 'Sin estimación')}
        ${etiqueta('Duración', duracion)}
        ${etiqueta('Plazo', !automatica && hora(ruta.deadline_at))}
        ${etiqueta('Responsables', ruta.recipients?.join(' · '), 'vigia-report-owners')}
        ${humana ? etiqueta('Ruta de triaje', [disposicion(ruta.recommendation), ruta.reason !== motivo ? ruta.reason : ''].filter(Boolean).join(' · '), 'vigia-report-owners') : ''}
      </dl>
    </section>
    <div class="vigia-report-grid">
      <section class="vigia-report-section">
        <h3>Hallazgos y contexto</h3>
        <div class="vigia-report-observation">
          <span class="vigia-report-marker ${corroborado ? 'verificado' : ''}"></span>
          <div><strong>${corroborado ? 'Hallazgo corroborado' : 'Sin hallazgo corroborado'}</strong>
            <p>${esc(crit.summary || (recuperados ? 'Los registros recuperados aportan contexto para seguir investigando.'
              : 'El índice no devolvió registros para verificar esta alerta.'))}</p></div>
        </div>
        ${preguntas.length ? desplegable('Qué falta por comprobar', registroHTML(preguntas)) : ''}
        ${registro('Criterio y referencias', crit)}
        ${registro('Enriquecimiento del índice', informe.enrichment)}
        ${registro('Vulnerabilidades', informe.vulnerabilities)}
        ${registro('Entidades declaradas', informe.declared_entities)}
        ${registro('Discrepancias de entidades', informe.entity_discrepancies)}
        ${registro('Alertas relacionadas', informe.related_alerts)}
        ${registro('Técnicas MITRE', informe.mitre)}
        ${registro('Alcance del incidente N2', informe.incident?.scope)}
      </section>
      <section class="vigia-report-section">
        <h3>Propuesta y revisión adversarial</h3>
        <ol class="vigia-report-review">
          <li><strong>${fuente === 'Reglas locales' ? 'Comprobación local' : 'Primera propuesta'}</strong>
            <span>${esc(fuente || 'Sin proveedor registrado')}</span>
            ${registro('Propuesta registrada', propuesta)}
          </li>
          <li><strong>${informe.review_provider ? 'Contraste del fiscal' : 'Contraste de la evidencia'}</strong>
            <span>${esc(informe.review_provider || (tieneContraste ? 'Verificación de los registros' : 'Sin contraste registrado'))}</span>
            ${informe.review_reason ? `<p>${esc(informe.review_reason)}</p>` : ''}
            ${registro('Contraste registrado', contraste)}
          </li>
        </ol>
        ${tieneLimites ? `<div class="vigia-report-limit"><strong>Límites de la revisión</strong>
          ${errores.proposal ? `<p><b>Propuesta</b> · ${esc(errores.proposal)}</p>` : ''}
          ${errores.review ? `<p><b>Contraste</b> · ${esc(errores.review)}</p>` : ''}
          ${registro('Registro de incidencias', Object.fromEntries(Object.entries(errores).filter(([fase]) => !['proposal', 'review'].includes(fase))))}
        </div>` : ''}
        ${!tienePropuesta && !tieneContraste ? '<p class="vigia-report-muted">Este expediente se limita a las consultas y evidencias registradas.</p>' : ''}
      </section>
    </div>
    <section class="vigia-report-section">
      <h3>Consultas al índice <span class="vigia-report-count">${fmt(consultas.length)}</span></h3>
      ${consultas.length ? `<ul class="vigia-report-queries">${consultas.map(c => `<li>
        <div><strong>${esc(c.tool)}</strong><p>${esc(c.query)}</p>${c.note ? `<p>${esc(c.note)}</p>` : ''}</div>
        ${c.count != null ? `<span>${fmt(c.count)} ${c.count === 1 ? 'resultado' : 'resultados'}</span>` : ''}
      </li>`).join('')}</ul>` : '<p class="vigia-report-muted">Sin consultas registradas.</p>'}
    </section>
  </div>`;
}

function decisionHTML(t) {
  if (!t.alert_id || !t.expediente) return '';
  const decision = t.decision_actual;
  const cerrada = ['accepted', 'corrected'].includes(decision?.decision);
  const automatica = decision?.decision === 'automatic';
  return `<div class="tarjeta"><h3>Decisión e historial</h3>
    ${decision ? `<p class="ok"><b>${esc(disposicion(decision.decision))}</b> · ${esc(veredicto(decision.verdict))}${decision.reviewer ? ` · ${esc(decision.reviewer)}` : ''}</p>${decision.reason ? `<p class="sub">${esc(decision.reason)}</p>` : ''}` : '<p class="sub">Pendiente de decisión humana.</p>'}
    ${automatica ? '<p class="sub">El cierre ya está registrado. Puedes consultar el informe o corregirlo si aparece nueva evidencia.</p>' : ''}
    ${cerrada ? '' : `<div class="botones">${t.puede_aceptar ? '<button id="aceptar-alerta">Aceptar veredicto</button>' : ''}<button id="abrir-correccion" class="sec">${automatica ? 'Registrar una corrección' : 'Corregir veredicto'}</button></div>
      <form id="corregir-alerta" hidden><div class="botones"><label>Veredicto <select name="verdict" required><option value="">Selecciona</option>${Object.entries(VERDICTO).filter(([id]) => id !== 'needs_more_info').map(([id, texto]) => `<option value="${id}">${esc(texto)}</option>`).join('')}</select></label>
        <label>Motivo <input name="reason" type="text" required maxlength="700"></label><button>Registrar corrección</button></div></form>`}
    <p class="sub" id="estado-decision" role="status"></p>
    ${(t.historial || []).map(h => `<div class="paso"><b>${esc(h.kind)}</b> · ${esc(h.actor)} · ${esc(hora(h.created_at))}${h.reason ? `<br>${esc(h.reason)}` : ''}</div>`).join('') || '<p class="sub">Sin cambios de historial registrados.</p>'}</div>`;
}

function aislamientoHTML(propuesta) {
  return `<details><summary>Aislamiento en el simulador de Tarvia</summary>
    <p class="sub">Puesto propuesto · <b>${esc(propuesta.target)}</b></p>
    <form id="aislar-alerta">
      <label>Clave N2 de práctica <input name="password" type="password" required maxlength="128" autocomplete="off"></label>
      <label>Justificación <input name="reason" required maxlength="500"></label>
      <label><input name="confirmed" type="checkbox" required> Confirmo el aislamiento simulado</label>
      <button>Ejecutar en el simulador</button>
    </form></details>`;
}

function activarAislamiento(t) {
  const form = $('#aislar-alerta'), status = $('#resultado');
  form.onsubmit = async event => {
    event.preventDefault();
    const control = form.querySelector('button');
    control.disabled = true;
    const payload = {target: t.expediente.isolation_proposal.target, password: form.elements.password.value,
      reason: form.elements.reason.value, confirmed: form.elements.confirmed.checked};
    form.elements.password.value = '';
    try {
      const r = await post('aislar/' + encodeURIComponent(t.alert_id), payload), body = await r.json();
      if (!r.ok) throw new Error(mensajeError(body));
      await ruta();
    } catch (error) { status.textContent = error.message; control.disabled = false; }
  };
}

async function editorGuia(name) {
  const block = $('#guia-editable'), doc = await api('documentos/' + encodeURIComponent(name));
  block.innerHTML = `<details><summary>Documento del agente · revisión ${doc.revision}</summary>
    <form><textarea aria-label="Documento del agente" maxlength="16000" required ${rol() === 'N1' ? 'readonly' : ''}></textarea>
      ${rol() === 'N1' ? '' : '<button>Guardar revisión</button>'}
      <p class="sub" role="status"></p>
    </form></details>`;
  const form = block.querySelector('form'), input = form.querySelector('textarea');
  input.value = doc.texto;
  form.onsubmit = async event => {
    event.preventDefault();
    try {
      const r = await post('documentos/' + encodeURIComponent(name), {revision: doc.revision, texto: input.value, rol: rol()}, 'PUT');
      if (!r.ok) throw new Error(mensajeError(await r.json()));
      await editorGuia(name);
      block.querySelector('details').open = true;
      block.querySelector('[role="status"]').textContent = 'Revisión guardada.';
    } catch (error) { form.querySelector('[role="status"]').textContent = error.message; }
  };
}

function activarDecision(t) {
  const forma = $('#corregir-alerta'), aceptar = $('#aceptar-alerta'), estado = $('#estado-decision');
  if (!forma) return;
  $('#abrir-correccion').onclick = () => { forma.hidden = !forma.hidden; if (!forma.hidden) forma.elements.verdict.focus(); };
  const guardarDecision = async (decision, verdict, reason) => {
    const botones = [aceptar, forma.querySelector('button')].filter(Boolean);
    botones.forEach(b => b.disabled = true);
    estado.textContent = 'Guardando decisión…';
    try {
      const r = await post('decision/' + encodeURIComponent(t.alert_id), {decision, verdict, reason, rol: rol()});
      if (!r.ok) throw new Error(mensajeError(await r.json()));
      await ruta();
    } catch (e) { estado.textContent = e.message; }
    finally { botones.forEach(b => b.disabled = false); }
  };
  if (aceptar) aceptar.onclick = () => guardarDecision('accepted', t.verdict, '');
  forma.onsubmit = e => {
    e.preventDefault();
    const reason = forma.elements.reason.value.trim();
    if (!reason) { estado.textContent = 'Escribe el motivo de la corrección.'; return; }
    guardarDecision('corrected', forma.elements.verdict.value, reason);
  };
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
  if (id === 'SKILL') {
    $('#vista').innerHTML = '<p class="sub"><a class="prueba" href="#playbooks">← Playbooks</a></p><h2>Guía del agente</h2><div id="guia-editable" class="tarjeta"></div>';
    await editorGuia(id);
    return;
  }
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
      </div><div id="guia-editable" class="tarjeta"></div>`;
    await editorGuia(id);
    return;
  }
  $('#vista').innerHTML = `<h2>Playbooks</h2><p class="sub">Los 10 runbooks del SOC convertidos en guías paso a paso. <a class="prueba" href="#playbooks/SKILL">Guía editable del agente →</a></p>
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
    <p class="sub">${fmt(d.cerradas)} de ${fmt(d.total)} alertas (${Math.round(100 * d.cerradas / Math.max(1, d.total))} %) elegibles para cierre en el barrido local. Los ejemplos enlazan al expediente con las citas.</p>
    <div class="desc-kpis">
      <div class="tarjeta"><b>${fmt(d.cerradas)}</b><small>cierres elegibles</small></div>
      <div class="tarjeta"><b>${fmt(horas)} h</b><small>estimación a 15 min por alerta</small></div>
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
        <td class="mono"><a class="prueba" href="${enlace('caso', 'VIG-' + e.alert_id)}">${esc(e.alert_id)}</a></td><td>${esc(e.quien)}</td><td class="suave">${Object.entries(e.datos).map(([k, v]) => `<b>${esc(k)}</b> ${esc(v)}`).join(' · ')}</td></tr>`).join('')}</table>
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

async function vistaDirecto(jid, prellenar = '') {
  const est = await api('estado');
  $('#vista').innerHTML = `<h2>Analizar en directo</h2>
    <p class="sub">Pega IDs del índice, un objeto JSON o un lote JSONL. Vigía contrasta los registros y aplica la política del turno.
      ${est.openai_disponible ? `Contraste opcional con <b class="ok">${esc(est.modelo || 'OpenAI')}</b>.` : '<b>Análisis local disponible sin clave.</b>'}</p>
    <div class="dos directo">
      <div class="tarjeta"><h3>1 · Alertas</h3>
        <textarea id="entrada" aria-label="Alertas para analizar" spellcheck="false" placeholder="ALR-20261010-011795"></textarea>
        <div class="botones"><label>Turno <select id="modo-d"><option value="diurno">Horario atendido</option><option value="guardia">Guardia</option></select></label>
          <label><input type="checkbox" id="remoto-d" ${est.openai_disponible ? 'checked' : 'disabled'}> Contrastar con OpenAI</label></div>
        <div class="botones"><button class="sec" id="ej">Lote de ensayo</button>
          <button class="sec" id="ej-nueva">Alerta nueva de ensayo</button>
          <label class="sec boton-f">Subir fichero<input type="file" id="fich" accept=".json,.jsonl,.txt" hidden></label>
          <button id="go">▶ Analizar alertas</button></div>
        <p class="sub" style="margin:8px 0 0"><small>${est.openai_disponible ? 'Con OpenAI activado, Analizar envía la alerta y una selección de evidencias para propuesta y contraste.' : 'Para una alerta nueva, carga el objeto completo con sus entidades y referencias a eventos.'}</small></p></div>
      <div class="tarjeta"><h3>2 · VIGÍA trabajando <span id="reloj-d" class="mono suave"></span></h3>
        <div id="estado-d" class="sub" role="status">Esperando alertas…</div><div id="feed" class="feed"></div><div id="res-d"></div></div>
    </div>`;
  const entrada = $('#entrada'), go = $('#go'), estado = $('#estado-d');
  entrada.value = prellenar;
  const error = texto => { estado.textContent = texto; estado.classList.add('warn'); };
  $('#ej').onclick = async () => {
    try { entrada.value = (await api('lote_ensayo')).texto; }
    catch { error('No se pudo cargar el lote de ensayo.'); }
  };
  $('#ej-nueva').onclick = async () => {
    try { entrada.value = (await api('lote_ensayo?una=true')).texto; }
    catch { error('No se pudo cargar la alerta de ensayo.'); }
  };
  $('#fich').onchange = async e => {
    const f = e.target.files[0];
    if (!f) return;
    try { entrada.value = await f.text(); }
    catch { error('No se pudo leer el archivo.'); }
  };
  go.onclick = async () => {
    const texto = entrada.value.trim(), remoto = $('#remoto-d').checked;
    if (!texto) { error('Pega o carga al menos una alerta.'); entrada.focus(); return; }
    go.disabled = true;
    estado.classList.remove('warn');
    estado.textContent = 'Preparando el lote…';
    try {
      const r = await post('analizar', {texto, modo: $('#modo-d').value, remoto});
      const j = await r.json();
      if (!r.ok || !j.trabajo) throw new Error(mensajeError(j));
      if (go.isConnected) seguir(j.trabajo);
    } catch (e) { error(e.message); go.disabled = false; }
  };
  if (jid) seguir(jid);
}

function seguir(jid) {
  let desde = 0;
  const feed = $('#feed'), resultados = $('#res-d'), estado = $('#estado-d'), reloj = $('#reloj-d'), go = $('#go');
  feed.replaceChildren(); resultados.replaceChildren(); go.disabled = true;
  const tic = async () => {
    if (!feed.isConnected) return;
    try {
      const j = await api(`trabajo/${encodeURIComponent(jid)}?desde=${desde}`);
      if (!feed.isConnected) return;
      desde = Number(j.total_pasos) || desde;
      for (const p of j.pasos || []) {
        const d = document.createElement('div');
        d.className = 'fp ' + p.tipo;
        d.innerHTML = `<span>${esc(PASO_ICONO[p.tipo] || '•')}</span><div>${esc(pasoTxt(p))}${p.tipo === 'herramienta' && p.resultado ? `<small>${esc(String(p.resultado).slice(0, 140))}</small>` : ''}</div>`;
        feed.appendChild(d);
      }
      feed.scrollTop = feed.scrollHeight;
      reloj.textContent = `${j.segundos} s`;
      if (j.estado === 'terminado') {
        estado.innerHTML = `<span class="ok">✓ ${j.tickets.length} de ${esc(j.alertas)} alerta(s) investigadas en ${esc(j.segundos)} s</span>`;
        resultados.innerHTML = (j.cerradas?.length ? `<h4 class="dec-tit">Cierres registrados</h4>${j.cerradas.map(c => `<div class="paso"><span class="mono">${esc(c.alert_id)}</span> · ${esc(c.reason)}</div>`).join('')}` : '') +
          (j.tickets?.length ? `<h4 class="dec-tit">Alertas investigadas</h4><div class="casos3">${j.tickets.map(tarjetaCaso).join('')}</div>` : '');
        go.disabled = false;
      } else if (j.estado === 'error') {
        throw new Error(j.error || 'El análisis se interrumpió.');
      } else {
        estado.innerHTML = `<span class="pulso"></span> ${esc(j.estado)}…`;
        setTimeout(tic, 800);
      }
    } catch (e) {
      estado.innerHTML = `<span class="warn">${esc(e.message)}</span>`;
      go.disabled = false;
    }
  };
  tic();
}
