// VIGÍA · componentes visuales: historia del ataque, playbooks guiados y lo descartado
const FASE_COLOR = {'Acceso inicial': 'var(--marca)', 'Ejecución': 'var(--marca)', 'Persistencia': 'var(--naranja)',
  'Robo de credenciales': 'var(--rojo)', 'Descubrimiento': 'var(--suave)', 'Movimiento lateral': 'var(--naranja)',
  'Recogida de datos': 'var(--suave)', 'Mando y control': 'var(--naranja)', 'Exfiltración': 'var(--rojo)',
  'Deterioro de defensas': 'var(--rojo)', 'Impacto': 'var(--rojo)'};
const colorFase = fase => FASE_COLOR[fase] || 'var(--suave)';
const guardar = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} };
const cargar = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch (e) { return d; } };

function chipEntidad(e) {
  if (e.tipo === 'ip') {
    const i = e.info || {}, mala = i.reputacion === 'malicious', sosp = i.reputacion === 'suspicious';
    const tip = [i.pais, i.org, i.tipo, i.reputacion && `TIP: ${i.reputacion}${i.familia ? ' · ' + i.familia : ''}`].filter(Boolean).join(' · ');
    return `<span class="ent ip ${mala ? 'mala' : sosp ? 'sosp' : ''}" title="${esc(tip)}">${esc(e.valor)}${i.pais ? ' · ' + esc(i.pais) : ''}${i.tipo ? ' · ' + esc(i.tipo) : ''}${mala ? ' · ' + esc(i.familia || 'maliciosa') : ''}</span>`;
  }
  return `<span class="ent ${esc(e.tipo)}">${esc(e.valor)}</span>`;
}

function historiaHTML(L) {
  if (!L || !L.pasos.length) return '';
  const alcanzadas = L.fases.filter(f => f.n).length;
  const hitos = L.pasos.filter(p => p.hito).length;
  return `<div class="tarjeta historia" id="historia">
    <div class="hist-cab"><div><h3>Cronología</h3><p class="sub" style="margin:0">Abre un registro para ver sus datos originales. Filtra por fase o fuente.</p></div>
      <div class="hist-kpis">
        <div><b>${esc(L.duracion || '—')}</b><small>de principio a fin</small></div>
        <div><b>${alcanzadas}</b><small>fases en el informe N2</small></div>
        <div><b>${L.pasos.length}</b><small>pasos · ${hitos} alertas</small></div>
        <div><b class="${L.fuera_de_horario ? 'rojo' : ''}">${fmt(L.fuera_de_horario)}</b><small>con el SOC cerrado</small></div>
      </div></div>
    ${alcanzadas ? `<div class="cadena">${L.fases.filter(f => f.n).map(f => `<button class="fase on" data-fase="${esc(f.fase)}" style="--c:${colorFase(f.fase)}"
        title="${fmt(f.n)} pasos · desde ${esc(f.primera)}"><span>${esc(f.fase)}</span><b>${fmt(f.n)}</b></button>`).join('')}</div>` : ''}
    <div class="filtros"><button class="vista-btn" id="ver-todo">Ver los ${L.pasos.length} pasos</button><span class="sep"></span>
      <button class="filtro activo" data-fuente="">Todas las fuentes</button>${L.fuentes.map(f => `<button class="filtro" data-fuente="${esc(f)}">${esc(f)}</button>`).join('')}</div>
    <div class="tl2 resumen">${L.pasos.map((p, i) => {
      const prev = L.pasos[i - 1], salto = prev ? (Date.parse(p.ts) - Date.parse(prev.hasta || prev.ts)) / 36e5 : 0;
      return `${salto >= 3 ? `<div class="hueco">··· ${salto >= 48 ? Math.round(salto / 24) + ' días' : Math.round(salto) + ' h'} después ···</div>` : ''}
      <div class="paso2 ${p.hito ? 'hito' : ''} ${p.hito || !L.pasos.slice(0, i).some(q => q.fase === p.fase) ? 'clave' : ''}" data-f="${esc(p.fase)}" data-src="${esc(p.fuente_nombre)}" data-evr="${p.hito ? '' : esc(p.id)}" style="--c:${colorFase(p.fase)}">
        <div class="cuando">${esc(p.hora_local.slice(0, 5))}<b>${esc(p.hora_local.slice(6))}</b>${p.fuera_de_horario ? '<span>Guardia</span>' : ''}</div>
        <div class="nodo"></div>
        <div class="cuerpo">
          <div class="meta2"><span class="fuente">${esc(p.fuente_nombre)}</span><span class="tag-fase">${esc(p.fase)}</span>
            ${p.tactica_declarada ? `<span class="suave">Táctica de la regla · ${esc(p.tactica_declarada)}</span>` : ''}
            ${p.mitre ? `<span class="mono suave">${esc(p.mitre)}</span>` : ''}${p.hito ? sev(p.severidad) : ''}
            ${p.repeticiones > 1 ? `<span class="rep">×${fmt(p.repeticiones)}</span>` : ''}
            ${p.hito ? `<span class="mono suave id">${esc(p.id)}</span>` : `<button type="button" class="sec prueba mono id" aria-expanded="false" aria-label="Ver registro ${esc(p.id)}">${esc(p.id)}</button>`}</div>
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
  box.querySelectorAll('.paso2[data-evr]').forEach(p => {
    if (!p.dataset.evr) return;
    p.onclick = async event => {
      if (event.target.closest('.raw')) return;
      const destino = p.querySelector('.raw'), button = p.querySelector('button.id');
      const opening = destino.hidden;
      button.setAttribute('aria-expanded', String(opening));
      if (opening) await mostrarEvento(p.dataset.evr, destino);
      else destino.hidden = true;
    };
  });
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

function origenEvidencia(event, report) {
  if (event.verified ?? report.criterio_verificado?.citations?.includes(event.event_id)) return 'Verificada por regla';
  const citations = (event.cited_by || []).map(role => ({proposal: 'propuesta', review: 'contraste'})[role]).filter(Boolean);
  if (citations.length) return 'Citada en ' + citations.join(' y ');
  return event.cited ? 'Citada en el expediente' : 'Registro de contexto';
}

const nombresInteligencia = {kev: 'CISA KEV', cve: 'Lista CVE'};

function inteligenciaHTML(matches) {
  if (!matches?.length) return '';
  return `<section class="vigia-report-section">
    <h3>Inteligencia de vulnerabilidades</h3>
    <p class="vigia-report-muted">Cruce del inventario con avisos públicos consultados al investigar.</p>
    <ul class="vigia-report-queries">${matches.map(match => {
      const kev = match.source === 'kev';
      const url = kev ? 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
        : 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(match.cve);
      const signal = kev ? 'Explotación observada' + (match.ransomware === 'known' ? ' · vinculada a ransomware' : '')
        : match.state === 'REJECTED' ? 'Registro rechazado' : 'Aviso actualizado';
      return `<li><div><a class="prueba mono" href="${url}" target="_blank" rel="noreferrer">${esc(match.cve)}</a>
        <p>${esc(match.asset)} · ${signal}</p>
        <p>${esc(nombresInteligencia[match.source])} · ${esc(match.error ? 'Copia anterior del ' : 'Consultada el ')}${esc(hora(match.fetched_at))}</p>
      </div></li>`;
    }).join('')}</ul>
  </section>`;
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
  const fuentesConsultadas = [...new Set(consultas.map(c => c.tool).filter(Boolean))];
  const citasDecisivas = [...(crit.citations || []), ...(crit.sandbox_refs || [])];
  const paso = numero => `<span class="vigia-report-step" aria-hidden="true">${numero}</span>`;
  const duracion = informe.timing_ms == null ? ''
    : informe.timing_ms < 1000 ? `${fmt(informe.timing_ms)} ms`
      : `${(informe.timing_ms / 1000).toLocaleString('es-ES', {maximumFractionDigits: 1})} s`;
  const desplegable = (nombre, contenido) => contenido
    ? `<details class="vigia-report-fold"><summary>${nombre}</summary><div class="vigia-report-fold-content">${contenido}</div></details>`
    : '';
  const registro = (nombre, dato) => desplegable(nombre, dato && Object.keys(dato).length ? registroHTML(dato) : '');
  const contexto = [
    registro('Enriquecimiento del índice', informe.enrichment),
    registro('Vulnerabilidades', informe.vulnerabilities),
    registro('Entidades declaradas', informe.declared_entities),
    registro('Discrepancias de entidades', informe.entity_discrepancies),
    registro('Alertas relacionadas', informe.related_alerts),
    registro('Técnicas MITRE', informe.mitre),
    registro('Alcance del incidente N2', informe.incident?.scope),
  ].join('');
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
        ${etiqueta(`Confianza ${ayudaHTML('la confianza del triaje', 'En el triaje local refleja el respaldo de las pruebas. Si se valida el contraste de Vigía, muestra su estimación.')}`, estimada ? `${Math.round(informe.confidence * 100)} %` : 'Sin estimación')}
        ${etiqueta('Duración', duracion)}
        ${etiqueta('Plazo', !automatica && hora(ruta.deadline_at))}
        ${etiqueta('Responsables', ruta.recipients?.join(' · '), 'vigia-report-owners')}
        ${humana ? etiqueta('Ruta de triaje', [disposicion(ruta.recommendation), ruta.reason !== motivo ? ruta.reason : ''].filter(Boolean).join(' · '), 'vigia-report-owners') : ''}
      </dl>
    </section>
    <section class="vigia-report-rationale" aria-label="Cómo se llegó a la decisión">
      <h3>Cómo se llegó a la decisión</h3>
      <div class="vigia-report-stage">
        <h4>${paso('01')} Datos consultados</h4>
        <p class="vigia-report-muted">${esc(fuentesConsultadas.slice(0, 4).join(' · ') || 'El expediente no conserva consultas al índice.')}
          ${fuentesConsultadas.length > 4 ? ` · ${fmt(fuentesConsultadas.length - 4)} más` : ''}</p>
        <details class="vigia-report-fold vigia-report-index">
          <summary>Consultas al índice <span class="vigia-report-count">${fmt(consultas.length)}</span></summary>
          ${consultas.length ? `<ul class="vigia-report-queries">${consultas.map(c => `<li>
            <div><strong>${esc(c.tool || c)}</strong>${c.query ? `<p>${esc(c.query)}</p>` : ''}${c.note ? `<p>${esc(c.note)}</p>` : ''}</div>
            ${c.count != null ? `<span>${fmt(c.count)} ${c.count === 1 ? 'resultado' : 'resultados'}</span>` : ''}
          </li>`).join('')}</ul>` : '<p class="vigia-report-muted">Sin consultas registradas.</p>'}
        </details>
      </div>
      <div class="vigia-report-grid">
      <section class="vigia-report-section">
        <h4>${paso('02')} Hallazgos y contexto</h4>
        <div class="vigia-report-observation">
          <span class="vigia-report-marker ${corroborado ? 'verificado' : ''}"></span>
          <div><strong>${corroborado ? 'Hallazgo corroborado' : 'Sin hallazgo corroborado'}</strong>
            <p>${esc(crit.summary || (recuperados ? 'Los registros recuperados aportan contexto para seguir investigando.'
              : 'El índice no devolvió registros para verificar esta alerta.'))}</p></div>
        </div>
        ${citasDecisivas.length ? `<p class="vigia-report-citations">Citas decisivas · ${citasDecisivas.slice(0, 3).map(id => `<code>${esc(id)}</code>`).join(' · ')}${citasDecisivas.length > 3 ? ` · ${fmt(citasDecisivas.length - 3)} más` : ''}</p>` : ''}
        ${preguntas.length ? desplegable('Qué falta por comprobar', registroHTML(preguntas)) : ''}
        ${registro('Criterio y referencias', crit)}
        ${desplegable('Contexto técnico', contexto)}
      </section>
      <section class="vigia-report-section">
        <h4>${paso('03')} Propuesta y revisión adversarial ${ayudaHTML('la revisión adversarial', 'La segunda revisión busca pruebas en contra y comprueba si las citas respaldan la propuesta inicial.')}</h4>
        <ol class="vigia-report-review">
          <li><strong>${fuente === 'Reglas locales' ? 'Comprobación local' : 'Primera propuesta'}</strong>
            <span>${fuente === 'Reglas locales' ? 'Reglas locales' : fuente ? 'Vigía' : 'Sin proveedor registrado'}</span>
            ${fuente && fuente !== 'Reglas locales' && propuesta.summary ? `<p>${esc(textoVigia(propuesta.summary))}</p>` : ''}
            ${registro('Propuesta registrada', propuesta)}
          </li>
          <li><strong>${informe.review_provider ? 'Contraste del fiscal' : 'Contraste de la evidencia'}</strong>
            <span>${informe.review_provider ? 'Vigía' : tieneContraste ? 'Verificación de los registros' : 'Sin contraste registrado'}</span>
            ${informe.review_reason ? `<p>${esc(informe.review_reason)}</p>` : ''}
            ${contraste.summary ? `<p>${esc(textoVigia(contraste.summary))}</p>` : ''}
            ${registro('Contraste registrado', contraste)}
          </li>
        </ol>
        ${tieneLimites ? `<div class="vigia-report-limit"><strong>Límites de la revisión</strong>
          ${errores.proposal ? `<p><b>Propuesta</b> · ${esc(textoVigia(errores.proposal))}</p>` : ''}
          ${errores.review ? `<p><b>Contraste</b> · ${esc(textoVigia(errores.review))}</p>` : ''}
          ${registro('Registro de incidencias', Object.fromEntries(Object.entries(errores).filter(([fase]) => !['proposal', 'review'].includes(fase))))}
        </div>` : ''}
        ${!tienePropuesta && !tieneContraste ? '<p class="vigia-report-muted">Este expediente se limita a las consultas y evidencias registradas.</p>' : ''}
      </section>
      </div>
      <div class="vigia-report-stage">
        <h4>${paso('04')} Criterio aplicado</h4>
        <p class="vigia-report-muted">${esc(informe.severity_rationale || ruta.reason || 'El expediente no conserva el criterio de prioridad.')}</p>
        ${crit.basis && crit.basis !== motivo ? `<p class="vigia-report-muted">${esc(crit.basis)}</p>` : ''}
      </div>
    </section>
    ${inteligenciaHTML(informe.threat_intel)}
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
    ${(t.historial || []).map(h => {
      const actor = h.kind === 'Análisis' && !['Reglas locales', 'Local'].includes(h.actor) ? 'Vigía' : h.actor;
      return `<div class="paso"><b>${esc(h.kind)}</b> · ${esc(actor)} · ${esc(hora(h.created_at))}${h.reason ? `<br>${esc(textoVigia(h.reason))}` : ''}</div>`;
    }).join('') || '<p class="sub">Sin cambios de historial registrados.</p>'}</div>`;
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
  const block = $('#guia-editable'), path = 'documentos/' + encodeURIComponent(name);
  let doc;
  try { doc = await api(path); }
  catch {
    block.textContent = 'No se pudo abrir el documento del agente.';
    return;
  }
  if (!block.isConnected) return;
  const editable = rol() !== 'N1';
  block.innerHTML = `<div class="pb-editor-bar">
    <div><h3 id="pb-doc-title">Documento del agente</h3>
      <p><code>${esc(name)}.md</code> <span data-revision></span></p></div>
    ${editable ? '<button type="button" class="sec pb-doc-edit">Editar documento</button>' : '<span class="pb-readonly">Solo lectura</span>'}
  </div>
  <pre class="pb-doc-body" aria-labelledby="pb-doc-title"></pre>
  ${editable ? `<form hidden>
    <label for="pb-doc-input">Texto Markdown</label>
    <textarea id="pb-doc-input" spellcheck="false" maxlength="16000" required></textarea>
    <div class="pb-editor-actions"><button type="submit">Guardar revisión</button><button type="button" class="sec pb-doc-cancel">Cancelar</button></div>
  </form>` : ''}
  <p class="pb-editor-status" role="status"></p>`;
  const preview = block.querySelector('.pb-doc-body');
  const revision = block.querySelector('[data-revision]');
  const status = block.querySelector('[role="status"]');
  function renderDocument() {
    revision.textContent = `Revisión ${doc.revision}`;
    const fragment = document.createDocumentFragment();
    doc.texto.split('\n').forEach((line, i) => {
      if (i) fragment.append('\n');
      if (/^#{1,6}\s/.test(line)) {
        const heading = document.createElement('span');
        heading.className = 'pb-doc-heading';
        heading.textContent = line;
        fragment.append(heading);
      } else fragment.append(line);
    });
    preview.replaceChildren(fragment);
  }
  renderDocument();
  if (!editable) return;
  const form = block.querySelector('form'), input = form.querySelector('textarea');
  const edit = block.querySelector('.pb-doc-edit'), cancel = block.querySelector('.pb-doc-cancel');
  const save = form.querySelector('[type="submit"]');
  function setEditing(editing) {
    if (editing) input.value = doc.texto;
    form.hidden = !editing;
    preview.hidden = editing;
    edit.hidden = editing;
    (editing ? input : edit).focus();
  }
  edit.onclick = () => { status.textContent = ''; setEditing(true); };
  cancel.onclick = () => { status.textContent = ''; setEditing(false); };
  form.onsubmit = async event => {
    event.preventDefault();
    save.disabled = cancel.disabled = input.readOnly = true;
    status.textContent = 'Guardando revisión…';
    try {
      const r = await post(path, {revision: doc.revision, texto: input.value, rol: rol()}, 'PUT');
      const saved = await r.json();
      if (!r.ok) throw new Error(mensajeError(saved));
      doc = saved;
      renderDocument();
      setEditing(false);
      status.textContent = 'Revisión guardada.';
    } catch (error) { status.textContent = error.message; }
    finally { save.disabled = cancel.disabled = input.readOnly = false; }
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
  return `<div class="playbook pb-case" data-pb="${esc(pbk.id)}" data-t="${esc(tid)}">
    <div class="pb-case-heading"><div><code>${esc(pbk.id)}</code><h3>${esc(pbk.titulo)}</h3></div>
      <div class="pb-case-progress"><b aria-live="polite"><span data-count>${hechos}</span>/${pbk.total}</b>
        <small>Comprobaciones hechas</small><progress value="${hechos}" max="${pbk.total || 1}" aria-label="Comprobaciones hechas"></progress></div></div>
    <p class="pb-description">Vigía completó <b>${pbk.hechos}</b> comprobaciones con los datos. Marca las pendientes cuando las hagas.</p>
    <ol class="pb-steps">${pbk.pasos.map(s => {
      const propio = Boolean(marcas[s.n]), comprobado = s.estado === 'hecho';
      return `<li class="pb-check-row">${comprobado
        ? '<span class="pb-check-icon" aria-hidden="true">✓</span>'
        : `<button type="button" class="pb-check-icon" data-check="${s.n}" aria-pressed="${propio}" aria-label="Comprobación ${s.n}: ${esc(s.titulo)}">${propio ? '✓' : '○'}</button>`}
        <div><div class="pb-step-title"><b>${esc(s.titulo)}</b>
          <small class="pb-check-state">${comprobado ? 'Vigía' : propio ? 'Tú' : 'Pendiente'}</small></div>
          <p>${esc(s.texto)}</p>
          ${comprobado && s.hallazgo ? `<p class="pb-finding">${esc(s.hallazgo)} ${s.prueba ? `<button type="button" class="sec prueba mono" data-ev="${esc(s.prueba)}">${esc(s.prueba)}</button>` : ''}</p>` : ''}
          ${fuentesPlaybookHTML(s.fuentes)}
        </div></li>`;
    }).join('')}</ol>
    <h4>Decisión</h4>
    ${decisionesPlaybookHTML(pbk.decisiones, pbk.elegida)}
  </div>`;
}

function playbooksCasoHTML(pbs, tid) {
  if (!pbs || !pbs.length) return '';
  const act = Math.min(+(window._pbTab || 0), pbs.length - 1);
  return `<div class="pb-case-workspace">
    <div class="pb-case-tabs" role="group" aria-label="Playbooks del caso">${pbs.map((p, i) =>
      `<button type="button" data-playbook-tab="${i}" aria-pressed="${i === act}" aria-controls="pb-case-${i}">
        <code>${esc(p.id)}</code> ${esc(p.titulo.split(/[:(]/)[0])} <small>${p.hechos}/${p.total}</small></button>`).join('')}</div>
    ${pbs.map((p, i) => `<div id="pb-case-${i}" data-playbook-panel="${i}" ${i === act ? '' : 'hidden'}>${playbookHTML(p, tid)}</div>`).join('')}
  </div>`;
}

function activarPlaybooks() {
  const workspace = $('.pb-case-workspace');
  if (!workspace) return;
  const tabs = [...workspace.querySelectorAll('[data-playbook-tab]')];
  const panels = [...workspace.querySelectorAll('[data-playbook-panel]')];
  tabs.forEach(tab => tab.onclick = () => {
    window._pbTab = tab.dataset.playbookTab;
    tabs.forEach(other => other.setAttribute('aria-pressed', String(other === tab)));
    panels.forEach(panel => panel.hidden = panel.dataset.playbookPanel !== window._pbTab);
  });
  workspace.querySelectorAll('.pb-case').forEach(box => {
    const key = `vigia_pb_${box.dataset.t}_${box.dataset.pb}`, marks = cargar(key, {});
    const progress = box.querySelector('progress'), count = box.querySelector('[data-count]');
    box.querySelectorAll('[data-check]').forEach(check => check.onclick = () => {
      const checked = !marks[check.dataset.check];
      marks[check.dataset.check] = checked;
      guardar(key, marks);
      check.setAttribute('aria-pressed', String(checked));
      check.textContent = checked ? '✓' : '○';
      check.closest('li').querySelector('.pb-check-state').textContent = checked ? 'Tú' : 'Pendiente';
      progress.value += checked ? 1 : -1;
      count.textContent = progress.value;
    });
  });
}

function fuentesPlaybookHTML(fuentes) {
  return fuentes.length ? `<ul class="pb-sources" aria-label="Fuentes">${fuentes.map(f => `<li><code>${esc(f)}</code></li>`).join('')}</ul>` : '';
}

const PB_DECISION = {verde: 'Cerrar', ambar: 'Vigilar', rojo: 'Contener y escalar'};

function decisionesPlaybookHTML(decisiones, recomendada) {
  return `<ul class="pb-decisions">${decisiones.map((d, i) => `<li data-tone="${esc(d.color)}">
    <div class="pb-decision-label"><span>${PB_DECISION[d.color] || 'Decisión'}</span>
      ${i === recomendada ? '<strong>Vigía recomienda</strong>' : ''}</div>
    <p>Si: ${esc(d.condicion)}</p><p><b>${esc(d.accion)}</b></p>
  </li>`).join('')}</ul>`;
}

function exploradorPlaybooks(playbooks, active) {
  const archivos = [{id: 'SKILL', titulo: 'Guía general'}, ...playbooks];
  return `<nav class="pb-explorer" aria-label="Documentos del agente">
    ${archivos.map(p => `<a href="${enlace('playbooks', p.id)}" title="${esc(p.titulo)}" ${p.id === active ? 'aria-current="page"' : ''}>
      <code>${esc(p.id)}.md</code><span>${esc(p.titulo)}</span></a>`).join('')}
  </nav>`;
}

async function vistaPlaybooks(id) {
  const hash = location.hash;
  const view = $('#vista');
  view.innerHTML = '<p class="sub" role="status">Cargando playbooks…</p>';
  const playbooks = await api('playbooks');
  if (location.hash !== hash) return;
  if (!id) {
    view.innerHTML = `<section class="pb-page">
      <div class="pb-page-heading"><div><h2>Playbooks</h2>
        <p>Los ${playbooks.length} runbooks del SOC convertidos en guías paso a paso.</p></div>
        <a class="pb-doc-link" href="#playbooks/SKILL"><code>SKILL.md</code> Guía general <span aria-hidden="true">→</span></a>
      </div>
      <div class="pb-catalog">
        <section class="pb-workflow" aria-label="Cómo se aplica un playbook"><ol>
          <li><b>Llega una alerta</b><p>Vigía identifica el playbook según la regla del SIEM.</p></li>
          <li><b>Vigía hace las comprobaciones</b><p>Cruza logs, inventario, inteligencia y cambios, y marca cada paso con su prueba.</p></li>
          <li><b>Tú decides</b><p>Revisas lo pendiente (○) y confirmas la decisión que recomienda.</p></li>
        </ol></section>
        <ul class="pb-file-list">${playbooks.map(p => `<li><a href="${enlace('playbooks', p.id)}">
          <span class="pb-file-title"><code>${esc(p.id)}</code><b>${esc(p.titulo)}</b></span>
          <span class="pb-file-stats"><span>${p.pasos.length} pasos</span><span>${fmt(p.alertas)} alertas</span>
            <span>${p.casos.length} ${p.casos.length === 1 ? 'caso' : 'casos'}</span></span>
          <span class="pb-decision-marks" aria-label="${esc(p.decisiones.map(d => PB_DECISION[d.color]).join(', '))}" role="img">
            ${p.decisiones.map(d => `<i data-tone="${esc(d.color)}"></i>`).join('')}
          </span>
        </a></li>`).join('')}</ul>
      </div>
    </section>`;
    return;
  }
  const skill = id === 'SKILL';
  const playbook = playbooks.find(p => p.id === id);
  const header = skill ? '<h2>Guía general</h2>' : playbook
    ? `<code>${esc(playbook.id)}</code><h2>${esc(playbook.titulo)}</h2>
      <p>${fmt(playbook.alertas)} alertas este mes · ${playbook.casos.length} ${playbook.casos.length === 1 ? 'caso' : 'casos'}</p>
      ${fuentesPlaybookHTML(playbook.reglas)}` : '<h2>Playbook no disponible</h2>';
  view.innerHTML = `<section class="pb-page">
    <div class="pb-page-heading"><div><a class="prueba pb-back" href="#playbooks">← Playbooks</a>${header}</div>
      ${playbook ? '<button type="button" class="sec pb-jump">Ver documento del agente</button>' : ''}</div>
    <div class="pb-workspace">
      ${exploradorPlaybooks(playbooks, id)}
      <div class="pb-workspace-body">
        ${playbook ? `<div class="pb-runbook-detail">
          <section><h3>1 · Comprueba</h3><ol class="pb-steps">${playbook.pasos.map(s =>
            `<li><span class="pb-step-num" aria-hidden="true">${s.n}</span><div><b>${esc(s.titulo)}</b><p>${esc(s.texto)}</p>
              ${fuentesPlaybookHTML(s.fuentes)}</div></li>`).join('')}</ol></section>
          <div><section><h3>2 · Decide</h3>${decisionesPlaybookHTML(playbook.decisiones)}
            <p class="pb-description">Verde: cerrar · Ámbar: vigilar · Rojo: contener y escalar</p></section>
            <section class="pb-runbook-cases"><h3>3 · Casos reales donde se ha usado</h3>
              ${playbook.casos.map(c => `<a href="${enlace('caso', c.ticket_id)}">${sev(c.severity)} <span>${esc(c.title)}</span></a>`).join('') || '<p class="pb-description">Ningún caso este mes.</p>'}
            </section></div>
        </div>` : ''}
        ${skill || playbook ? '<section id="guia-editable" class="pb-editor" tabindex="-1"><p role="status">Cargando documento…</p></section>' : ''}
      </div>
    </div>
  </section>`;
  if (!skill && !playbook) return;
  const current = $('.pb-explorer [aria-current="page"]');
  const explorer = current.parentElement;
  if (explorer.scrollWidth > explorer.clientWidth) {
    explorer.scrollLeft = current.getBoundingClientRect().left - explorer.getBoundingClientRect().left - 8;
  }
  const jump = $('.pb-jump');
  if (jump) jump.onclick = () => $('#guia-editable').focus();
  await editorGuia(id);
}

async function vistaDescartado() {
  const hash = location.hash;
  const d = await api('descartado');
  if (location.hash !== hash) return;
  const color = {'Falsa alarma': '#5e5e5e', 'Ataque sin efecto': '#86BC25', 'Actividad autorizada': '#26890D'};
  const horas = d.grupos.reduce((s, g) => s + g.horas, 0);
  $('#vista').innerHTML = `<h2>Descartes</h2>
    <p class="sub">${fmt(d.cerradas)} de ${fmt(d.total)} alertas (${Math.round(100 * d.cerradas / Math.max(1, d.total))} %) elegibles para cierre en el barrido local. Los ejemplos enlazan al expediente con las citas.</p>
    <div class="desc-kpis">
      <div class="tarjeta"><b>${fmt(d.cerradas)}</b><small>cierres elegibles</small></div>
      <div class="tarjeta"><b>${fmt(horas)} h</b><small>estimación a 15 min por alerta</small></div>
      <div class="tarjeta"><b>${d.grupos.length}</b><small>motivos distintos</small></div>
      <div class="tarjeta ancho"><small>Tipo de descarte</small><div class="apilada">${d.tipos.map(([t, n]) => `<i style="width:${100 * n / d.cerradas}%;background:${color[t]}" title="${esc(t)}: ${fmt(n)}"></i>`).join('')}</div>
        <div class="leyenda">${d.tipos.map(([t, n]) => `<span><i style="background:${color[t]}"></i>${esc(t)} · ${fmt(n)}</span>`).join('')}</div></div>
    </div>
    <div class="motivos">${d.grupos.map((g, i) => `<div class="motivo">
      <div class="m-cab"><div class="m-t"><b>${esc(g.titulo)}</b><span class="m-tipo" style="--c:${color[g.tipo] || '#5e5e5e'}">${esc(g.tipo)}</span></div>
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

// Etiquetas de actividad del triaje y de expedientes archivados.
const HERR_TXT = {get_asset: a => `Consulta la CMDB: ${a.key}`, get_user: a => `Consulta el directorio y RRHH: ${a.key}`,
  events_for_entity: a => `Busca en los logs la actividad de ${a.value}${a.horas ? ` (±${a.horas} h)` : ''}`, search_logs: a => `Busca "${a.text}" en los logs`,
  get_intel: a => `Consulta la inteligencia sobre ${a.indicator}`, get_sandbox: a => `Consulta la sandbox (${String(a.sha256).slice(0, 12)}…)`,
  get_changes: a => `Revisa el calendario de cambios: "${a.q}"`, get_cve: a => `Cruza las CVE de ${a.host} con KEV y EPSS`,
  alerts_for_entity: a => `Busca otras alertas de ${a.value}`, get_event: a => `Lee el evento ${a.event_id}`};
const textoVigia = value => String(value ?? '')
  .replace(/\bOPENAI_API_KEY\b/gi, 'la clave de Vigía')
  .replace(/\bOpenAI\b/gi, 'Vigía');

function pasoTxt(p) {
  if (p.tipo === 'herramienta') return HERR_TXT[p.nombre] ? HERR_TXT[p.nombre](p.entrada || {}) : p.nombre;
  const text = textoVigia(p.texto);
  if (!['propuesta', 'fiscal'].includes(p.tipo)) return text;
  const [alertId, , ...detail] = text.split(' · ');
  return detail.length ? [alertId, 'Vigía', ...detail].join(' · ') : text;
}
