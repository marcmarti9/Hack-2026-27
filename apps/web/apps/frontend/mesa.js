/* Mesa operativa. El servidor conserva alertas, expedientes y asignaciones. */
async function vistaMesaDirecto(jid, prellenar = '') {
  const initialRoute = location.hash;
  const settings = await api('estado');
  if (location.hash !== initialRoute) return;
  const view = $('#vista');
  view.innerHTML = `<section class="mesa" aria-labelledby="mesa-titulo">
    <header class="mesa-heading"><div><h2 id="mesa-titulo">Analizar en directo</h2>
      <p>Importa alertas y revisa el informe de cada investigación.</p></div></header>
    <div class="mesa-intake">
      <form class="mesa-import">
        <h3>Nuevo lote</h3>
        <label class="mesa-label" for="mesa-texto">Alertas en formato JSON o JSONL</label>
        <textarea id="mesa-texto" name="texto" rows="2" placeholder="Pega las alertas o sus identificadores" spellcheck="false"></textarea>
        <div class="mesa-toolbar">
          <label for="mesa-archivo" class="mesa-button mesa-secondary">Cargar archivo</label>
          <input type="file" id="mesa-archivo" accept=".json,.jsonl,.txt" class="mesa-file-input">
          <button type="button" class="mesa-button mesa-secondary" data-sample>Lote de ensayo</button>
          <button type="button" class="mesa-button mesa-secondary" data-sample-one>Alerta nueva de ensayo</button>
          <label>Turno <select name="modo"><option value="guardia">Guardia</option><option value="diurno">Horario atendido</option></select></label>
          <label><input type="checkbox" name="remoto" ${settings.openai_disponible ? '' : 'disabled'}> Contrastar con OpenAI</label>
          <button class="mesa-button mesa-primary" type="submit">Analizar lote</button>
        </div>
        <p class="mesa-source" data-source>Hasta 150 alertas y 1 MB por lote.</p>
      </form>
      <section class="mesa-progress" aria-labelledby="mesa-progreso">
        <h3 id="mesa-progreso">Progreso del lote</h3>
        <p role="status" data-progress>Esperando un lote.</p>
        <details data-progress-details hidden><summary>Actividad de Vigía</summary>
          <ol class="mesa-steps" aria-label="Actividad del análisis"></ol>
        </details>
      </section>
    </div>
    <section class="mesa-assigned" aria-labelledby="mesa-asignadas">
      <h3 id="mesa-asignadas">Alertas asignadas</h3><div data-assigned></div>
    </section>
    <div class="mesa-filter">
      <label for="mesa-buscar" class="mesa-sr-only">Buscar una alerta</label>
      <input type="search" id="mesa-buscar" placeholder="Buscar una alerta">
      <span data-count class="mesa-count"></span>
      <p data-error class="mesa-error" role="status"></p>
    </div>
    <div class="mesa-scroll" tabindex="0" aria-label="Cola de alertas del análisis en directo">
      <table class="mesa-table"><caption class="mesa-sr-only">Alertas del análisis en directo</caption>
        <thead><tr>
          <th scope="col" data-column="primera"><button type="button">Hora</button></th>
          <th scope="col" data-column="title"><button type="button">Nombre</button></th>
          <th scope="col" data-column="severity"><button type="button">Severidad</button></th>
          <th scope="col" data-column="estado"><button type="button">Estado</button></th>
          <th scope="col" data-column="verdict"><button type="button">Veredicto</button></th>
          <th scope="col" data-column="asignado"><button type="button">Asignado</button></th>
          <th scope="col">Acciones</th>
        </tr></thead><tbody></tbody>
      </table>
    </div>
  </section>`;

  const root = view.querySelector('.mesa');
  const find = selector => root.querySelector(selector);
  const form = find('.mesa-import');
  const input = form.elements.texto;
  const submit = form.querySelector('[type="submit"]');
  const progress = find('[data-progress]');
  const progressDetails = find('[data-progress-details]');
  const steps = find('.mesa-steps');
  const rows = find('tbody');
  const search = find('#mesa-buscar');
  const errorBox = find('[data-error]');
  const assigned = find('[data-assigned]');
  const source = find('[data-source]');
  const date = new Intl.DateTimeFormat('es-ES', {
    timeZone: 'Europe/Madrid', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
  const states = {
    pendiente: 'Pendiente', en_curso: 'En curso', investigada: 'Investigada',
    escalada: 'Escalada', cerrada: 'Cerrada', interrumpida: 'Interrumpida', error: 'Error',
  };
  const levels = ['informational', 'low', 'medium', 'high', 'critical'];
  const details = document.createElement('tr');
  details.className = 'mesa-expanded';
  details.innerHTML = '<td colspan="7"><section id="mesa-expediente" aria-label="Expediente de la alerta"></section></td>';
  const reportPanel = details.querySelector('section');
  let alerts = [];
  let snapshot = '';
  let fileName = '';
  let sort = {field: 'primera', direction: -1};
  let expanded = null;
  let reportRequest = 0;
  let jobId = jid || null;
  let cursor = 0;
  let busy = false;
  let polling = false;
  let timer;
  input.value = prellenar;

  const label = row => states[row.estado] || row.estado || 'Pendiente';
  const assignee = row => row.rol || row.asignado || (row.decision === 'automatic' ? 'Vigía' : '');
  const myAssignee = () => 'analista.' + rol().toLowerCase();
  const sameRole = row => row.rol === rol() || row.asignado === myAssignee();
  const err = message => { errorBox.textContent = message; };
  const fieldValue = (row, field) => {
    if (field === 'severity') return levels.indexOf(row.severity);
    if (field === 'primera') return Date.parse(row.primera) || 0;
    if (field === 'estado') return label(row);
    if (field === 'verdict') return row.verdict ? veredicto(row.verdict) : '';
    if (field === 'asignado') return assignee(row);
    return row[field] || '';
  };

  function renderRows() {
    const term = search.value.trim().toLocaleLowerCase('es');
    const visible = alerts.filter(row => [row.alert_id, row.title, severidades[row.severity],
      label(row), veredicto(row.verdict), assignee(row)]
      .some(value => String(value || '').toLocaleLowerCase('es').includes(term)));
    visible.sort((a, b) => {
      const first = fieldValue(a, sort.field);
      const second = fieldValue(b, sort.field);
      const difference = typeof first === 'number' ? first - second : first.localeCompare(second, 'es');
      return sort.direction * difference;
    });

    const focus = document.activeElement;
    const focusedAction = focus?.dataset?.mesaAction;
    const focusedId = focus?.closest('tr[data-alert]')?.dataset.alert;
    details.remove();
    rows.innerHTML = visible.map(row => {
      const opened = expanded === row.alert_id;
      const when = Date.parse(row.primera);
      const verdict = row.verdict ? veredicto(row.verdict) : '—';
      const assigneeLabel = assignee(row) || '—';
      const canAssign = row.estado !== 'cerrada' && (!row.asignado || sameRole(row));
      return `<tr data-alert="${esc(row.alert_id)}" class="mesa-alert-row${opened ? ' mesa-open' : ''}">
        <td><time datetime="${esc(row.primera)}">${Number.isFinite(when) ? esc(date.format(when)) : '—'}</time>
          ${row.fuera_de_horario ? '<small>Fuera de horario</small>' : ''}</td>
        <td><button type="button" class="mesa-name" data-mesa-action="detail" aria-expanded="${opened}"${opened ? ' aria-controls="mesa-expediente"' : ''}>${esc(row.title)}</button>
          <small class="mono">${esc(row.alert_id)}</small></td>
        <td><span class="mesa-severity" data-level="${esc(row.severity)}">${esc(severidades[row.severity] || 'Sin evaluar')}</span></td>
        <td><span class="mesa-pill" data-state="${esc(row.estado)}">${esc(label(row))}</span></td>
        <td><span class="mesa-verdict" data-verdict="${esc(row.verdict || '')}">${esc(verdict)}</span>
          ${row.provisional ? '<small>Sin corroborar</small>' : ''}
          ${row.fiscal ? `<small>Fiscal: ${esc(row.fiscal)}</small>` : ''}</td>
        <td>${esc(assigneeLabel)}</td>
        <td><div class="mesa-actions">
          ${canAssign ? `<button type="button" class="mesa-action" data-mesa-action="assign">${sameRole(row) ? 'Liberar' : 'Asignarme'}</button>` : ''}
          <button type="button" class="mesa-action" data-mesa-action="toggle" aria-expanded="${opened}"${opened ? ' aria-controls="mesa-expediente"' : ''}>${opened ? 'Ocultar' : 'Ver'}</button>
        </div></td></tr>`;
    }).join('') || `<tr class="mesa-empty"><td colspan="7">${term ? 'No hay alertas que coincidan con la búsqueda.' : 'La cola está vacía. Carga un lote para empezar.'}</td></tr>`;
    const selected = Array.from(rows.querySelectorAll('[data-alert]')).find(row => row.dataset.alert === expanded);
    if (selected) selected.after(details);
    if (focusedAction && focusedId) {
      const row = Array.from(rows.querySelectorAll('[data-alert]')).find(item => item.dataset.alert === focusedId);
      const control = Array.from(row?.querySelectorAll('[data-mesa-action]') || []).find(button => button.dataset.mesaAction === focusedAction);
      control?.focus({preventScroll: true});
    }
    find('[data-count]').textContent = `${visible.length} de ${alerts.length} alertas`;
    root.querySelectorAll('[data-column]').forEach(th => {
      const active = th.dataset.column === sort.field;
      th.setAttribute('aria-sort', active ? (sort.direction === 1 ? 'ascending' : 'descending') : 'none');
    });
    const mine = alerts.filter(sameRole);
    assigned.innerHTML = mine.length
      ? `<ul>${mine.map(row => `<li><button type="button" class="mesa-name" data-assigned-alert="${esc(row.alert_id)}">${esc(row.title)} <span>${esc(row.alert_id)}</span></button></li>`).join('')}</ul>`
      : '<p>No tienes alertas asignadas. Usa «Asignarme» en una fila para hacer seguimiento.</p>';
  }

  async function showReport(row) {
    const request = ++reportRequest;
    if (!row.ticket_id) {
      reportPanel.textContent = row.error || (row.estado === 'pendiente'
        ? 'La alerta está en cola. El informe estará disponible al finalizar.'
        : 'La investigación todavía no ha guardado un informe.');
      return;
    }
    reportPanel.textContent = 'Cargando expediente…';
    try {
      const ticket = await api('tickets/' + encodeURIComponent(row.ticket_id));
      if (request !== reportRequest || expanded !== row.alert_id || !root.isConnected) return;
      const report = ticket.expediente || {};
      const events = Array.isArray(report.evidence) ? report.evidence : [];
      const declared = report.declared_evidence;
      reportPanel.innerHTML = `<div class="mesa-report-heading">
        <div><h3>Expediente de ${esc(row.alert_id)}</h3><p>${esc(report.summary || ticket.summary || row.summary)}</p></div>
        <div class="mesa-actions"><a class="mesa-action" href="${enlace('caso', row.ticket_id)}">Abrir expediente</a>
        <a class="mesa-action" href="/api/expediente/${encodeURIComponent(row.alert_id)}" download>Descargar JSON</a></div>
      </div>
      ${row.error ? `<p class="mesa-error">${esc(row.error)} Se muestra el último informe guardado.</p>` : ''}
      ${row.motivo_cierre ? `<p><strong>Motivo de cierre</strong> · ${esc(row.motivo_cierre)}</p>` : ''}
      ${expedienteHTML(ticket)}
      <div class="mesa-report-grid">
        <section class="mesa-evidence"><h4>Evidencia recuperada</h4>
          ${events.length ? `<ul>${events.map(event => `<li><button type="button" class="mesa-name prueba" data-event="${esc(event.event_id)}">${esc(event.event_id)}</button> · ${esc(event.finding || event.source)}</li>`).join('')}</ul>` : '<p>El índice no devolvió registros para verificar esta alerta.</p>'}
          <div data-event-output role="status" hidden></div>
        </section>
        <section class="mesa-evidence"><h4>Declarada por el sensor</h4>
          ${declared && typeof declared === 'object' && Object.keys(declared).length
            ? `<p>Contenido aportado en la alerta, pendiente de corroboración.</p>${registroHTML(declared)}`
            : '<p>La alerta no aportó evidencia declarada adicional.</p>'}
        </section>
      </div>`;
      const output = reportPanel.querySelector('[data-event-output]');
      reportPanel.querySelectorAll('[data-event]').forEach(button => {
        button.addEventListener('click', () => mostrarEvento(button.dataset.event, output));
      });
    } catch {
      if (request === reportRequest) reportPanel.textContent = 'No se pudo cargar el expediente. Vuelve a abrir la alerta.';
    }
  }

  function open(row, toggle = true) {
    if (toggle && expanded === row.alert_id) {
      expanded = null;
      ++reportRequest;
      renderRows();
      return;
    }
    expanded = row.alert_id;
    renderRows();
    showReport(row);
  }

  async function assign(row, button) {
    button.disabled = true;
    err('');
    try {
      const response = await post('directo/' + encodeURIComponent(row.alert_id) + '/asignacion',
        {rol: rol(), asignarme: !sameRole(row)}, 'PUT');
      const body = await response.json();
      if (!response.ok) throw new Error(mensajeError(body));
      await updateQueue();
    } catch (failure) { err(failure.message); }
    finally { button.disabled = false; }
  }

  rows.addEventListener('click', event => {
    if (event.target.closest('.mesa-expanded')) return;
    const row = alerts.find(item => item.alert_id === event.target.closest('[data-alert]')?.dataset.alert);
    if (!row) return;
    const button = event.target.closest('[data-mesa-action]');
    if (button?.dataset.mesaAction === 'assign') assign(row, button);
    else open(row);
  });
  assigned.addEventListener('click', event => {
    const row = alerts.find(item => item.alert_id === event.target.closest('[data-assigned-alert]')?.dataset.assignedAlert);
    if (!row) return;
    search.value = '';
    open(row, false);
    details.scrollIntoView({block: 'nearest'});
  });
  search.addEventListener('input', renderRows);
  root.querySelectorAll('[data-column] button').forEach(button => {
    button.addEventListener('click', () => {
      const field = button.parentElement.dataset.column;
      sort = {field, direction: sort.field === field ? -sort.direction : 1};
      renderRows();
    });
  });

  function setSource(name) {
    fileName = name;
    source.textContent = name ? `Archivo seleccionado: ${name}` : 'Hasta 150 alertas y 1 MB por lote.';
  }

  find('#mesa-archivo').addEventListener('change', async event => {
    const control = event.target;
    const file = control.files[0];
    control.value = '';
    if (!file) return;
    if (file.size > 1000000) { err('El archivo supera el límite de 1 MB.'); return; }
    try { input.value = await file.text(); setSource(file.name.slice(0, 160)); err(''); }
    catch { err('No se pudo leer el archivo.'); }
  });
  input.addEventListener('input', () => setSource(''));
  async function loadSample(single) {
    try {
      input.value = (await api('lote_ensayo' + (single ? '?una=true' : ''))).texto;
      setSource(single ? 'alerta-de-ensayo.jsonl' : 'lote-de-ensayo.jsonl');
      err('');
    } catch { err('No se pudo cargar el ensayo.'); }
  }
  find('[data-sample]').addEventListener('click', () => loadSample(false));
  find('[data-sample-one]').addEventListener('click', () => loadSample(true));

  function follow(id) {
    jobId = id;
    cursor = 0;
    steps.replaceChildren();
    progressDetails.hidden = true;
    submit.disabled = Boolean(id);
  }

  async function updateQueue() {
    const queue = await api('directo');
    if (!root.isConnected) return;
    const next = queue.alertas || [];
    const signature = JSON.stringify(next);
    if (signature !== snapshot) {
      const selectedBefore = alerts.find(row => row.alert_id === expanded);
      alerts = next;
      snapshot = signature;
      renderRows();
      const selected = next.find(row => row.alert_id === expanded);
      if (selected && JSON.stringify(selected) !== JSON.stringify(selectedBefore)) showReport(selected);
    }
    if (!jobId && queue.trabajo) follow(queue.trabajo);
    if (!jobId && !busy) submit.disabled = false;
  }

  async function refreshJob() {
    if (!jobId) return;
    const id = jobId;
    const job = await api('trabajo/' + encodeURIComponent(id) + '?desde=' + cursor);
    if (!root.isConnected || jobId !== id) return;
    for (const step of job.pasos || []) {
      const item = document.createElement('li');
      item.textContent = pasoTxt(step);
      steps.appendChild(item);
    }
    cursor = job.total_pasos;
    progressDetails.hidden = !steps.children.length;
    const total = `${job.tickets.length} de ${job.alertas} investigadas · ${job.segundos} s`;
    if (job.fin != null) {
      jobId = null;
      progress.textContent = job.estado === 'error' ? 'El lote terminó con errores.' : total;
      if (job.error) err(job.error);
      return;
    }
    progress.textContent = `${total} · ${job.estado}`;
  }

  async function poll() {
    if (!root.isConnected || polling) return;
    polling = true;
    try {
      await updateQueue();
      await refreshJob();
    } catch (failure) {
      if (jobId && failure.message === '404') {
        jobId = null;
        progress.textContent = 'El progreso de este lote ya no está disponible. Los informes guardados siguen en la mesa.';
      } else {
        err('No se pudo actualizar la mesa. Se volverá a intentar.');
      }
    } finally {
      polling = false;
      submit.disabled = busy || Boolean(jobId);
      if (root.isConnected) timer = setTimeout(poll, jobId ? 800 : 3500);
    }
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || jobId) return;
    const texto = input.value.trim();
    if (!texto) { err('Selecciona un archivo o pega al menos una alerta.'); return; }
    if (new TextEncoder().encode(texto).length > 1000000) { err('El lote supera el límite de 1 MB.'); return; }
    busy = true;
    submit.disabled = true;
    err('');
    try {
      const response = await post('analizar', {
        texto, modo: form.elements.modo.value, remoto: form.elements.remoto.checked, archivo: fileName,
      });
      const body = await response.json();
      if (!response.ok || !body.trabajo) throw new Error(mensajeError(body));
      if (!root.isConnected) return;
      follow(body.trabajo);
      progress.textContent = 'Lote recibido. Preparando la investigación.';
      clearTimeout(timer);
      await poll();
    } catch (failure) { err(failure.message); }
    finally { busy = false; submit.disabled = Boolean(jobId); }
  });
  renderRows();
  await poll();
}
