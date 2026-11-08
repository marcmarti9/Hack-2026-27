/* Mesa operativa. El servidor conserva alertas, expedientes y asignaciones. */
async function vistaMesaDirecto(jid, prellenar = '') {
  const initialRoute = location.hash;
  const settings = await api('estado');
  if (location.hash !== initialRoute) return;
  const view = $('#vista');
  const icon = (path, className = '') => `<svg class="${className}" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${path}"/></svg>`;
  const upload = icon('M12 16V4m-4 4 4-4 4 4M4 16v4h16v-4');
  const activity = icon('M3 12h4l3-7 4 14 3-7h4');
  const chevron = icon('m6 9 6 6 6-6', 'mesa-chevron');
  const arrow = icon('M4 12h15m-6-6 6 6-6 6', 'mesa-arrow');
  view.innerHTML = `<section class="mesa" aria-labelledby="mesa-titulo">
    <header class="mesa-heading">
      <div><h2 id="mesa-titulo">Triaje</h2>
        <p>Carga alertas del SIEM y consulta el informe de cada una.</p></div>
    </header>
    <div class="mesa-intake">
      <form class="mesa-import" aria-labelledby="mesa-nuevo">
        <div class="mesa-panel-heading">
          <h3><span id="mesa-nuevo">Nuevo lote</span> ${ayudaHTML('el nuevo lote', 'Carga un archivo JSON o JSONL del SIEM, pega alertas o usa un lote de ensayo para probar la mesa.')}</h3>
          <span class="mesa-format">JSON / JSONL</span>
        </div>
        <label class="mesa-sr-only" for="mesa-texto">Alertas en formato JSON o JSONL</label>
        <textarea id="mesa-texto" name="texto" rows="3" placeholder="Pega aquí las alertas o sus identificadores" spellcheck="false" aria-describedby="mesa-fuente"></textarea>
        <div class="mesa-attachment" data-attachment hidden>
          ${icon('M6 3h8l4 4v14H6zM14 3v5h4M9 13h6m-6 4h6')}
          <div><p data-filename></p><span>Archivo listo para analizar</span></div>
          <button type="button" class="mesa-button mesa-subtle" data-edit-input>Editar entrada</button>
        </div>
        <div class="mesa-source-row">
          <div class="mesa-toolbar">
            <label for="mesa-archivo" class="mesa-button mesa-secondary">${upload} Cargar archivo</label>
            <input type="file" id="mesa-archivo" accept=".json,.jsonl,.txt" class="mesa-file-input">
            <button type="button" class="mesa-button mesa-subtle" data-sample>Lote de ensayo</button>
            <button type="button" class="mesa-button mesa-subtle" data-sample-one>Alerta nueva de ensayo</button>
          </div>
          <p id="mesa-fuente" class="mesa-source">Hasta 150 alertas · 1 MB</p>
          <span class="mesa-sr-only" data-source role="status"></span>
        </div>
        <p class="mesa-error" data-intake-error role="alert"></p>
        <div class="mesa-submit-row">
          <div class="mesa-toolbar">
            <span class="mesa-control">
              <label class="mesa-control">Turno <select name="modo"><option value="guardia">Guardia</option><option value="diurno">Horario atendido</option></select></label>
              ${ayudaHTML('el turno', 'El turno indica si el equipo está atendiendo el SOC. Las alertas críticas se escalan en ambos modos.')}
            </span>
            <span class="mesa-control">
              <label class="mesa-control"><input type="checkbox" name="remoto" ${settings.openai_disponible ? '' : 'disabled'}> Contraste de Vigía</label>
              ${ayudaHTML('el contraste de Vigía', settings.openai_disponible
                ? 'Añade una propuesta y una segunda revisión que busca contradicciones. Las citas del índice respaldan la decisión.'
                : 'El contraste remoto no está disponible. Puedes analizar el lote con el motor local.')}
            </span>
          </div>
          <button class="mesa-button mesa-primary" type="submit">Analizar lote ${arrow}</button>
        </div>
      </form>
      <section class="mesa-progress" aria-labelledby="mesa-progreso" data-phase="idle">
        <div class="mesa-panel-heading">
          <h3>${activity} <span id="mesa-progreso">Progreso del lote</span> ${ayudaHTML('el progreso', 'Muestra cuántas alertas se han investigado. Abre «Ver actividad» para seguir las consultas y el guardado de informes.')}</h3>
          <span class="mesa-phase" data-phase-label role="status">En espera</span>
        </div>
        <p class="mesa-tally" data-tally hidden><strong data-completed>0</strong><span data-total></span></p>
        <p class="mesa-progress-copy" data-progress>Al iniciar un lote verás aquí la actividad de Vigía.</p>
        <div class="mesa-track" aria-hidden="true"><span data-progress-bar></span></div>
        <p class="mesa-latest" data-latest hidden></p>
        <details data-progress-details hidden><summary>Ver actividad ${chevron}</summary>
          <ol class="mesa-steps" aria-label="Actividad del análisis"></ol>
        </details>
      </section>
    </div>
    <section class="mesa-queue" aria-labelledby="mesa-cola">
      <div class="mesa-queue-heading">
        <div><h3><span id="mesa-cola">Cola de alertas</span> ${ayudaHTML('los filtros de la cola', 'Escaladas muestra los casos que requieren revisión. Cerradas por Vigía muestra los autocierres, con el informe disponible para consulta.')}</h3><p data-count class="mesa-count"></p></div>
        <div class="mesa-filter">
          <div class="mesa-filters" role="group" aria-label="Filtrar por resolución">
            <button type="button" data-filter="all" aria-pressed="true">Todas</button>
            <button type="button" data-filter="escalated" aria-pressed="false">Escaladas</button>
            <button type="button" data-filter="automatic" aria-pressed="false">Cerradas por Vigía</button>
          </div>
          <label for="mesa-buscar" class="mesa-search">${icon('m21 21-4.35-4.35M19 11a8 8 0 1 1-16 0 8 8 0 0 1 16 0Z')}
            <span class="mesa-sr-only">Buscar una alerta</span>
            <input type="search" id="mesa-buscar" placeholder="Buscar una alerta">
          </label>
        </div>
      </div>
      <section class="mesa-assigned" aria-labelledby="mesa-asignadas" hidden>
        <h4 id="mesa-asignadas">Mis alertas</h4><div data-assigned></div>
      </section>
      <div class="mesa-mobile-sort">
        <label>Ordenar por <select data-sort-field>
          <option value="primera">Hora</option><option value="title">Nombre</option>
          <option value="severity">Severidad</option><option value="estado">Estado</option>
          <option value="verdict">Veredicto</option><option value="asignado">Asignado</option>
        </select></label>
        <select data-sort-direction aria-label="Dirección del orden">
          <option value="-1">Descendente</option><option value="1">Ascendente</option>
        </select>
      </div>
      <p data-error class="mesa-error" role="status"></p>
    <div class="mesa-scroll" tabindex="0" aria-label="Cola de alertas del triaje">
      <table class="mesa-table"><caption class="mesa-sr-only">Alertas del triaje</caption>
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
    </section>
  </section>`;

  const root = view.querySelector('.mesa');
  const find = selector => root.querySelector(selector);
  const form = find('.mesa-import');
  const input = form.elements.texto;
  const attachment = find('[data-attachment]');
  const attachmentName = find('[data-filename]');
  const submit = form.querySelector('[type="submit"]');
  const progressPanel = find('.mesa-progress');
  const progress = find('[data-progress]');
  const phaseLabel = find('[data-phase-label]');
  const tally = find('[data-tally]');
  const completed = find('[data-completed]');
  const totalLabel = find('[data-total]');
  const progressBar = find('[data-progress-bar]');
  const latest = find('[data-latest]');
  const progressDetails = find('[data-progress-details]');
  const steps = find('.mesa-steps');
  const rows = find('tbody');
  const search = find('#mesa-buscar');
  const sortField = find('[data-sort-field]');
  const sortDirection = find('[data-sort-direction]');
  const errorBox = find('[data-error]');
  const intakeError = find('[data-intake-error]');
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
  let filter = 'all';
  let expanded = null;
  let reportRequest = 0;
  let jobId = jid || null;
  let cursor = 0;
  let busy = false;
  let polling = false;
  let timer;
  input.value = prellenar;

  const automatic = row => row.estado === 'cerrada' && row.decision === 'automatic';
  const label = row => automatic(row) ? 'Cerrada por Vigía' : states[row.estado] || row.estado || 'Pendiente';
  const assignee = row => automatic(row) ? 'Vigía' : row.rol || row.asignado || '';
  const myAssignee = () => 'analista.' + rol().toLowerCase();
  const sameRole = row => !automatic(row) && (row.rol === rol() || row.asignado === myAssignee());
  const err = message => { errorBox.textContent = message; };
  const formError = message => { intakeError.textContent = message; };
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
    const visible = alerts.filter(row => (filter === 'all' || (filter === 'escalated' && row.estado === 'escalada') ||
      (filter === 'automatic' && automatic(row))) && [row.alert_id, row.title, severidades[row.severity],
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
    const focusedReport = details.contains(focus);
    const assignedId = focus?.dataset?.assignedAlert;
    details.remove();
    rows.innerHTML = visible.map(row => {
      const opened = expanded === row.alert_id;
      const when = Date.parse(row.primera);
      const verdict = row.verdict ? veredicto(row.verdict) : '—';
      const assigneeLabel = assignee(row) || '—';
      const canAssign = row.estado !== 'cerrada' && (!row.asignado || sameRole(row));
      const severity = `<span class="mesa-severity" data-level="${esc(row.severity)}">${esc(severidades[row.severity] || 'Sin evaluar')}</span>`;
      const status = `<span class="mesa-pill" data-state="${esc(row.estado)}">${esc(label(row))}</span>`;
      const compactDetails = [Number.isFinite(when) ? date.format(when) : '', row.verdict ? verdict : '',
        row.provisional ? 'Sin corroborar' : '', row.fuera_de_horario ? 'Fuera de horario' : '',
        row.asignado ? assigneeLabel : '', row.fiscal ? 'Fiscal: ' + row.fiscal : ''].filter(Boolean).join(' · ');
      return `<tr data-alert="${esc(row.alert_id)}" class="mesa-alert-row${opened ? ' mesa-open' : ''}">
        <td><time datetime="${esc(row.primera)}">${Number.isFinite(when) ? esc(date.format(when)) : '—'}</time>
          ${row.fuera_de_horario ? '<small>Fuera de horario</small>' : ''}</td>
        <td><button type="button" class="mesa-name" data-mesa-action="detail" aria-expanded="${opened}"${opened ? ' aria-controls="mesa-expediente"' : ''}>${esc(row.title)}</button>
          <small class="mono">${esc(row.alert_id)}</small>
          <div class="mesa-mobile-meta">${severity} ${status}
            <small>${esc(compactDetails)}</small>
          </div></td>
        <td>${severity}</td>
        <td>${status}</td>
        <td><span class="mesa-verdict" data-verdict="${esc(row.verdict || '')}">${esc(verdict)}</span>
          ${row.provisional ? '<small>Sin corroborar</small>' : ''}
          ${row.fiscal ? `<small>Fiscal: ${esc(row.fiscal)}</small>` : ''}</td>
        <td>${esc(assigneeLabel)}</td>
        <td><div class="mesa-actions">
          ${canAssign ? `<button type="button" class="mesa-action" data-mesa-action="assign">${sameRole(row) ? 'Liberar' : 'Asignarme'}</button>` : ''}
          <button type="button" class="mesa-action mesa-report-toggle" data-mesa-action="toggle" aria-expanded="${opened}"${opened ? ' aria-controls="mesa-expediente"' : ''}>${opened ? 'Ocultar informe' : 'Ver informe'} ${chevron}</button>
        </div></td></tr>`;
    }).join('') || `<tr class="mesa-empty"><td colspan="7"><strong>${alerts.length ? 'No hay alertas en esta vista' : 'Todavía no hay alertas'}</strong>
      <span>${term || filter !== 'all' ? 'Prueba con otro filtro o búsqueda.' : 'Carga un archivo o usa un lote de ensayo para empezar.'}</span></td></tr>`;
    const selected = Array.from(rows.querySelectorAll('[data-alert]')).find(row => row.dataset.alert === expanded);
    if (selected) selected.after(details);
    if (focusedAction && focusedId) {
      const row = Array.from(rows.querySelectorAll('[data-alert]')).find(item => item.dataset.alert === focusedId);
      const control = Array.from(row?.querySelectorAll('[data-mesa-action]') || []).find(button => button.dataset.mesaAction === focusedAction);
      (control || row?.querySelector('[data-mesa-action="toggle"]') || search).focus({preventScroll: true});
    } else if (focusedReport) {
      (selected ? focus : search).focus({preventScroll: true});
    }
    find('[data-count]').textContent = `${visible.length} de ${alerts.length} alertas`;
    root.querySelectorAll('[data-column]').forEach(th => {
      const active = th.dataset.column === sort.field;
      th.setAttribute('aria-sort', active ? (sort.direction === 1 ? 'ascending' : 'descending') : 'none');
    });
    const mine = alerts.filter(sameRole);
    assigned.parentElement.hidden = !mine.length;
    assigned.innerHTML = `<ul>${mine.map(row => `<li><button type="button" class="mesa-name" data-assigned-alert="${esc(row.alert_id)}">${esc(row.title)} <span>${esc(row.alert_id)}</span></button></li>`).join('')}</ul>`;
    if (assignedId) {
      const button = Array.from(assigned.querySelectorAll('button')).find(item => item.dataset.assignedAlert === assignedId);
      (button || search).focus({preventScroll: true});
    }
  }

  async function showReport(row) {
    const request = ++reportRequest;
    if (!row.ticket_id) {
      reportPanel.textContent = textoVigia(row.error) || (row.estado === 'pendiente'
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
      reportPanel.innerHTML = `<div class="mesa-report-content"><div class="mesa-report-heading">
        <div><span class="mesa-report-id mono">${esc(row.alert_id)}</span><h3>Expediente de investigación</h3></div>
        <div class="mesa-actions"><a class="mesa-action" href="${enlace('caso', row.ticket_id)}">Abrir expediente ${arrow}</a>
        <a class="mesa-action mesa-subtle" href="/api/expediente/${encodeURIComponent(row.alert_id)}" download>Exportar JSON</a></div>
      </div>
      ${row.error ? `<p class="mesa-error">${esc(textoVigia(row.error))} Se muestra el último informe guardado.</p>` : ''}
      ${!ticket.expediente ? `<p>${esc(ticket.summary || row.summary)}</p>` : ''}
      ${expedienteHTML(ticket)}
      <div class="mesa-report-grid">
        <section class="mesa-evidence"><h4>Evidencia recuperada <span class="mesa-evidence-count">${events.length}</span> ${ayudaHTML('la evidencia recuperada', 'Son registros encontrados en el índice. Pulsa el identificador de un evento para consultar el registro original.')}</h4>
          ${events.length ? `<ul>${events.map(event => `<li><button type="button" class="mesa-name prueba" data-event="${esc(event.event_id)}">${esc(event.event_id)}</button> · ${esc(origenEvidencia(event, report))}<br><small>${esc(event.finding || event.source)}</small></li>`).join('')}</ul>` : '<p>El índice no devolvió registros para verificar esta alerta.</p>'}
          <div data-event-output role="status" hidden></div>
        </section>
        <section class="mesa-evidence"><h4>Declarada por el sensor ${ayudaHTML('la evidencia declarada', 'Son datos que venían en el archivo del SIEM. Las citas del expediente indican cuáles se pudieron comprobar.')}</h4>
          ${declared && typeof declared === 'object' && Object.keys(declared).length
            ? `<p>Campos aportados por el sensor. Las citas del informe indican qué se verificó.</p>${registroHTML(declared)}`
            : '<p>La alerta no aportó evidencia declarada adicional.</p>'}
        </section>
      </div></div>`;
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
    setFilter('all');
    open(row, false);
    rows.querySelector('.mesa-open [data-mesa-action="detail"]')?.focus({preventScroll: true});
    details.scrollIntoView({block: 'nearest'});
  });
  const filterButtons = root.querySelectorAll('[data-filter]');
  function setFilter(value) {
    filter = value;
    filterButtons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.filter === value)));
  }
  filterButtons.forEach(button => button.addEventListener('click', () => {
    setFilter(button.dataset.filter);
    renderRows();
  }));
  search.addEventListener('input', renderRows);
  for (const control of [sortField, sortDirection]) {
    control.addEventListener('change', () => {
      sort = {field: sortField.value, direction: Number(sortDirection.value)};
      renderRows();
    });
  }
  root.querySelectorAll('[data-column] button').forEach(button => {
    button.addEventListener('click', () => {
      const field = button.parentElement.dataset.column;
      sort = {field, direction: sort.field === field ? -sort.direction : 1};
      sortField.value = sort.field;
      sortDirection.value = sort.direction;
      renderRows();
    });
  });

  function setSource(name) {
    fileName = name;
    attachmentName.textContent = name;
    attachment.hidden = !name;
    input.hidden = Boolean(name);
    source.textContent = name ? `Archivo listo para analizar: ${name}` : '';
  }
  function editInput() {
    attachment.hidden = true;
    input.hidden = false;
    input.focus();
  }
  find('[data-edit-input]').addEventListener('click', editInput);

  find('#mesa-archivo').addEventListener('change', async event => {
    const control = event.target;
    const file = control.files[0];
    control.value = '';
    if (!file) return;
    if (file.size > 1000000) { formError('El archivo supera el límite de 1 MB.'); return; }
    try { input.value = await file.text(); setSource(file.name.slice(0, 160)); formError(''); }
    catch { formError('No se pudo leer el archivo.'); }
  });
  input.addEventListener('input', () => { setSource(''); formError(''); });
  async function loadSample(single) {
    try {
      input.value = (await api('lote_ensayo' + (single ? '?una=true' : ''))).texto;
      setSource(single ? 'alerta-de-ensayo.jsonl' : 'lote-de-ensayo.jsonl');
      formError('');
    } catch { formError('No se pudo cargar el ensayo.'); }
  }
  find('[data-sample]').addEventListener('click', () => loadSample(false));
  find('[data-sample-one]').addEventListener('click', () => loadSample(true));

  function setPhase(phase, label) {
    progressPanel.dataset.phase = phase;
    if (phaseLabel.textContent !== label) phaseLabel.textContent = label;
  }

  function follow(id) {
    jobId = id;
    cursor = 0;
    steps.replaceChildren();
    progressDetails.open = false;
    progressDetails.hidden = true;
    tally.hidden = true;
    latest.hidden = true;
    progressBar.style.setProperty('--mesa-completion', 0);
    progress.textContent = 'Recuperando las primeras pruebas.';
    setPhase('running', 'En curso');
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
    if (job.pasos?.length) {
      latest.textContent = pasoTxt(job.pasos.at(-1));
      latest.hidden = false;
      steps.scrollTop = steps.scrollHeight;
    }
    cursor = job.total_pasos;
    progressDetails.hidden = !steps.children.length;
    const done = job.tickets.length;
    tally.hidden = false;
    completed.textContent = done;
    totalLabel.textContent = `de ${job.alertas} investigadas`;
    progressBar.style.setProperty('--mesa-completion', job.alertas ? done / job.alertas : 0);
    progress.textContent = job.fin == null ? `${job.segundos} s en curso` : `Tiempo total · ${job.segundos} s`;
    if (job.fin != null) {
      jobId = null;
      if (job.error) {
        setPhase('error', job.estado === 'error' ? 'Con errores' : 'Terminado con incidencias');
        formError(textoVigia(job.error));
      } else {
        setPhase('done', 'Terminado');
      }
    } else {
      setPhase('running', 'En curso');
    }
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
        setPhase('idle', 'No disponible');
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
    if (!texto) { formError('Selecciona un archivo o pega al menos una alerta.'); editInput(); return; }
    if (new TextEncoder().encode(texto).length > 1000000) { formError('El lote supera el límite de 1 MB.'); return; }
    busy = true;
    submit.disabled = true;
    formError('');
    try {
      const response = await post('analizar', {
        texto, modo: form.elements.modo.value, remoto: form.elements.remoto.checked, archivo: fileName,
      });
      const body = await response.json();
      if (!response.ok || !body.trabajo) throw new Error(mensajeError(body));
      if (!root.isConnected) return;
      follow(body.trabajo);
      clearTimeout(timer);
      await poll();
    } catch (failure) { formError(failure.message); }
    finally { busy = false; submit.disabled = Boolean(jobId); }
  });
  renderRows();
  await poll();
}
