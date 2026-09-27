const managementEscape = value => String(value ?? '').replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[character]));

let managementRefreshVersion = 0;
let managementRefreshPending = false;

function managementRefs(label, refs) {
  if (!refs?.length) return '';
  return `<p class="meta">${managementEscape(label)}: ${refs.map(ref =>
    `<code class="evidence-reference">${managementEscape(ref)}</code>`
  ).join(' ')}</p>`;
}

function renderSharedTask(task, results, evidenceUnavailable) {
  const linked = results.filter(result => result.task_id === task.task_id);
  const resultViews = evidenceUnavailable
    ? '<p class="muted">Result evidence unavailable.</p>'
    : linked.length ? linked.map(result => `
    <div class="management-result">
      <p class="summary">${managementEscape(result.summary || 'Result submitted without a summary.')}</p>
      <p class="meta">Result ${managementEscape(result.result_id)} · authority ${managementEscape(result.authority || 'UNKNOWN')} · owner epoch ${managementEscape(result.owner_epoch)}</p>
      ${managementRefs('Evidence', result.evidence)}
    </div>`).join('') : '<p class="meta">No result evidence submitted.</p>';
  const accepted = task.accepted_result_id
    ? `<p class="meta">Accepted result: ${managementEscape(task.accepted_result_id)}</p>`
    : '';
  return `<article class="management-item">
    <header><strong>${managementEscape(task.objective)}</strong><span class="badge">${managementEscape(task.status || 'UNKNOWN')}</span></header>
    <p class="meta">Task ${managementEscape(task.task_id)} · revision ${managementEscape(task.revision)}</p>
    <p class="summary">${managementEscape(task.acceptance_criteria || 'No acceptance criteria recorded.')}</p>
    ${accepted}${resultViews}
  </article>`;
}

function renderRepresentativeRequest(request) {
  return `<article class="management-item">
    <header><strong>${managementEscape(request.capability || 'Representative request')}</strong><span class="badge">${managementEscape(request.state || 'UNKNOWN')}</span></header>
    <p class="meta">Request ${managementEscape(request.federation_request_id || request.request_id)} · ${managementEscape(request.source_group_id)} → ${managementEscape(request.target_group_id)}</p>
    <p class="meta">Source ${managementEscape(request.source_state || 'UNKNOWN')} · target ${managementEscape(request.target_state || 'UNKNOWN')}</p>
    <p class="meta">Representatives ${managementEscape(request.source_representative_endpoint_id || 'unknown')} → ${managementEscape(request.target_representative_endpoint_id || 'unknown')}</p>
    ${managementRefs('Evidence', request.evidence_refs)}
    ${managementRefs('Provenance', request.provenance_refs)}
    ${managementRefs('Artifacts', request.artifact_refs)}
    <p class="meta receipt-state">Receipt ${managementEscape(request.receipt_state || 'UNKNOWN')} · no linked transport receipt</p>
  </article>`;
}

function renderGroupView(view) {
  const {group, tasks, results, requests, errors} = view;
  const taskContent = errors.tasks
    ? `<p class="muted">Task view unavailable: ${managementEscape(errors.tasks)}</p>`
    : tasks.length ? tasks.map(task => renderSharedTask(task, results, Boolean(errors.results))).join('')
      : '<p class="muted">No shared tasks recorded.</p>';
  const requestContent = errors.requests
    ? `<p class="muted">Representative request view unavailable: ${managementEscape(errors.requests)}</p>`
    : requests.length ? requests.map(renderRepresentativeRequest).join('')
      : '<p class="muted">No representative requests recorded.</p>';
  const evidenceError = errors.results
    ? `<p class="muted">Task evidence unavailable: ${managementEscape(errors.results)}</p>` : '';
  return `<article class="management-card">
    <header><div><strong>${managementEscape(group.name)}</strong><p class="meta">${managementEscape(group.group_id)} · revision ${managementEscape(group.revision)}</p></div><span class="badge">${managementEscape(group.state || 'UNKNOWN')}</span></header>
    <p class="summary">${managementEscape(group.purpose || 'No Group purpose recorded.')}</p>
    <p class="meta">Isolation profile ${managementEscape(group.isolation_profile || 'unknown')} · context policy ${managementEscape(group.context_policy || 'unknown')}</p>
    <div class="management-columns">
      <section class="management-panel"><h3>Shared tasks</h3>${taskContent}${evidenceError}</section>
      <section class="management-panel"><h3>Representative requests</h3>${requestContent}</section>
    </div>
  </article>`;
}

async function loadGroupManagement(group, api) {
  const id = encodeURIComponent(group.group_id);
  const read = async path => {
    try { return await api(path); }
    catch (error) { return {error: error.message}; }
  };
  const [taskData, resultData, requestData] = await Promise.all([
    read('/v1/groups/' + id + '/tasks'),
    read('/v1/groups/' + id + '/tasks/results'),
    read('/v1/groups/' + id + '/representative-requests'),
  ]);
  return {
    group, tasks: taskData.tasks || [], results: resultData.results || [], requests: requestData.requests || [],
    errors: {tasks: taskData.error || '', results: resultData.error || '', requests: requestData.error || ''},
  };
}

window.CicadaManagement = {
  async refresh(groups, api) {
    if (managementRefreshPending) return;
    managementRefreshPending = true;
    const version = ++managementRefreshVersion;
    const target = document.getElementById('management-groups');
    const summary = document.getElementById('group-summary');
    try {
      if (!groups.length) {
        target.className = 'management-list empty';
        target.textContent = 'No Groups have been created.';
        summary.textContent = '0 groups';
        return;
      }
      const views = await Promise.all(groups.slice(0, 100).map(group => loadGroupManagement(group, api)));
      if (version !== managementRefreshVersion) return;
      target.className = 'management-list';
      target.innerHTML = views.map(renderGroupView).join('');
      const taskCount = views.reduce((count, view) => count + view.tasks.length, 0);
      const requestCount = views.reduce((count, view) => count + view.requests.length, 0);
      summary.textContent = views.length + ' groups · ' + taskCount + ' tasks · ' + requestCount + ' representative requests';
    } finally {
      managementRefreshPending = false;
    }
  },
};
