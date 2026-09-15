const state = {
  token: sessionStorage.getItem('cicada_api_token') || '',
  refreshing: false,
};

const byId = id => document.getElementById(id);
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[character]));
const statusClass = status => ['running', 'queued', 'recovering', 'failed', 'blocked', 'completed'].includes(status) ? status : '';
const readableTime = value => value ? new Date(value).toLocaleString() : '';

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set('Authorization', `Bearer ${state.token}`);
  const response = await fetch(path, {...options, headers, credentials: 'same-origin'});
  const text = await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = {error: text}; }
  }
  if (!response.ok) {
    if (response.status === 401) byId('access-panel').open = true;
    throw new Error(data.error || response.statusText);
  }
  return data;
}

let messageTimer;
function showMessage(message, error = false) {
  const target = byId('message');
  target.textContent = message;
  target.className = `show${error ? ' error' : ''}`;
  clearTimeout(messageTimer);
  messageTimer = setTimeout(() => { target.className = ''; }, 3600);
}

window.CicadaClient = {api, showMessage, escapeHTML};

function renderApprovals(approvals) {
  const target = byId('approvals');
  if (!approvals.length) {
    target.className = 'empty';
    target.innerHTML = 'Nothing needs your decision.';
    return;
  }
  target.className = '';
  target.innerHTML = approvals.map(item => `
    <article class="approval">
      <header><div><strong>${escapeHTML(item.method)}</strong><p class="meta">${escapeHTML(item.goal_id)} · ${escapeHTML(item.worker_id)}</p></div><span class="badge">P1</span></header>
      <pre>${escapeHTML(JSON.stringify(item.request, null, 2))}</pre>
      <div class="button-row">
        <button data-approval="${escapeHTML(item.id)}" data-decision="approve">Approve</button>
        <button class="danger" data-approval="${escapeHTML(item.id)}" data-decision="deny">Deny</button>
      </div>
    </article>`).join('');
  target.querySelectorAll('[data-approval]').forEach(button => {
    button.addEventListener('click', () => resolveApproval(button.dataset.approval, button.dataset.decision));
  });
}

function renderNotifications(notifications) {
  const target = byId('notifications');
  if (!notifications.length) {
    target.className = 'empty';
    target.innerHTML = 'No unread notifications.';
    return;
  }
  target.className = '';
  target.innerHTML = notifications.map(item => `
    <article class="notice ${escapeHTML(item.priority)}">
      <header><div><strong>${escapeHTML(item.title)}</strong><p class="meta">${escapeHTML(readableTime(item.created_at))}</p></div><span class="badge">${escapeHTML(item.priority)}</span></header>
      <p class="summary">${escapeHTML(item.body)}</p>
      <button class="secondary" data-read="${escapeHTML(item.id)}">Acknowledge</button>
    </article>`).join('');
  target.querySelectorAll('[data-read]').forEach(button => {
    button.addEventListener('click', async () => {
      try { await api(`/v1/notifications/${button.dataset.read}/read`, {method: 'POST'}); await refresh(); }
      catch (error) { showMessage(error.message, true); }
    });
  });
}

function renderGoals(goals) {
  const target = byId('goals');
  if (!goals.length) {
    target.className = 'goal-list empty';
    target.innerHTML = 'No goals yet.';
    return;
  }
  target.className = 'goal-list';
  target.innerHTML = goals.map(goal => {
    const workers = goal.workers || [];
    const workerList = workers.length ? `<div class="worker-list">${workers.map(worker =>
      `<span class="worker">${escapeHTML(worker.harness)} · ${escapeHTML(worker.status)} · ${escapeHTML(worker.machine_id)}</span>`
    ).join('')}</div>` : '';
    const children = (goal.children || []).length;
    const metadata = [goal.id, `${workers.length} worker${workers.length === 1 ? '' : 's'}`, children ? `${children} child goals` : '', goal.deadline ? `due ${readableTime(goal.deadline)}` : ''].filter(Boolean).join(' · ');
    return `<article class="goal">
      <header><strong>${escapeHTML(goal.objective)}</strong><span class="badge ${statusClass(goal.status)}">${escapeHTML(goal.status)}</span></header>
      <p class="meta">${escapeHTML(metadata)}</p>
      <p class="summary">${escapeHTML(goal.summary || goal.current_state || 'Working autonomously…')}</p>
      ${workerList}
      <button class="secondary detail-toggle" data-goal-detail="${escapeHTML(goal.id)}" type="button">View detail</button>
      <div class="goal-detail" data-goal-detail-panel="${escapeHTML(goal.id)}" hidden></div>
    </article>`;
  }).join('');
  window.CicadaGoalDetail?.attach(target);
}

async function refresh() {
  if (state.refreshing || document.hidden) return;
  state.refreshing = true;
  try {
    const [identity, goalsData, notificationsData, approvalsData] = await Promise.all([
      api('/v1/identity'), api('/v1/goals'), api('/v1/notifications'), api('/v1/approvals?pending=true'),
    ]);
    const goals = goalsData.goals || [];
    const approvals = approvalsData.approvals || [];
    byId('identity').textContent = identity.id || 'identity unavailable';
    byId('running-count').textContent = goals.filter(goal => ['queued', 'running', 'recovering'].includes(goal.status)).length;
    byId('approval-count').textContent = approvals.length;
    byId('completed-count').textContent = goals.filter(goal => goal.status === 'completed').length;
    byId('updated-at').textContent = `updated ${new Date().toLocaleTimeString()}`;
    renderApprovals(approvals);
    renderGoals(goals);
    renderNotifications(notificationsData.notifications || []);
  } catch (error) {
    showMessage(error.message, true);
  } finally {
    state.refreshing = false;
  }
}

async function resolveApproval(id, decision) {
  try {
    await api(`/v1/approvals/${encodeURIComponent(id)}`, {
      method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({decision}),
    });
    showMessage(`Decision recorded: ${decision}`);
    await refresh();
  } catch (error) { showMessage(error.message, true); }
}

byId('goal-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.submitter || event.target.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const intent = await api('/v1/intents', {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({
        text: byId('objective').value,
        kind: byId('intent-kind').value,
        goal: {success_criteria: byId('criteria').value},
      }),
    });
    if (intent.status === 'needs_input') {
      showMessage(intent.question || 'Cicada needs more information.', true);
    } else {
      event.target.reset();
      showMessage(`${intent.resolved_kind} accepted. Cicada will report meaningful changes.`);
    }
    await refresh();
  } catch (error) { showMessage(error.message, true); }
  finally { button.disabled = false; }
});

byId('token-form').addEventListener('submit', event => {
  event.preventDefault();
  state.token = byId('api-token').value.trim();
  sessionStorage.setItem('cicada_api_token', state.token);
  showMessage('API token is active for this tab.');
  refresh();
});
byId('clear-token').addEventListener('click', () => {
  state.token = '';
  byId('api-token').value = '';
  sessionStorage.removeItem('cicada_api_token');
  showMessage('API token cleared.');
  refresh();
});
byId('api-token').value = state.token;
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
refresh();
setInterval(refresh, 5000);
