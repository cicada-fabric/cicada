const detailEscape = value => String(value ?? '').replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[character]));
const detailJSON = value => detailEscape(typeof value === 'string' ? value : JSON.stringify(value, null, 2));

function detailList(items, render, empty = 'None recorded.') {
  return items.length ? `<ul>${items.map(render).join('')}</ul>` : `<p class="muted">${empty}</p>`;
}

function renderGoalDetail(panel, data) {
  const {goal, events, workers, artifacts, workspaces, actions} = data;
  const eventItems = detailList(events, event => `<li><strong>${detailEscape(event.type)}</strong><span>${detailEscape(event.created_at)}</span><pre>${detailJSON(event.payload)}</pre></li>`);
  const workerItems = detailList(workers, worker => `<li><strong>${detailEscape(worker.harness)}</strong><span>${detailEscape(worker.status)}</span><small>${detailEscape(worker.id)}${worker.thread_id ? ` · thread ${detailEscape(worker.thread_id)}` : ''}</small><button class="secondary worker-log-button" data-worker-log="${detailEscape(worker.id)}" type="button">View raw output</button><pre data-worker-log-output="${detailEscape(worker.id)}" hidden></pre></li>`);
  const monitor = goal.monitor ? `<p><strong>Monitor</strong><span>${detailEscape(goal.monitor.status)}</span><small>${detailEscape(goal.monitor.id)}</small></p>` : '<p class="muted">No monitor assigned.</p>';
  const artifactItems = detailList(artifacts, artifact => `<li><strong>${detailEscape(artifact.name)}</strong><span>${detailEscape(artifact.kind)}</span><small>${detailEscape(artifact.path)}</small></li>`);
  const workspaceItems = detailList(workspaces, workspace => `<li><strong>${detailEscape(workspace.status)}</strong><small>${detailEscape(workspace.path)}</small></li>`);
  const actionItems = detailList(actions, action => `<li><strong>${detailEscape(action.kind)}</strong><span>${detailEscape(action.status)}</span><small>${detailEscape(action.url)}</small></li>`);
  panel.innerHTML = `<div class="detail-grid">
    <div><h3>Conclusion</h3><p class="summary">${detailEscape(goal.outcome || goal.summary || goal.current_state || 'No conclusion yet.')}</p><p class="meta">${detailEscape(goal.success_criteria || 'No success criteria recorded.')}</p></div>
    <div><h3>Execution graph</h3>${monitor}${workerItems}</div>
    <div><h3>Artifacts</h3>${artifactItems}</div>
    <div><h3>Workspaces</h3>${workspaceItems}</div>
    <div><h3>External actions</h3>${actionItems}</div>
    <div><h3>Key events</h3>${eventItems}</div>
  </div>`;
  panel.querySelectorAll('[data-worker-log]').forEach(button => {
    button.addEventListener('click', async () => {
      const workerID = button.dataset.workerLog;
      const output = [...panel.querySelectorAll('[data-worker-log-output]')].find(item => item.dataset.workerLogOutput === workerID);
      if (!output) return;
      button.disabled = true;
      try {
        const log = await window.CicadaClient.api(`/v1/workers/${encodeURIComponent(workerID)}/log`);
        output.textContent = `${log.content || ''}${log.truncated ? '\n… output truncated …' : ''}`;
        output.hidden = false;
        button.textContent = 'Refresh raw output';
      } catch (error) {
        window.CicadaClient.showMessage(error.message, true);
      } finally {
        button.disabled = false;
      }
    });
  });
}

async function loadGoalDetail(id, panel) {
  panel.hidden = false;
  panel.innerHTML = '<p class="muted">Loading detail…</p>';
  try {
    const api = window.CicadaClient.api;
    const encoded = encodeURIComponent(id);
    const [goal, eventsData, workersData, artifactsData, workspacesData, actionsData] = await Promise.all([
      api(`/v1/goals/${encoded}`), api(`/v1/goals/${encoded}/events`), api(`/v1/goals/${encoded}/workers`),
      api(`/v1/artifacts?goal_id=${encoded}`), api(`/v1/workspaces?goal_id=${encoded}`), api(`/v1/actions?goal_id=${encoded}`),
    ]);
    renderGoalDetail(panel, {
      goal, events: eventsData.events || [], workers: workersData.workers || [],
      artifacts: artifactsData.artifacts || [], workspaces: workspacesData.workspaces || [],
      actions: actionsData.actions || [],
    });
  } catch (error) {
    panel.innerHTML = `<p class="muted">${detailEscape(error.message)}</p>`;
    window.CicadaClient.showMessage(error.message, true);
  }
}

window.CicadaGoalDetail = {
  attach(root) {
    root.querySelectorAll('[data-goal-detail]').forEach(button => {
      button.addEventListener('click', () => {
        const panel = [...root.querySelectorAll('[data-goal-detail-panel]')].find(item => item.dataset.goalDetailPanel === button.dataset.goalDetail);
        if (!panel) return;
        if (!panel.hidden) {
          panel.hidden = true;
          return;
        }
        loadGoalDetail(button.dataset.goalDetail, panel);
      });
    });
  },
};
