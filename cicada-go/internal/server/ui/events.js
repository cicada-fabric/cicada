const EVENT_TYPES = [
  'GoalCreated', 'WorkerQueued', 'WorkerStarted', 'WorkerCompleted', 'WorkerFailed',
  'WorkerRecovered', 'WorkerCancelled', 'GoalCompleted', 'GoalBlocked', 'GoalCancelled',
  'MonitorEvaluated', 'MonitorCorrectionQueued', 'MonitorCommandQueued', 'MonitorCommandSent',
  'CodexEvent', 'ArtifactProduced', 'PeerMessageSent', 'PeerMessageReceived',
  'PeerMessageQueued', 'PeerMessageDispatched', 'ExternalEventReceived',
  'ExternalActionRequested', 'ExternalActionClaimed', 'ExternalActionCompleted',
];

const streams = new Map();
let currentGoals = [];
let currentToken = '';
let currentRefresh = () => {};

function closeStream(id) {
  const state = streams.get(id);
  if (!state) return;
  state.source.close();
  streams.delete(id);
}

function openStream(goal, after = 0) {
  if (streams.has(goal.id)) return;
  const state = {lastId: after, source: null};
  const source = new EventSource(`/v1/goals/${encodeURIComponent(goal.id)}/events/stream?after=${after}`);
  state.source = source;
  const onEvent = event => {
    const id = Number(event.lastEventId);
    if (Number.isSafeInteger(id) && id > state.lastId) state.lastId = id;
    currentRefresh();
  };
  EVENT_TYPES.forEach(type => source.addEventListener(type, onEvent));
  source.onerror = () => {
    const lastId = state.lastId;
    closeStream(goal.id);
    setTimeout(() => {
      const stillRunning = currentGoals.some(item => item.id === goal.id && ['queued', 'running', 'recovering'].includes(item.status));
      if (!currentToken && stillRunning) openStream(goal, lastId);
    }, 5000);
  };
  streams.set(goal.id, state);
}

function sync(goals, token, refresh) {
  currentGoals = goals;
  currentToken = token || '';
  currentRefresh = refresh;
  const active = new Set(goals.filter(goal => ['queued', 'running', 'recovering'].includes(goal.status)).map(goal => goal.id));
  [...streams.keys()].forEach(id => {
    if (currentToken || !active.has(id)) closeStream(id);
  });
  if (currentToken) return;
  goals.filter(goal => active.has(goal.id)).forEach(openStream);
}

window.CicadaEvents = {sync};
