import { boxContains, endpointAdmissionGesture, endpointJoinGesture, groupHasMember, layoutTopology, normalizeBox, screenPointToWorld } from './panel-model.js';
import { installCanvasControls } from './panel-canvas-controls.js';
import { button, html, svg } from './panel-dom.js';

export class CanvasPanel {
  constructor(root, options) {
    this.root = root;
    this.db = options.db;
    this.cryptoApi = options.cryptoApi;
    this.identity = options.identity;
    this.topology = options.initialSnapshots.topology;
    this.status = options.initialSnapshots.status;
    this.writeFence = options.initialSnapshots.writeFence || null;
    this.reviewedWriteFenceID = '';
    this.rpc = options.rpc;
    this.refresh = options.refresh;
    this.clearWriteFence = options.clearWriteFence;
    this.recover = options.recover;
    this.lock = options.lock;
    this.pending = options.pending;
    this.networkId = this.topology.networks?.[0]?.network_id || '';
    this.networkDirectory = { networkId: '', endpoints: [], nextCursor: '', loading: false, error: '' };
    this.selection = new Set();
    this.plan = [];
    this.planReview = '';
    this.pendingLinkGesture = null;
    this.view = { x: 90, y: 25, scale: 0.82 };
    this.mode = 'select';
    this.drag = null;
    this.message = '';
  }

  mount() {
    this.root.replaceChildren();
    const workspace = html('section', 'workspace');
    this.stage = html('div', 'stage');
    const title = html('div', 'stage-head');
    title.append(html('span', 'chip good', `Network · ${this.networkName()}`));
    title.append(button('Refresh snapshots', () => this.reload(), 'btn quiet'));
    const tools = html('div', 'stage-tools');
    this.modeButtons = new Map();
    for (const [mode, label] of [['select', 'Select'], ['pan', 'Pan'], ['join', 'Drag to Group'], ['link', 'Draw Link']]) {
      const modeButton = button(label, () => this.setMode(mode), 'btn canvas-mode');
      modeButton.setAttribute('aria-pressed', mode === this.mode ? 'true' : 'false');
      modeButton.classList.toggle('active-tool', mode === this.mode);
      this.modeButtons.set(mode, modeButton);
      tools.append(modeButton);
    }
    tools.append(button('−', () => this.zoomAt(.82), 'btn'), button('+', () => this.zoomAt(1.22), 'btn'));
    this.svgRoot = svg('svg', { role: 'img', 'aria-label': 'Hub topology canvas', tabindex: '0' });
    this.world = svg('g', { class: 'world' });
    this.selectionRect = svg('rect', { class: 'selection-box', visibility: 'hidden' });
    this.svgRoot.append(this.world, this.selectionRect);
    this.banner = html('div', 'status-banner', 'Layout is local to this browser. It does not change ownership, ACLs, or Network policy.');
    this.stage.append(title, tools, this.svgRoot, this.banner);
    this.side = html('aside', 'side');
    workspace.append(this.stage, this.side);
    this.root.append(workspace);
    this.attachCanvasEvents();
    this.render();
    this.renderSide();
    this.resizeObserver = new ResizeObserver(() => this.render());
    this.resizeObserver.observe(this.stage);
  }

  networkName() {
    return this.topology.networks?.find(network => network.network_id === this.networkId)?.name || this.networkId || 'All networks';
  }

  async reload(forFenceReview = false) {
    try {
      const snapshots = await this.refresh();
      this.topology = snapshots.topology;
      this.status = snapshots.status;
      this.writeFence = snapshots.writeFence || null;
      this.reviewedWriteFenceID = '';
      let reviewRace = false;
      if (forFenceReview && this.writeFence) {
        const resolvedAt = Date.parse(this.writeFence.resolvedAt || '');
        if (Number.isFinite(resolvedAt) && resolvedAt < snapshots.snapshotStartedAt) {
          this.reviewedWriteFenceID = this.writeFence.operationID;
        } else {
          reviewRace = true;
        }
      }
      this.message = reviewRace ? 'This write became uncertain during the refresh. Refresh again after it resolves before reviewing state.' :
        'Authoritative topology and status snapshots refreshed.';
      this.render();
      this.renderSide();
    } catch (error) {
      this.message = error.message;
      this.banner.textContent = `Refresh stopped: ${error.message}`;
      if (error.message.includes('unresolved') || error.message.includes('sequence state')) this.pending?.(error.message);
      this.renderSide();
    }
  }

  attachCanvasEvents() {
    this.svgRoot.addEventListener('wheel', event => {
      event.preventDefault();
      const point = this.localPoint(event);
      const factor = event.deltaY < 0 ? 1.1 : 0.9;
      const before = screenPointToWorld(point, this.view);
      this.view.scale = Math.max(.25, Math.min(2.1, this.view.scale * factor));
      this.view.x = point.x - before.x * this.view.scale;
      this.view.y = point.y - before.y * this.view.scale;
      this.transformWorld();
    }, { passive: false });
    this.svgRoot.addEventListener('pointerdown', event => this.beginPointer(event));
    this.svgRoot.addEventListener('pointermove', event => this.movePointer(event));
    this.svgRoot.addEventListener('pointerup', event => this.endPointer(event));
    this.svgRoot.addEventListener('pointercancel', () => this.cancelPointer());
  }

  setMode(mode) {
    if (!['select', 'pan', 'join', 'link'].includes(mode)) return;
    this.cancelPointer();
    this.mode = mode;
    for (const [key, modeButton] of this.modeButtons || []) {
      modeButton.setAttribute('aria-pressed', key === mode ? 'true' : 'false');
      modeButton.classList.toggle('active-tool', key === mode);
    }
    const hint = { select: 'Select Endpoints or drag a box.', pan: 'Drag empty canvas space to pan.',
      join: 'Drag an Endpoint reference onto a Group to preview one join.',
      link: 'Drag from an Endpoint reference to another to prepare a Link proposal.' }[mode];
    this.setMessage(hint);
  }

  cancelPointer() {
    this.drag = null;
    this.selectionRect?.setAttribute('visibility', 'hidden');
    this.gesturePath?.remove();
    this.gesturePath = null;
  }

  localPoint(event) {
    const rect = this.svgRoot.getBoundingClientRect();
    return { x: event.clientX - rect.left, y: event.clientY - rect.top };
  }

  beginPointer(event) {
    if (event.button !== 0) return;
    const target = event.target.closest?.('[data-endpoint-id]');
    if (target && this.mode === 'select') {
      const id = target.getAttribute('data-endpoint-id');
      if (event.shiftKey || event.metaKey || event.ctrlKey) this.selection.has(id) ? this.selection.delete(id) : this.selection.add(id);
      else if (!this.selection.has(id)) { this.selection.clear(); this.selection.add(id); }
      this.render();
      this.renderSide();
      return;
    }
    if (target && (this.mode === 'join' || this.mode === 'link')) {
      const start = this.localPoint(event);
      const endpointId = target.getAttribute('data-endpoint-id');
      const groupId = target.getAttribute('data-group-ref') || '';
      const ref = this.scene?.endpointRefs.find(item => item.endpoint.endpoint_id === endpointId && item.groupId === groupId);
      if (!ref) return;
      this.svgRoot.setPointerCapture(event.pointerId);
      this.drag = { pointerId: event.pointerId, start, last: start, mode: this.mode,
        endpointId, groupId, worldStart: { x: ref.x + 73, y: ref.y + 25 } };
      this.gesturePath = svg('path', { class: 'gesture-line', d: `M ${this.drag.worldStart.x} ${this.drag.worldStart.y} L ${this.drag.worldStart.x} ${this.drag.worldStart.y}` });
      this.world.append(this.gesturePath);
      this.setMessage(this.mode === 'join' ? 'Drop over a Group to review an Endpoint join.' : 'Drop over another Endpoint reference to review a Link proposal.');
      return;
    }
    if (this.mode === 'join' || this.mode === 'link') return;
    this.svgRoot.setPointerCapture(event.pointerId);
    const start = this.localPoint(event);
    this.drag = { pointerId: event.pointerId, start, last: start, mode: this.mode,
      worldStart: screenPointToWorld(start, this.view) };
    if (this.mode === 'select') {
      this.selectionRect.setAttribute('visibility', 'visible');
      this.updateSelectionRect(this.drag.worldStart, this.drag.worldStart);
    }
  }

  movePointer(event) {
    if (!this.drag || this.drag.pointerId !== event.pointerId) return;
    const point = this.localPoint(event);
    if (this.drag.mode === 'join' || this.drag.mode === 'link') {
      const worldPoint = screenPointToWorld(point, this.view);
      this.gesturePath?.setAttribute('d', `M ${this.drag.worldStart.x} ${this.drag.worldStart.y} L ${worldPoint.x} ${worldPoint.y}`);
      return;
    }
    if (this.drag.mode === 'pan') {
      this.view.x += point.x - this.drag.last.x;
      this.view.y += point.y - this.drag.last.y;
      this.drag.last = point;
      this.transformWorld();
      return;
    }
    const worldEnd = screenPointToWorld(point, this.view);
    this.updateSelectionRect(this.drag.worldStart, worldEnd);
  }

  endPointer(event) {
    if (!this.drag || this.drag.pointerId !== event.pointerId) return;
    if (this.drag.mode === 'join' || this.drag.mode === 'link') {
      const gesture = this.drag;
      const hit = document.elementFromPoint?.(event.clientX, event.clientY) || event.target;
      if (gesture.mode === 'join') {
        const groupTarget = hit.closest?.('[data-group-drop-id]');
        if (groupTarget) this.previewEndpointJoin(gesture.endpointId, groupTarget.getAttribute('data-group-drop-id'));
        else this.setMessage('No Group was targeted. No topology action was prepared.');
      } else {
        const endpointTarget = hit.closest?.('[data-endpoint-id]');
        if (endpointTarget) this.prepareLinkGesture(gesture, {
          endpointId: endpointTarget.getAttribute('data-endpoint-id'),
          groupId: endpointTarget.getAttribute('data-group-ref') || ''
        });
        else this.setMessage('No target Endpoint was selected. No Link proposal was prepared.');
      }
      this.cancelPointer();
      this.render();
      this.renderSide();
      return;
    }
    if (this.drag.mode === 'select') {
      const worldEnd = screenPointToWorld(this.localPoint(event), this.view);
      const box = normalizeBox(this.drag.worldStart, worldEnd);
      if (box.width > 5 || box.height > 5) {
        const scene = layoutTopology(this.topology, this.networkId, this.status);
        for (const ref of scene.endpointRefs) {
          if (boxContains(box, { x: ref.x, y: ref.y, width: 146, height: 50 })) this.selection.add(ref.endpoint.endpoint_id);
        }
      }
    }
    this.drag = null;
    this.selectionRect.setAttribute('visibility', 'hidden');
    this.render();
    this.renderSide();
  }

  updateSelectionRect(a, b) {
    const box = normalizeBox(a, b);
    for (const [key, value] of Object.entries(box)) this.selectionRect.setAttribute(key, value);
  }

  zoomAt(factor) {
    const rect = this.svgRoot.getBoundingClientRect();
    const point = { x: rect.width / 2, y: rect.height / 2 };
    const world = screenPointToWorld(point, this.view);
    this.view.scale = Math.max(.25, Math.min(2.1, this.view.scale * factor));
    this.view.x = point.x - world.x * this.view.scale;
    this.view.y = point.y - world.y * this.view.scale;
    this.transformWorld();
  }

  transformWorld() {
    this.world.setAttribute('transform', `translate(${this.view.x} ${this.view.y}) scale(${this.view.scale})`);
  }

  render() {
    if (!this.svgRoot) return;
    this.world.replaceChildren();
    const scene = layoutTopology(this.topology, this.networkId, this.status);
    this.scene = scene;
    const refByKey = new Map(scene.endpointRefs.map(ref => [`${ref.endpoint.endpoint_id}\u0000${ref.groupId}`, ref]));
    for (const group of scene.groups) {
      const position = scene.groupPos.get(group.group_id);
      const count = scene.endpointRefs.filter(ref => ref.groupId === group.group_id).length;
      const height = Math.max(185, 84 + Math.ceil(count / 2) * 66 + 14);
      this.world.append(svg('rect', { x: position.x, y: position.y, width: 350, height,
        class: group.parent_group_id ? 'group-box child' : 'group-box', 'data-group-drop-id': group.group_id }));
      this.world.append(svg('text', { x: position.x + 17, y: position.y + 27, class: 'group-label',
        'data-group-drop-id': group.group_id }, group.name));
      const parentName = scene.groups.find(item => item.group_id === group.parent_group_id)?.name;
      const meta = parentName ? `nested under ${parentName} · v${group.version}` : `network root · v${group.version}`;
      this.world.append(svg('text', { x: position.x + 18, y: position.y + 45, class: 'group-meta' }, meta));
      if (group.parent_group_id && scene.groupPos.has(group.parent_group_id)) {
        const parent = scene.groupPos.get(group.parent_group_id);
        this.world.append(svg('path', { d: `M ${parent.x + 350} ${parent.y + 38} C ${parent.x + 390} ${parent.y + 38}, ${position.x - 40} ${position.y + 38}, ${position.x} ${position.y + 38}`, class: 'edge' }));
      }
    }
    for (const link of scene.links) {
      const source = refByKey.get(`${link.source_endpoint_id}\u0000${link.source_group_id}`);
      const target = refByKey.get(`${link.target_endpoint_id}\u0000${link.target_group_id}`);
      if (!source || !target) continue;
      const active = link.state === 'ACTIVE' || link.state === 'active';
      this.world.append(svg('path', { d: `M ${source.x + 145} ${source.y + 24} C ${source.x + 210} ${source.y + 24}, ${target.x - 35} ${target.y + 24}, ${target.x} ${target.y + 24}`, class: active ? 'edge' : 'edge proposed' }));
    }
    for (const ref of scene.endpointRefs) this.drawEndpoint(ref);
    for (const [key, value] of Object.entries(this.view)) if (Number.isFinite(value)) this.view[key] = value;
    this.transformWorld();
    const stageTitle = this.stage.querySelector('.stage-head .chip');
    if (stageTitle) stageTitle.textContent = `Network · ${this.networkName()}`;
    this.banner.textContent = this.message || `Local layout only · ${scene.endpointRefs.length} endpoint references · zoom ${Math.round(this.view.scale * 100)}%`;
  }

  drawEndpoint(ref) {
    const endpoint = ref.endpoint;
    const group = svg('g', { class: this.selection.has(endpoint.endpoint_id) ? 'endpoint selected' : 'endpoint',
      'data-endpoint-id': endpoint.endpoint_id, 'data-group-ref': ref.groupId, tabindex: '0', role: 'button',
      'aria-label': `${endpoint.name || endpoint.endpoint_id}, ${endpoint.presence || 'presence unknown'}` });
    group.append(svg('rect', { x: ref.x, y: ref.y, width: 146, height: 50, class: 'endpoint-card', rx: 9 }));
    group.append(svg('text', { x: ref.x + 10, y: ref.y + 19, class: 'endpoint-name' }, endpoint.name || endpoint.endpoint_id));
    const status = ref.status?.presence;
    const state = status?.known ? `${status.state}${status.stale ? ' · stale' : ''}` : 'presence unknown';
    group.append(svg('text', { x: ref.x + 10, y: ref.y + 37, class: 'endpoint-meta' }, `${state} · ${ref.groupId || 'unassigned'}`));
    this.world.append(group);
  }

  async previewEndpointJoin(endpointId, groupId) {
    try {
      const endpoint = this.topology.endpoints?.find(item => item.endpoint_id === endpointId);
      if (!endpoint) throw new Error('Endpoint is no longer visible in this Owner snapshot. Refresh before continuing.');
      let intent;
      if (groupHasMember(this.topology, endpoint, groupId)) {
        intent = endpointJoinGesture(this.topology, endpointId, groupId, this.networkId);
      } else {
        if (!(endpoint.network_ids || []).includes(this.networkId)) {
          throw new Error('Only an Endpoint enrolled in the selected Network can be admitted to this Group.');
        }
        this.setMessage('Fetching an exact Owner-scoped admission preview. No Group membership is being written.');
        const preview = await this.rpc('topology.endpoint_admission_preview', {
          network_id: this.networkId, group_id: groupId, endpoint_id: endpointId
        });
        intent = endpointAdmissionGesture(this.topology, endpointId, groupId, this.networkId, preview);
      }
      this.queueAction(intent.action, intent.review);
    } catch (error) {
      this.setMessage(error.message);
    }
  }

}

installCanvasControls(CanvasPanel);
