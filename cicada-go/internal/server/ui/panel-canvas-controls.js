import { actionSummary, groupHasMember } from './panel-model.js';
import { button, html, selectField, textField } from './panel-dom.js';

export function installCanvasControls(CanvasPanel) {
  Object.assign(CanvasPanel.prototype, {
  renderSide() {
    this.side.replaceChildren();
    this.side.append(this.ownerCard(), this.statusCard(), this.groupCard(), this.joinCard(),
      this.monitorCard(), this.linkCard(), this.linksCard(), this.warningCard());
    if (this.writeFence) this.side.append(this.writeFenceCard());
    if (this.plan.length) this.side.append(this.planCard());
  },

  ownerCard() {
    const card = html('section', 'card');
    card.append(html('div', 'eyebrow', 'OWNER SESSION'), html('h2', '', this.topology.owner_principal_id || 'Owner unavailable'));
    const networks = (this.topology.networks || []).map(item => ({ value: item.network_id, label: `${item.name} · ${item.state}` }));
    if (networks.length) {
      const network = selectField('Active Network', networks, this.networkId);
      network.select.addEventListener('change', () => { this.networkId = network.select.value; this.selection.clear(); this.render(); this.renderSide(); });
      card.append(network.wrap);
    }
    const header = html('div', 'buttons');
    header.append(button('Recover pending request', () => this.recoverPending(), 'btn warn'), button('Lock device', () => this.lock(), 'btn quiet'));
    card.append(header);
    if (this.plan.length) card.append(html('p', 'small', `${this.plan.length} preview item(s) waiting for separate confirmation.`));
    return card;
  },

  statusCard() {
    const card = html('section', 'card');
    card.append(html('h2', '', 'Live status snapshot'));
    const scope = this.status.scope_mode || 'unknown scope';
    card.append(html('p', 'small', `${scope} · captured ${this.status.captured_at || 'unknown time'}`));
    const visibleGroupIds = new Set((this.topology.groups || []).filter(group =>
      !this.networkId || !group.network_id || group.network_id === this.networkId).map(group => group.group_id));
    const groups = (this.status.groups || []).filter(item => visibleGroupIds.has(item.group_id));
    const endpoints = (this.status.endpoints || []).filter(item => !this.networkId || !item.group_ids?.length ||
      item.group_ids.some(id => this.topology.groups?.some(group => group.group_id === id && (!group.network_id || group.network_id === this.networkId))));
    card.append(html('div', 'status-row', `${groups.length} Groups`), html('div', 'status-row', `${endpoints.length} Endpoints`));
    for (const endpoint of endpoints.slice(0, 7)) {
      const row = html('div', 'status-row');
      row.append(html('span', '', endpoint.name || endpoint.endpoint_id), html('span', 'chip', endpoint.presence?.known ? endpoint.presence.state : 'unknown'));
      card.append(row);
    }
    return card;
  },

  groupCard() {
    const card = html('section', 'card');
    card.append(html('h2', '', 'Create Group'));
    const networkItems = (this.topology.networks || []).filter(item => item.can_create_group);
    if (!networkItems.length) { card.append(html('p', 'small', 'No active Owner-managed Network currently allows Group creation.')); return card; }
    const networkSelect = selectField('Network', networkItems.map(item => ({ value: item.network_id, label: item.name })), this.networkId);
    const parentSelect = selectField('Parent Group', []);
    const updateParentOptions = () => {
      parentSelect.select.replaceChildren();
      for (const option of [{ value: '', label: 'Network root' }, ...this.groupsForNetwork(networkSelect.select.value).map(group => ({ value: group.group_id, label: group.name }))]) {
        const item = html('option', '', option.label);
        item.value = option.value;
        parentSelect.select.append(item);
      }
    };
    networkSelect.select.addEventListener('change', updateParentOptions);
    updateParentOptions();
    const name = textField('New Group name');
    card.append(networkSelect.wrap, parentSelect.wrap, name.wrap,
      html('p', 'footer-note', 'A nested create is one topology action, but the current Control implementation writes the new Group and its parent relation separately; if the second step fails, inspect the refreshed snapshot for a root Group.'),
      button('Preview Group creation', () => {
        const action = { kind: 'group.create', create_group: { group: { network_id: networkSelect.select.value, name: name.input.value.trim() }, parent_group_id: parentSelect.select.value } };
        this.queueAction(action);
      }, 'btn primary'));
    return card;
  },

  joinCard() {
    const card = html('section', 'card');
    card.append(html('h2', '', 'Attach selected Endpoints'));
    const selected = this.selectedEndpoints();
    card.append(html('p', 'small', `${selected.length} Endpoint(s) selected. A join preserves existing references in other Groups.`));
    const groups = this.groupsForNetwork();
    const group = selectField('Target Group', groups.map(item => ({ value: item.group_id, label: item.name })), groups[0]?.group_id || '');
    card.append(group.wrap, button('Preview joins one by one', () => {
      if (!group.select.value) { this.setMessage('Choose an active Group first.'); return; }
      const queue = [];
      for (const endpoint of selected) {
        if ((endpoint.group_ids || []).includes(group.select.value)) continue;
        if (!groupHasMember(this.topology, endpoint, group.select.value)) continue;
        queue.push({ kind: 'endpoint.join_group', join_group: { endpoint_id: endpoint.endpoint_id, group_id: group.select.value } });
      }
      if (!queue.length) { this.setMessage('No selected Endpoint has an active membership for that Group, or all are already attached.'); return; }
      this.plan = queue;
      this.renderSide();
    }, 'btn primary'));
    return card;
  },

  monitorCard() {
    const card = html('section', 'card');
    card.append(html('h2', '', 'Membership & Monitor settings'));
    const members = (this.topology.memberships || []).filter(item => !this.networkId || this.topology.groups?.some(group => group.group_id === item.group_id && group.network_id === this.networkId));
    if (!members.length) { card.append(html('p', 'small', 'No visible Group Memberships.')); return card; }
    const member = selectField('Membership', members.map(item => ({ value: item.membership_id, label: `${item.display_name || item.principal_id} · ${item.group_id}` })));
    const role = selectField('Role', ['member', 'worker', 'monitor'].map(value => ({ value, label: value })), 'monitor');
    const roleAction = button('Preview role update', () => {
      const item = members.find(value => value.membership_id === member.select.value);
      if (!item) return;
      this.queueAction({ kind: 'membership.bind_role', bind_role: { group_id: item.group_id,
        membership_id: item.membership_id, role: role.select.value,
        expected_membership_version: item.version } });
    }, 'btn');
    const broadcast = selectField('Explicit message.broadcast permission', [
      { value: 'false', label: 'Keep disabled / remove grant' }, { value: 'true', label: 'Enable for this Membership' }], 'false');
    const broadcastAction = button('Preview permission change', () => {
      const item = members.find(value => value.membership_id === member.select.value);
      if (!item) return;
      this.queueAction({ kind: 'membership.set_broadcast_permission', set_broadcast_permission: {
        group_id: item.group_id, membership_id: item.membership_id,
        enabled: broadcast.select.value === 'true', expected_membership_version: item.version } });
    }, 'btn warn');
    card.append(member.wrap, role.wrap, roleAction, html('p', 'footer-note', 'A Monitor role does not grant message.broadcast. That permission is a separate explicit action.'), broadcast.wrap, broadcastAction);
    return card;
  },

  linkCard() {
    const card = html('section', 'card');
    card.append(html('h2', '', 'Propose a Link'));
    const endpoints = (this.topology.endpoints || []).filter(item => !this.networkId || item.network_ids?.includes(this.networkId) || item.group_ids?.some(id => this.topology.groups?.some(group => group.group_id === id && (!group.network_id || group.network_id === this.networkId))));
    if (endpoints.length < 2) { card.append(html('p', 'small', 'At least two visible Endpoints are needed.')); return card; }
    const endpointOptions = endpoints.map(item => ({ value: item.endpoint_id, label: item.name || item.endpoint_id }));
    const source = selectField('Source Endpoint', endpointOptions);
    const target = selectField('Target Endpoint', endpointOptions, endpoints[1].endpoint_id);
    const sourceGroup = selectField('Source Group', this.groupsForNetwork().map(item => ({ value: item.group_id, label: item.name })));
    const targetGroup = selectField('Target Group', this.groupsForNetwork().map(item => ({ value: item.group_id, label: item.name })));
    const scopes = textField('Data scopes (comma separated)', 'status');
    const actions = textField('Allowed actions (comma separated)', 'task.read');
    const expiry = textField('Expires in days', '7', 'number');
    card.append(source.wrap, sourceGroup.wrap, target.wrap, targetGroup.wrap, actions.wrap, scopes.wrap, expiry.wrap,
      html('p', 'footer-note', 'Proposing a Link does not make it active. The other side must separately review and accept it.'),
      button('Preview Link proposal', () => {
        const endTime = new Date(Date.now() + Math.max(1, Number(expiry.input.value) || 7) * 86400000).toISOString();
        this.queueAction({ kind: 'link.propose', propose_link: { proposal: {
          source_endpoint_id: source.select.value, source_group_id: sourceGroup.select.value,
          target_endpoint_id: target.select.value, target_group_id: targetGroup.select.value,
          direction: 'bidirectional', actions: actions.input.value.split(',').map(value => value.trim()).filter(Boolean),
          data_scopes: scopes.input.value.split(',').map(value => value.trim()).filter(Boolean), expires_at: endTime } } });
      }, 'btn primary'));
    return card;
  },

  linksCard() {
    const card = html('section', 'card');
    card.append(html('h2', '', 'Links'));
    const links = this.topology.links || [];
    if (!links.length) { card.append(html('p', 'small', 'No visible Link proposals or active Links.')); return card; }
    for (const link of links.slice(0, 8)) {
      const row = html('div', 'status-row');
      row.append(html('span', '', `${link.source_endpoint_id} ↔ ${link.target_endpoint_id}`), html('span', link.state === 'ACTIVE' ? 'chip good' : 'chip warn', link.state));
      if (link.state === 'ACTIVE' || link.state === 'active') row.append(button('Revoke', () => this.queueAction({ kind: 'link.revoke', revoke_link: { link_id: link.link_id, expected_link_version: link.version } }), 'btn quiet small'));
      card.append(row);
    }
    card.append(html('p', 'footer-note', 'A proposal is not an active cross-Owner Link. Only an accepted, currently authorized Link is active.'));
    return card;
  },

  warningCard() {
    const card = html('section', 'card');
    card.append(html('h2', '', 'Shared Thread memory'),
      html('p', 'small', 'Endpoints in the same Group may share Thread memory according to Group policy. Review sharing and retention before adding an Endpoint. Canvas position is local presentation and never an ACL.'));
    return card;
  },

  planCard() {
    const card = html('section', 'card');
    card.append(html('h2', '', 'Exact action preview'));
    const action = this.plan[0];
    card.append(html('p', '', actionSummary(action)), html('p', 'small', `${this.plan.length} action(s) are queued. Only the first is shown and submitted; each next item requires its own review.`));
    const pre = html('pre');
    pre.textContent = JSON.stringify(action, null, 2);
    card.append(pre, button('Commit this one action', () => this.applyFirst(), 'btn primary'),
      button('Discard preview queue', () => { this.plan = []; this.renderSide(); }, 'btn quiet'));
    return card;
  },

  writeFenceCard() {
    const fence = this.writeFence;
    const card = html('section', 'card fence-card');
    card.append(html('div', 'eyebrow danger-text', 'UNCERTAIN WRITE FENCE'),
      html('h2', '', 'A prior change may have taken effect'),
      html('p', 'small', `${fence.operation} · operation ${fence.operationID}`),
      html('p', 'small', fence.digestBasis === 'legacy-sealed-packet' ?
        `Legacy sealed-packet SHA-256: ${fence.packetSha256}` : `Submitted JSON body SHA-256: ${fence.bodySha256}`),
      html('p', 'small', `Scope: ${JSON.stringify(fence.scope || {})}`),
      html('p', 'footer-note', 'The authenticated recovery response advanced the Client sequence, but it did not prove whether this change applied. No new topology write is allowed until you inspect fresh snapshots and explicitly authorize one. The old action is never replayed.'));
    card.append(button('Refresh topology and status for review', () => this.reload(true), 'btn warn'));
    const reviewed = this.reviewedWriteFenceID === fence.operationID;
    const authorize = button('I reviewed this state; authorize a new write', () => this.authorizeReviewedWriteFence(), 'btn primary');
    authorize.disabled = !reviewed;
    card.append(authorize);
    if (!reviewed) card.append(html('p', 'small', 'Refresh after the uncertain operation resolves. The confirmation button unlocks only after both authoritative snapshots finish.'));
    return card;
  },

  async authorizeReviewedWriteFence() {
    const fence = this.writeFence;
    if (!fence || this.reviewedWriteFenceID !== fence.operationID) {
      this.setMessage('Refresh topology and status for this exact write fence before authorizing another write.');
      return;
    }
    const digestLabel = fence.digestBasis === 'legacy-sealed-packet' ?
      `Legacy packet SHA-256: ${fence.packetSha256}` : `Submitted JSON SHA-256: ${fence.bodySha256}`;
    const confirmed = globalThis.confirm(`Authorize new topology writes after reviewing the fresh state?\n\nPrior operation: ${fence.operation}\nOperation ID: ${fence.operationID}\n${digestLabel}\nScope: ${JSON.stringify(fence.scope || {})}\n\nThis does not retry or repeat the prior action.`);
    if (!confirmed) return;
    try {
      await this.clearWriteFence(fence.operationID);
      this.writeFence = null;
      this.reviewedWriteFenceID = '';
      this.plan = [];
      this.message = 'You authorized a new write after reviewing fresh snapshots. The prior action was not replayed.';
      this.render();
      this.renderSide();
    } catch (error) {
      this.setMessage(error.message);
      await this.reload();
    }
  },

  queueAction(action) {
    if (this.writeFence) {
      this.setMessage('A prior write has an uncertain outcome. Review fresh topology and status, then explicitly authorize a new write.');
      return;
    }
    const errors = this.validateAction(action);
    if (errors) { this.setMessage(errors); return; }
    this.plan = [action];
    this.renderSide();
  },

  validateAction(action) {
    if (action.create_group && !action.create_group.group.name) return 'Enter a Group name before previewing.';
    if (action.propose_link && (!action.propose_link.proposal.source_group_id || !action.propose_link.proposal.target_group_id)) return 'Choose both Groups for the Link proposal.';
    if (action.propose_link && (!action.propose_link.proposal.actions.length || !action.propose_link.proposal.data_scopes.length)) return 'Link proposal needs at least one action and data scope.';
    return '';
  },

  async applyFirst() {
    if (this.writeFence) {
      this.setMessage('A prior write has an uncertain outcome. Review fresh topology and status, then explicitly authorize a new write.');
      return;
    }
    const action = this.plan[0];
    if (!action) return;
    const button = [...this.side.querySelectorAll('button')].find(item => item.textContent === 'Commit this one action');
    if (button) button.disabled = true;
    this.message = `Submitting ${action.kind} as one encrypted topology.apply action…`;
    this.render();
    try {
      await this.rpc('topology.apply', action);
      this.plan.shift();
      this.message = `${action.kind} returned an authenticated result. Reloading topology and status before the next action.`;
      await this.reload();
    } catch (error) {
      this.message = `${action.kind} stopped: ${error.message}. Refresh the authoritative snapshots before deciding whether to retry.`;
      this.plan = [];
      this.banner.textContent = this.message;
      if (error.message.includes('unresolved') || error.message.includes('sequence state')) this.pending?.(error.message);
      else await this.reload();
    }
    this.renderSide();
  },

  async recoverPending() {
    try {
      const result = await this.recover();
      if (result?.error_code === 'OUTCOME_UNCERTAIN') this.message = 'The prior action has an uncertain outcome. The next snapshots are authoritative; review them before making another change.';
      else this.message = 'The prior encrypted Client operation was recovered.';
      await this.reload();
    } catch (error) {
      this.pending?.(error.message);
    }
  },

  setMessage(message) {
    this.message = message;
    this.banner.textContent = message;
  },

  groupsForNetwork(networkId = this.networkId) {
    return (this.topology.groups || []).filter(group => !networkId || !group.network_id || group.network_id === networkId);
  },

  selectedEndpoints() {
    return (this.topology.endpoints || []).filter(endpoint => this.selection.has(endpoint.endpoint_id));
  }
  });
}
