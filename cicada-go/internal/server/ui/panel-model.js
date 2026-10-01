export function pinMatches(pin, identity, origin) {
  return Boolean(pin && identity && pin.origin === origin && pin.hubId === identity.hub_id &&
    pin.keyId === identity.control_public_identity?.id && identity.control_key_version === 1 &&
    identity.suite === 'ML-KEM-768+ML-DSA-65+AES-256-GCM');
}

export function screenPointToWorld(point, view) {
  return { x: (point.x - view.x) / view.scale, y: (point.y - view.y) / view.scale };
}

export function worldPointToScreen(point, view) {
  return { x: point.x * view.scale + view.x, y: point.y * view.scale + view.y };
}

export function normalizeBox(a, b) {
  return { x: Math.min(a.x, b.x), y: Math.min(a.y, b.y),
    width: Math.abs(a.x - b.x), height: Math.abs(a.y - b.y) };
}

export function pointInBox(point, box) {
  return point.x >= box.x && point.x <= box.x + box.width &&
    point.y >= box.y && point.y <= box.y + box.height;
}

export function boxContains(box, candidate) {
  return candidate.x >= box.x && candidate.y >= box.y &&
    candidate.x + candidate.width <= box.x + box.width &&
    candidate.y + candidate.height <= box.y + box.height;
}

export function groupHasMember(snapshot, endpoint, groupId) {
  return (snapshot.memberships || []).some(member => member.group_id === groupId &&
    member.principal_id === endpoint.principal_id && String(member.status).toLowerCase() === 'active');
}

export function endpointJoinGesture(snapshot, endpointId, groupId, networkId) {
  const endpoint = (snapshot.endpoints || []).find(item => item.endpoint_id === endpointId);
  const group = (snapshot.groups || []).find(item => item.group_id === groupId);
  if (!endpoint || !group || String(group.state).toLowerCase() !== 'active' ||
      !networkId || group.network_id !== networkId) {
    throw new Error('Drop must target a visible Group in the selected Network.');
  }
  if ((endpoint.group_ids || []).includes(groupId)) {
    throw new Error('This Endpoint already has a reference in that Group.');
  }
  if (!groupHasMember(snapshot, endpoint, groupId)) {
    throw new Error('The Endpoint has no active membership in that Group. No write was prepared.');
  }
  return {
    action: { kind: 'endpoint.join_group', join_group: { endpoint_id: endpointId, group_id: groupId } },
    review: `Attach ${endpoint.name || endpointId} to ${group.name || groupId} in ${networkId}. This adds a Group reference and preserves the Endpoint's other Group references. Shared Thread context follows the current Group policy (${group.context_policy || 'not reported in this snapshot'}); this snapshot does not describe all historical visibility, so inspect the Group sharing terms before submitting. The Hub rechecks current membership and Owner authority. Canvas position grants no access.`
  };
}

export function endpointAdmissionGesture(snapshot, endpointId, groupId, networkId, preview) {
  const endpoint = (snapshot.endpoints || []).find(item => item.endpoint_id === endpointId);
  const group = (snapshot.groups || []).find(item => item.group_id === groupId);
  if (!endpoint || !group || String(group.state).toLowerCase() !== 'active' ||
      !networkId || group.network_id !== networkId || !(endpoint.network_ids || []).includes(networkId)) {
    throw new Error('Admission preview must match a visible same-Network Endpoint and active Group.');
  }
  if ((endpoint.group_ids || []).includes(groupId)) throw new Error('This Endpoint already has a reference in that Group.');
  if (!preview || preview.owner_principal_id !== snapshot.owner_principal_id ||
      preview.network_id !== networkId || preview.group_id !== groupId || preview.endpoint_id !== endpointId ||
      preview.endpoint_principal_id !== endpoint.principal_id ||
      preview.group_context_policy !== group.context_policy ||
      !['READY', 'MIGRATION_PENDING_GROUP'].includes(preview.endpoint_migration_state) ||
      !Array.isArray(preview.admission_roles) || preview.admission_roles.length !== 1 || preview.admission_roles[0] !== 'member' ||
      !Array.isArray(preview.admission_grants) || preview.admission_grants.length !== 0 ||
      preview.history_included !== false || preview.key_grant_created !== false ||
      preview.existing_thread_memory_retained !== true ||
      preview.membership_status || preview.membership_revision !== 0 ||
      preview.endpoint_group_status || preview.endpoint_group_revision !== 0) {
    throw new Error('Admission preview is stale, outside this Owner scope, or includes existing membership; refresh and review again.');
  }
  const admission = {
    network_id: preview.network_id, group_id: preview.group_id, endpoint_id: preview.endpoint_id,
    expected_endpoint_migration_state: preview.endpoint_migration_state,
    expected_network_version: preview.network_version, expected_group_version: preview.group_version,
    expected_network_membership_revision: preview.network_membership_revision,
    expected_endpoint_network_revision: preview.endpoint_network_revision,
    network_access_binding_id: preview.network_access_binding_id,
    network_access_epoch: preview.network_access_epoch,
    native_binding_id: preview.native_binding_id, native_binding_epoch: preview.native_binding_epoch,
    existing_group_binding_id: preview.existing_group_binding_id,
    existing_group_binding_epoch: preview.existing_group_binding_epoch,
    expected_membership_revision: preview.membership_revision,
    expected_endpoint_group_revision: preview.endpoint_group_revision
  };
  if (!Number.isSafeInteger(admission.expected_network_version) || admission.expected_network_version < 1 ||
      !Number.isSafeInteger(admission.expected_group_version) || admission.expected_group_version < 1 ||
      !Number.isSafeInteger(admission.expected_network_membership_revision) || admission.expected_network_membership_revision < 1 ||
      !Number.isSafeInteger(admission.expected_endpoint_network_revision) || admission.expected_endpoint_network_revision < 1 ||
      !Number.isSafeInteger(admission.network_access_epoch) || admission.network_access_epoch < 1 ||
      !Number.isSafeInteger(admission.native_binding_epoch) || admission.native_binding_epoch < 1 ||
      !admission.network_access_binding_id || !admission.native_binding_id) {
    throw new Error('Admission preview did not contain a complete current binding fence.');
  }
  return {
    action: { kind: 'endpoint.admit_group', admit_endpoint: { admission } },
    review: `Admit ${endpoint.name || endpointId} into ${group.name || groupId} in ${networkId} using the current owner-reviewed Network enrollment and native binding. This creates only a member Membership and a Group reference: no Worker/Monitor role, message.broadcast, historical access, or Group key grant. Existing Thread memory remains in the native Endpoint and is not cleared or isolated by this change. Current Group context policy: ${preview.group_context_policy}. Inspect that policy and shared-memory risk before you confirm. The Hub rechecks the exact Network, enrollment, Node/native binding and Group revisions atomically. Canvas position grants no authority.`
  };
}

export function linkGesturePair(snapshot, sourceEndpointId, sourceGroupId, targetEndpointId, targetGroupId, networkId) {
  const endpointFor = id => (snapshot.endpoints || []).find(item => item.endpoint_id === id);
  const groupFor = id => (snapshot.groups || []).find(item => item.group_id === id);
  const source = endpointFor(sourceEndpointId), target = endpointFor(targetEndpointId);
  const sourceGroup = groupFor(sourceGroupId), targetGroup = groupFor(targetGroupId);
  if (!networkId || !source || !target || !sourceGroup || !targetGroup || sourceEndpointId === targetEndpointId ||
      sourceGroup.network_id !== networkId || targetGroup.network_id !== networkId ||
      String(sourceGroup.state).toLowerCase() !== 'active' || String(targetGroup.state).toLowerCase() !== 'active' ||
      !(source.group_ids || []).includes(sourceGroupId) || !(target.group_ids || []).includes(targetGroupId) ||
      !groupHasMember(snapshot, source, sourceGroupId) || !groupHasMember(snapshot, target, targetGroupId)) {
    throw new Error('Draw between two distinct Endpoint references with current active memberships in the selected Network.');
  }
  const ownerRelation = source.owner_id && target.owner_id ?
    (source.owner_id === target.owner_id ? 'same Owner' : 'different Owners') : 'Owner relationship not available in this snapshot';
  const sourceContext = sourceGroup.context_policy || 'not reported in this snapshot';
  const targetContext = targetGroup.context_policy || 'not reported in this snapshot';
  return {
    sourceEndpointId, sourceGroupId, targetEndpointId, targetGroupId,
    review: `Propose a Link between ${source.name || sourceEndpointId} in ${sourceGroup.name || sourceGroupId} and ${target.name || targetEndpointId} in ${targetGroup.name || targetGroupId} (${ownerRelation}). Current shared-context policy: ${sourceContext} → ${targetContext}; this snapshot does not describe all historical visibility. This creates a proposal only; it does not activate routing. Each Owner's current key grants and any required acceptance are still checked by the Hub. Review the selected actions and data scopes below before authorizing.`
  };
}

export function statusLabel(observation) {
  if (!observation || observation.known !== true) return 'unknown';
  return observation.stale ? `${observation.state} · stale` : String(observation.state || 'unknown');
}

const readOnlyOperations = new Set(['topology.snapshot', 'status.snapshot', 'topology.regroup_proposal']);

export function isSemanticWriteOperation(operation) {
  return !readOnlyOperations.has(operation);
}

export function makeSemanticWriteFence(operation, operationId, bodySha256, input, createdAt) {
  if (!isSemanticWriteOperation(operation)) return null;
  const action = input?.action || input || {};
  const create = action.create_group?.group || {};
  const join = action.join_group || {};
  const admission = action.admit_endpoint?.admission || {};
  const membership = action.bind_role || action.set_broadcast_permission || {};
  const proposal = action.propose_link?.proposal || {};
  const revoke = action.revoke_link || {};
  const scope = {};
  const networkId = create.network_id || admission.network_id || action.network_id;
  const groupIds = [join.group_id, admission.group_id, membership.group_id, action.set_parent?.group_id,
    proposal.source_group_id, proposal.target_group_id, revoke.group_id].filter(Boolean);
  const endpointIds = [join.endpoint_id, admission.endpoint_id, proposal.source_endpoint_id, proposal.target_endpoint_id].filter(Boolean);
  const linkId = revoke.link_id;
  if (networkId) scope.networkId = String(networkId);
  if (groupIds.length) scope.groupIds = [...new Set(groupIds.map(String))];
  if (endpointIds.length) scope.endpointIds = [...new Set(endpointIds.map(String))];
  if (linkId) scope.linkId = String(linkId);
  return { operationID: operationId, operation, bodySha256, digestBasis: 'submitted-json', scope, createdAt };
}

export function recoveredWriteFence(pending, legacyPacketSha256 = '') {
  if (pending?.writeFence) return pending.writeFence;
  if (!pending || !isSemanticWriteOperation(pending.operation)) return null;
  if (!legacyPacketSha256) throw new Error('Legacy uncertain write needs a sealed-packet fingerprint.');
  return { operationID: pending.operationId, operation: pending.operation, bodySha256: '',
    packetSha256: legacyPacketSha256, digestBasis: 'legacy-sealed-packet', scope: { unavailable: true },
    createdAt: pending.createdAt || '', legacy: true };
}

export function reserveClientRequest(device, sealAtSequence, operation = '') {
  if (!device?.active || !Number.isSafeInteger(device.sessionEpoch) || device.sessionEpoch < 1) {
    throw new Error('No active enrolled browser device is available.');
  }
  if (device.pending) throw new Error('A Client request is unresolved. Recover that exact request before sending another.');
  if (device.writeFence && isSemanticWriteOperation(operation)) {
    throw new Error('A prior write has an uncertain outcome. Review fresh topology and status, then explicitly authorize a new write.');
  }
  const sequence = device.nextRequestSequence;
  if (!Number.isSafeInteger(sequence) || sequence < 1 || !Number.isSafeInteger(device.nextResponseSequence) || device.nextResponseSequence < 1) {
    throw new Error('Request or response sequence state is invalid; stop and restore a verified backup.');
  }
  const pending = sealAtSequence(sequence, device.nextResponseSequence);
  if (!pending || typeof pending.packet !== 'string' || !pending.packet || !pending.operationId) {
    throw new Error('Client Wire request could not be sealed.');
  }
  return { ...device, nextRequestSequence: sequence + 1, pending };
}

export function completeClientRequest(device, pending, responseSequence, outcome = {}) {
  if (!device?.pending || device.pending.packet !== pending?.packet ||
      device.pending.operationId !== pending.operationId || responseSequence !== device.nextResponseSequence) {
    throw new Error('Pending request or authenticated response sequence changed in another browser tab.');
  }
  const next = { ...device, pending: null, nextResponseSequence: responseSequence + 1,
    lastRequestSequence: pending.requestSequence, lastOperationId: pending.operationId };
  if (outcome.errorCode === 'OUTCOME_UNCERTAIN' && pending.writeFence && !device.writeFence) {
    next.writeFence = { ...pending.writeFence, resolvedAt: outcome.resolvedAt || new Date().toISOString() };
  }
  return next;
}

export function authorizeWriteFenceState(state, operationID, authorizedAt) {
  const fence = state.device?.writeFence;
  if (state.device?.pending) {
    throw new Error('A Client request is still unresolved. Recover the exact packet and refresh snapshots before authorizing a new write.');
  }
  if (!fence || fence.operationID !== operationID) {
    throw new Error('The uncertain write fence changed in another tab. Refresh state before authorizing a new write.');
  }
  const acknowledgements = [...(state.device.writeFenceAcknowledgements || []),
    { ...fence, authorizedAt }].slice(-16);
  return { ...state, device: { ...state.device, writeFence: null,
    writeFenceAcknowledgements: acknowledgements } };
}

export function createDeviceDraftState(state, origin, vault, manifest) {
  if (!state?.pin || state.pin.origin !== origin || state.pin.hubId !== manifest.hub_id) {
    throw new Error('Pinned Hub identity changed while the device key was being created.');
  }
  if (state.device?.active || state.enrollment?.body || state.deviceDraft || state.vault) {
    throw new Error('Another browser tab already created a device draft, enrollment, or vault.');
  }
  return { ...state, vault, deviceDraft: manifest };
}

export function saveEnrollmentState(state, request, origin) {
  if (state.device?.active) throw new Error('This browser device is already enrolled.');
  if (!state.pin || state.pin.hubId !== request.hubId || state.pin.origin !== origin ||
      !state.deviceDraft || state.deviceDraft.owner_id !== request.ownerId ||
      state.deviceDraft.owner_key_id !== request.ownerKeyId || state.deviceDraft.device_id !== request.deviceId ||
      state.deviceDraft.device_public_identity?.id !== request.deviceKeyId || !state.vault) {
    throw new Error('Enrollment request no longer matches the saved pinned Hub, encrypted device key, and public draft.');
  }
  if (state.enrollment?.body && state.enrollment.body !== request.body) {
    throw new Error('An exact enrollment request is already pending. Retry or inspect that request before creating another.');
  }
  return { ...state, enrollment: request };
}

export function actionSummary(action) {
  const label = action.kind;
  if (action.create_group) {
    const parent = action.parent_group_id ? ` under ${action.parent_group_id}` : ' at network root';
    return `Create Group “${action.create_group.group.name}”${parent}.`;
  }
  if (action.join_group) return `Attach Endpoint ${action.join_group.endpoint_id} to Group ${action.join_group.group_id}.`;
  if (action.admit_endpoint) return `Admit Endpoint ${action.admit_endpoint.admission.endpoint_id} as a minimum Group member in ${action.admit_endpoint.admission.group_id}.`;
  if (action.set_parent) return `Move Group ${action.set_parent.group_id} under ${action.set_parent.parent_group_id || 'network root'} (version ${action.set_parent.expected_group_version}).`;
  if (action.bind_role) return `Set Membership ${action.bind_role.membership_id} role to ${action.bind_role.role} (version ${action.bind_role.expected_membership_version}).`;
  if (action.set_broadcast_permission) return `${action.set_broadcast_permission.enabled ? 'Grant' : 'Remove'} message.broadcast for Membership ${action.set_broadcast_permission.membership_id} (version ${action.set_broadcast_permission.expected_membership_version}).`;
  if (action.propose_link) return `Propose a ${action.propose_link.proposal.direction} Link from ${action.propose_link.proposal.source_endpoint_id} to ${action.propose_link.proposal.target_endpoint_id}. It will remain proposed until the other side accepts.`;
  if (action.revoke_link) return `Revoke Link ${action.revoke_link.link_id} (version ${action.revoke_link.expected_link_version}).`;
  return `Apply ${label} as one versioned topology action.`;
}

export function layoutTopology(snapshot, networkId, statusSnapshot = null) {
  const groups = (snapshot.groups || []).filter(group => !networkId || !group.network_id || group.network_id === networkId);
  const visible = new Set(groups.map(group => group.group_id));
  const children = new Map();
  for (const group of groups) {
    const parent = visible.has(group.parent_group_id) ? group.parent_group_id : '';
    if (!children.has(parent)) children.set(parent, []);
    children.get(parent).push(group);
  }
  for (const list of children.values()) list.sort((a, b) => a.name.localeCompare(b.name) || a.group_id.localeCompare(b.group_id));
  const groupPos = new Map();
  function place(parentId, depth, baseY) {
    const list = children.get(parentId) || [];
    let y = baseY;
    for (const group of list) {
      const pos = { x: 60 + depth * 400, y };
      groupPos.set(group.group_id, pos);
      const below = place(group.group_id, depth + 1, y + 310);
      y = Math.max(y + 310, below);
    }
    return y;
  }
  place('', 0, 85);
  const endpoints = new Map((snapshot.endpoints || []).map(endpoint => [endpoint.endpoint_id, endpoint]));
  const statusByEndpoint = new Map((statusSnapshot?.endpoints || []).map(endpoint => [endpoint.endpoint_id, endpoint]));
  const endpointRefs = [];
  for (const group of groups) {
    const position = groupPos.get(group.group_id);
    const refs = [];
    for (const endpoint of endpoints.values()) {
      if ((endpoint.group_ids || []).includes(group.group_id)) refs.push(endpoint);
    }
    refs.sort((a, b) => a.name.localeCompare(b.name) || a.endpoint_id.localeCompare(b.endpoint_id));
    refs.forEach((endpoint, index) => endpointRefs.push({
      endpoint, groupId: group.group_id, x: position.x + 18 + (index % 2) * 160,
      y: position.y + 70 + Math.floor(index / 2) * 66,
      status: statusByEndpoint.get(endpoint.endpoint_id)
    }));
  }
  const orphanEndpoints = [...endpoints.values()].filter(endpoint => !(endpoint.group_ids || []).some(id => visible.has(id)));
  orphanEndpoints.forEach((endpoint, index) => endpointRefs.push({
    endpoint, groupId: '', x: 80 + (index % 4) * 165,
    y: 120 + Math.floor(index / 4) * 80 + Math.max(330, groups.length * 330),
    status: statusByEndpoint.get(endpoint.endpoint_id)
  }));
  return { groups, groupPos, endpointRefs, links: snapshot.links || [] };
}
