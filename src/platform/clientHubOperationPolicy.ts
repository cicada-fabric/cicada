/** Local implementation is required even when an authenticated Hub grants permission. */
export const IMPLEMENTED_CLIENT_RPC_OPERATIONS = [
  'session.capabilities', 'status.snapshot', 'status.changes', 'goal.lifecycle', 'goal.result',
  'topology.snapshot', 'topology.apply', 'devices.list', 'devices.revoke',
  'nodes.preview', 'nodes.confirm', 'nodes.list', 'nodes.revoke',
  'approvals.list', 'approvals.decide', 'intent.get', 'intent.status', 'intent.list', 'intent.submit',
  'link.list', 'link.invite_create', 'link.invite_preview', 'link.invite_accept',
  'group.key_manifest', 'group.key_grant', 'group.key_status',
  'network.key_manifest', 'network.key_grant', 'network.key_status',
  'monitor.broadcast_prepare', 'monitor.broadcast_confirm',
  'monitor.broadcast_recover', 'monitor.broadcast_status',
] as const;

/** Separate dual-Owner consent, admission and delegated proposal flows are not implemented. */
export const DEFERRED_CLIENT_CONSENT_OPERATIONS = [
  'space.foreign_member_admit', 'space.foreign_member_revoke', 'space.foreign_endpoint_join',
  'space.key_manifest_v2', 'space.key_consent_v2', 'space.key_admission_v2', 'space.key_status_v2',
  'topology.delegation_issue', 'topology.delegation_revoke', 'topology.regroup_proposal',
] as const;

export const UNVERIFIED_LINK_KEY_OPERATIONS = [
  'link.key_manifest', 'link.key_grants', 'link.key_grant',
] as const;

export type ImplementedClientRpcOperation = typeof IMPLEMENTED_CLIENT_RPC_OPERATIONS[number];
export type DeferredClientConsentOperation = typeof DEFERRED_CLIENT_CONSENT_OPERATIONS[number];
export type CatalogClientRpcOperation = ImplementedClientRpcOperation |
  DeferredClientConsentOperation | typeof UNVERIFIED_LINK_KEY_OPERATIONS[number];

const implemented = new Set<string>(IMPLEMENTED_CLIENT_RPC_OPERATIONS);
const mutating = new Set<string>([
  'goal.lifecycle', 'topology.apply', 'devices.revoke', 'nodes.confirm', 'nodes.revoke',
  'approvals.decide', 'intent.submit', 'link.invite_create', 'link.invite_accept',
  'group.key_grant', 'network.key_grant', 'monitor.broadcast_prepare', 'monitor.broadcast_confirm',
]);

export function isImplementedClientRpcOperation(value: unknown): value is ImplementedClientRpcOperation {
  return typeof value === 'string' && implemented.has(value);
}

interface OperationSession {
  nativeAvailable: boolean;
  remoteEnabled: boolean;
  sessionCapabilitiesReady: boolean;
  authFenced?: boolean;
  recoveryBlocked?: boolean;
  pendingOperationId?: string;
  uncertainNeedsReconciliation?: boolean;
  networkGrantReconciliationRequired?: boolean;
  allowedOperations: readonly string[];
}

export function clientHubOperationAllowed(status: OperationSession, operation: string): boolean {
  if (!isImplementedClientRpcOperation(operation)) return false;
  if (operation === 'network.key_grant' && status.networkGrantReconciliationRequired) return false;
  if (status.uncertainNeedsReconciliation && mutating.has(operation)) return false;
  return status.nativeAvailable === true && status.remoteEnabled === true &&
    status.sessionCapabilitiesReady === true && !status.authFenced && !status.recoveryBlocked &&
    !status.pendingOperationId && status.allowedOperations.includes(operation);
}
