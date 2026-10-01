/** Local implementation is required even when an authenticated Hub grants permission. */
export const IMPLEMENTED_CLIENT_RPC_OPERATIONS = [
  'session.capabilities', 'status.snapshot', 'status.changes', 'goal.lifecycle', 'goal.result',
  'topology.snapshot', 'topology.apply', 'devices.list', 'devices.revoke',
  'nodes.preview', 'nodes.confirm', 'nodes.list', 'nodes.revoke',
  'approvals.list', 'approvals.decide', 'intent.get', 'intent.status', 'intent.list', 'intent.submit',
  'link.list', 'link.invite_create', 'link.invite_preview', 'link.invite_accept',
  'link.review_policy_status',
  'group.key_manifest', 'group.key_grant', 'group.key_status',
  'network.key_manifest', 'network.key_grant', 'network.key_status',
  'network.directory', 'topology.endpoint_admission_preview',
  'topology.regroup_proposal', 'topology.delegation_issue', 'topology.delegation_revoke',
  'monitor.broadcast_prepare', 'monitor.broadcast_confirm',
  'monitor.broadcast_recover', 'monitor.broadcast_status',
] as const;

/** Separate dual-Owner consent and admission flows are not implemented. */
export const DEFERRED_CLIENT_CONSENT_OPERATIONS = [
  'space.foreign_member_admit', 'space.foreign_member_revoke', 'space.foreign_endpoint_join',
  'space.key_manifest_v2', 'space.key_consent_v2', 'space.key_admission_v2', 'space.key_status_v2',
] as const;

export const UNVERIFIED_LINK_KEY_OPERATIONS = [
  'link.key_manifest', 'link.key_grants', 'link.key_grant',
] as const;

/** v1.6 routes held closed until their independent proof/current-authority paths are complete. */
export const DEFERRED_V16_RPC_OPERATIONS = [
  'space.foreign_endpoint_preview',
  'network.collaboration_key_manifest', 'network.collaboration_key_grant',
  'network.collaboration_key_status',
  'link.review_policy_preview', 'link.review_policy_grant',
] as const;

export type ImplementedClientRpcOperation = typeof IMPLEMENTED_CLIENT_RPC_OPERATIONS[number];
export type DeferredClientConsentOperation = typeof DEFERRED_CLIENT_CONSENT_OPERATIONS[number];
export type DeferredV16RpcOperation = typeof DEFERRED_V16_RPC_OPERATIONS[number];
export type CatalogClientRpcOperation = ImplementedClientRpcOperation |
  DeferredClientConsentOperation | DeferredV16RpcOperation |
  typeof UNVERIFIED_LINK_KEY_OPERATIONS[number];

const implemented = new Set<string>(IMPLEMENTED_CLIENT_RPC_OPERATIONS);
const mutating = new Set<string>([
  'goal.lifecycle', 'topology.apply', 'devices.revoke', 'nodes.confirm', 'nodes.revoke',
  'approvals.decide', 'intent.submit', 'link.invite_create', 'link.invite_accept',
  'group.key_grant', 'network.key_grant', 'monitor.broadcast_prepare', 'monitor.broadcast_confirm',
  'topology.delegation_issue', 'topology.delegation_revoke',
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
  regroupReconciliationRequired?: boolean;
  allowedOperations: readonly string[];
}

export function clientHubOperationAllowed(status: OperationSession, operation: string): boolean {
  if (!isImplementedClientRpcOperation(operation)) return false;
  if (operation === 'network.key_grant' && status.networkGrantReconciliationRequired) return false;
  if (status.regroupReconciliationRequired &&
      ['topology.delegation_issue', 'topology.delegation_revoke'].includes(operation)) return false;
  if (status.uncertainNeedsReconciliation && mutating.has(operation)) return false;
  return status.nativeAvailable === true && status.remoteEnabled === true &&
    status.sessionCapabilitiesReady === true && !status.authFenced && !status.recoveryBlocked &&
    !status.pendingOperationId && status.allowedOperations.includes(operation);
}
