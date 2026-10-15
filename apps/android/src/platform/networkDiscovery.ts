import type {NetworkDirectoryEndpoint, NetworkDirectoryPage} from './networkTopology';

export interface NetworkDiscoveryScope {
  profileId: string;
  selectionGeneration: number;
  networkId: string;
  hubId: string;
  ownerId: string;
  deviceId: string;
  sessionEpoch: number | null;
  authorityRevision: string;
  fenceRevision: string;
  networkVersion: number | null;
}

export function networkDiscoveryScopeKey(scope: NetworkDiscoveryScope): string {
  return JSON.stringify([
    scope.profileId, scope.selectionGeneration, scope.networkId, scope.hubId,
    scope.ownerId, scope.deviceId, scope.sessionEpoch, scope.authorityRevision,
    scope.fenceRevision, scope.networkVersion,
  ]);
}

export interface NetworkDiscoveryRequestToken {
  readonly scopeKey: string;
  readonly generation: number;
}

/** Invalidates deferred UI callbacks when the selected profile, Network, or authority changes. */
export class NetworkDiscoveryLifecycle {
  private generation = 0;

  invalidate(): void {
    this.generation++;
  }

  capture(scopeKey: string): NetworkDiscoveryRequestToken {
    return Object.freeze({scopeKey, generation: this.generation});
  }

  isCurrent(token: NetworkDiscoveryRequestToken, currentScopeKey: string): boolean {
    return token.generation === this.generation && token.scopeKey === currentScopeKey;
  }
}

export interface NetworkDirectoryView {
  endpoints: NetworkDirectoryEndpoint[];
  nextCursor?: string;
  requestedAfterEndpointIds: Array<string | null>;
  cursorLoop: boolean;
}

export const emptyNetworkDirectoryView = (): NetworkDirectoryView => ({
  endpoints: [], requestedAfterEndpointIds: [], cursorLoop: false,
});

/** Keep the first copy of each reference and stop if the Hub repeats a pagination cursor. */
export function appendNetworkDirectoryPage(
  current: NetworkDirectoryView,
  page: NetworkDirectoryPage,
  requestedAfterEndpointId?: string,
): NetworkDirectoryView {
  const requested = requestedAfterEndpointId || null;
  const seen = new Set(current.endpoints.map(endpoint => endpoint.endpoint_id));
  const endpoints = current.endpoints.slice();
  for (const endpoint of page.endpoints) {
    if (!seen.has(endpoint.endpoint_id)) {
      seen.add(endpoint.endpoint_id);
      endpoints.push(endpoint);
    }
  }

  const nextCursor = page.next_cursor || undefined;
  const cursorLoop = Boolean(nextCursor && (nextCursor === requested ||
    current.requestedAfterEndpointIds.includes(nextCursor)));
  return {
    endpoints,
    nextCursor: cursorLoop ? undefined : nextCursor,
    requestedAfterEndpointIds: [...current.requestedAfterEndpointIds, requested],
    cursorLoop: current.cursorLoop || cursorLoop,
  };
}
