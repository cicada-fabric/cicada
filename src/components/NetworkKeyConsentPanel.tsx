import React, {useEffect, useRef, useState} from 'react';
import {Alert, Pressable, StyleSheet, Text, TextInput, View} from 'react-native';
import type {
  ClientHubApi, ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus,
  NetworkKeyGrantRequest, NetworkKeyResponse, VerifiedNetworkManifest,
} from '../platform/clientHub';
import {
  endpointsInNetwork, explicitActiveNetwork, networkKeyConsentAllows,
  NETWORK_ENDPOINT_ENROLLMENT_LIMIT,
} from '../platform/networkTopology';
import type {NetworkTopologyRecord, NetworkTopologySnapshot} from '../platform/networkTopology';

interface Props {
  api: ClientHubApi;
  status: ClientHubStatus;
  topology: NetworkTopologySnapshot | null;
  publicCapabilities: ClientHubCapabilities | null;
  sessionCapabilities: ClientHubSessionCapabilities | null;
  onRefresh: () => Promise<void>;
}

const PAGE_SIZE = 12;
const MAX_PROOF_BASE64_LENGTH = 43_692; // 32 KiB canonical Owner proof, encoded as padded base64.
const text = (record: NetworkTopologyRecord, key: string): string =>
  typeof record[key] === 'string' ? record[key] as string : '';
const positive = (record: NetworkTopologyRecord, key: string): boolean =>
  typeof record[key] === 'number' && Number.isSafeInteger(record[key]) && (record[key] as number) > 0;
const object = (value: unknown): value is NetworkTopologyRecord =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const scopeKey = (status: ClientHubStatus): string => JSON.stringify([
  status.profileId, status.selectionGeneration, status.hubId, status.ownerId,
  status.deviceId, status.sessionEpoch, status.activeNetworkId,
]);

function safeFailure(error: unknown): string {
  const code = object(error) && typeof error.code === 'string' ? error.code : '';
  switch (code) {
    case 'STILL_PROCESSING': return 'Hub 仍在处理原请求；保留同一密文，先完成安全恢复。';
    case 'OUTCOME_UNCERTAIN': return '原操作结果不确定；请恢复原请求，再读取此 Network 的权威授权状态。';
    case 'RECOVERY_UNAVAILABLE': return 'Hub 无法恢复原请求；请保留 pending 与计数并进行权威状态对账。';
    case 'PENDING_RECOVERY_REQUIRED': return '请先恢复待处理的原始加密请求。';
    case 'HUB_PROFILE_SCOPE_CHANGED': return 'Hub 或 Network 已切换；请在当前会话重新核对。';
    case 'NETWORK_MANIFEST_STALE': return '候选或绑定已改变；请刷新后重新验证并取得 Owner 签名。';
    case 'NETWORK_OWNER_PROOF_INVALID': return 'Owner 签名、有效期或 manifest 绑定未通过核验。';
    default: return '操作未得到可验证结果；请刷新当前会话和 Hub 权威状态。';
  }
}

/** Only native-verified evidence is eligible for display or phone confirmation. */
function verifiedManifest(
  response: VerifiedNetworkManifest,
  networkId: string,
  endpoint: NetworkTopologyRecord,
  status: ClientHubStatus,
): NetworkTopologyRecord {
  const manifest = response.result;
  const candidate = manifest?.candidate;
  if (response.ok !== true || response.verified !== true || !object(manifest) || !object(candidate) ||
      manifest.version !== 1 || text(manifest, 'hub_id') !== status.hubId ||
      text(manifest, 'owner_id') !== status.ownerId || text(manifest, 'network_id') !== networkId ||
      text(manifest, 'endpoint_id') !== text(endpoint, 'endpoint_id') ||
      text(manifest, 'principal_id') !== text(endpoint, 'principal_id') ||
      text(manifest, 'node_id') !== text(endpoint, 'node_id') || !text(manifest, 'native_session_id') ||
      (text(endpoint, 'native_session_id') &&
        text(manifest, 'native_session_id') !== text(endpoint, 'native_session_id')) ||
      !/^[0-9a-f]{64}$/.test(text(manifest, 'native_session_digest')) ||
      !/^[0-9a-f]{64}$/.test(text(manifest, 'digest')) || !text(manifest, 'binding_id') ||
      !positive(manifest, 'binding_epoch') || !positive(manifest, 'membership_revision') ||
      !positive(manifest, 'endpoint_enrollment_revision') || !positive(candidate, 'version') ||
      !/^sha256:[0-9a-f]{64}$/.test(text(candidate, 'fingerprint')) ||
      !['network_id', 'endpoint_id', 'principal_id', 'owner_id', 'node_id', 'binding_id', 'binding_epoch']
        .every(key => candidate[key] === manifest[key])) {
    throw new Error('INVALID_NETWORK_VERIFIED_RESULT');
  }
  return manifest;
}

function currentGrant(response: NetworkKeyResponse, networkId: string, endpointId: string,
                      ownerId: string | undefined): NetworkTopologyRecord {
  const result = response.result;
  if (response.ok !== true || !object(result) || text(result, 'network_id') !== networkId ||
      text(result, 'endpoint_id') !== endpointId || text(result, 'owner_id') !== ownerId ||
      !['active', 'stale'].includes(text(result, 'state'))) throw new Error('INVALID_NETWORK_GRANT_RESULT');
  return result;
}

export function NetworkKeyConsentPanel({api, status, topology, publicCapabilities,
  sessionCapabilities, onRefresh}: Props): React.JSX.Element {
  const [endpointId, setEndpointId] = useState('');
  const [ownerKeyId, setOwnerKeyId] = useState('');
  const [proof, setProof] = useState('');
  const [page, setPage] = useState(0);
  const [manifestState, setManifestState] = useState<{scope: string; value: NetworkTopologyRecord} | null>(null);
  const [grantState, setGrantState] = useState<{scope: string; value: NetworkTopologyRecord} | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  const busyRef = useRef(false);
  const operationRef = useRef(0);
  const scope = scopeKey(status);
  const scopeRef = useRef(scope);
  scopeRef.current = scope;

  useEffect(() => {
    mounted.current = true;
    operationRef.current++;
    return () => { mounted.current = false; };
  }, []);
  useEffect(() => {
    operationRef.current++;
    busyRef.current = false;
    setBusy(false);
    setEndpointId(''); setOwnerKeyId(''); setProof(''); setPage(0);
    setManifestState(null); setGrantState(null); setMessage('');
  }, [scope]);

  const network = explicitActiveNetwork(topology, status.activeNetworkId);
  const endpoints = endpointsInNetwork(topology, status.activeNetworkId)
    .slice(0, NETWORK_ENDPOINT_ENROLLMENT_LIMIT);
  const matchingEndpoints = endpoints.filter(item => text(item, 'endpoint_id') === endpointId);
  const endpoint = matchingEndpoints.length === 1 ? matchingEndpoints[0] : undefined;
  const readReady = networkKeyConsentAllows(publicCapabilities, sessionCapabilities, status,
    api.networkKeyConsentReady, topology, 'network.key_status');
  const writeReady = networkKeyConsentAllows(publicCapabilities, sessionCapabilities, status,
    api.networkKeyConsentReady, topology);
  const manifest = manifestState?.scope === scope ? manifestState.value : null;
  const grant = grantState?.scope === scope ? grantState.value : null;
  const candidate = manifest && object(manifest.candidate) ? manifest.candidate : null;

  const begin = (): number | null => {
    if (busyRef.current) return null;
    busyRef.current = true; setBusy(true);
    return ++operationRef.current;
  };
  const stillCurrent = (operation: number): boolean => mounted.current && scopeRef.current === scope &&
    operationRef.current === operation;
  const finish = (operation: number) => {
    if (stillCurrent(operation)) { busyRef.current = false; setBusy(false); }
  };
  const refresh = async (operation: number) => {
    if (stillCurrent(operation)) await onRefresh().catch(() => undefined);
  };
  const checkScope = async (operation: number, writing: boolean) => {
    const latest = await api.getStatus();
    if (!stillCurrent(operation) || scopeKey(latest) !== scope ||
        latest.profileId !== api.scope.profileId || latest.selectionGeneration !== api.scope.selectionGeneration ||
        !networkKeyConsentAllows(publicCapabilities, sessionCapabilities, latest,
          api.networkKeyConsentReady, topology, writing ? 'network.key_grant' : 'network.key_status')) {
      throw Object.assign(new Error('Scope changed'), {code: 'HUB_PROFILE_SCOPE_CHANGED'});
    }
  };
  const reportFailure = (operation: number, error: unknown) => {
    if (stillCurrent(operation)) setMessage(safeFailure(error));
  };

  const preview = async () => {
    if (!readReady || !network || !endpoint || !ownerKeyId.trim()) return;
    const operation = begin(); if (operation === null) return;
    setManifestState(null); setGrantState(null); setProof('');
    try {
      await checkScope(operation, false);
      const response = await api.previewNetworkKey({networkId: network.network_id, endpointId,
        ownerKeyId: ownerKeyId.trim()});
      const verified = verifiedManifest(response, network.network_id, endpoint, status);
      if (stillCurrent(operation)) {
        setManifestState({scope, value: verified});
        setMessage('完整 Endpoint 自签证明、公钥、原生绑定及 manifest 已在设备上验证。请由独立 Owner 签名器签署此摘要。');
      }
    } catch (error) { reportFailure(operation, error); }
    finally { await refresh(operation); finish(operation); }
  };

  const readStatus = async () => {
    if (!readReady || !network || !endpoint) return;
    const operation = begin(); if (operation === null) return;
    setGrantState(null);
    try {
      await checkScope(operation, false);
      const response = await api.networkKeyStatus({networkId: network.network_id, endpointId});
      const result = currentGrant(response, network.network_id, endpointId, status.ownerId);
      if (stillCurrent(operation)) {
        setGrantState({scope, value: result});
        setMessage(result.state === 'active' ? '已读取 Hub 的当前有效公钥授权。' :
          '当前授权已失效；请重新核对绑定并取得 Owner 对新 manifest 的签名。');
      }
    } catch (error) { reportFailure(operation, error); }
    finally { await refresh(operation); finish(operation); }
  };

  const reviewProof = async () => {
    if (!writeReady || !network || !endpoint || !manifest || !ownerKeyId.trim() || !proof.trim()) return;
    const operation = begin(); if (operation === null) return;
    const request: NetworkKeyGrantRequest = {networkId: network.network_id, endpointId,
      ownerKeyId: ownerKeyId.trim(), expectedDigest: text(manifest, 'digest'), signedProofBase64: proof.trim()};
    try {
      await checkScope(operation, true);
      const response = await api.previewNetworkKeyGrant(request);
      const reviewed = verifiedManifest(response, network.network_id, endpoint, status);
      if (!stillCurrent(operation)) return;
      if (text(reviewed, 'digest') !== request.expectedDigest) {
        throw Object.assign(new Error('Manifest changed'), {code: 'NETWORK_MANIFEST_STALE'});
      }
      const reviewedCandidate = reviewed.candidate as NetworkTopologyRecord;
      let decided = false;
      const cancel = () => { if (!decided) { decided = true; finish(operation); } };
      Alert.alert('明确授权 Network Endpoint 公钥',
        `Hub：${text(reviewed, 'hub_id')}\nNetwork：${network.network_id}\nOwner：${text(reviewed, 'owner_id')}\nOwner key：${request.ownerKeyId}\nEndpoint：${endpointId}\nPrincipal：${text(reviewed, 'principal_id')}\nNode：${text(reviewed, 'node_id')}\n原生 Session：${text(reviewed, 'native_session_id')}\nBinding：${text(reviewed, 'binding_id')} / epoch ${reviewed.binding_epoch}\nMembership / Enrollment：${reviewed.membership_revision} / ${reviewed.endpoint_enrollment_revision}\n公钥指纹：${text(reviewedCandidate, 'fingerprint')}\nManifest：${request.expectedDigest}\n\n外部 Owner 签名和有效期已核对；提交前设备将再次核对当前 manifest。`, [
          {text: '取消', style: 'cancel', onPress: cancel},
          {text: '批准并提交', onPress: async () => {
            if (decided) return;
            decided = true;
            let accepted = false;
            try {
              await checkScope(operation, true);
              const responseGrant = await api.grantNetworkKey(request);
              currentGrant(responseGrant, network.network_id, endpointId, status.ownerId);
              accepted = true;
              if (!stillCurrent(operation)) return;
              setProof(''); setManifestState(null);
              const responseStatus = await api.networkKeyStatus({networkId: network.network_id, endpointId});
              const result = currentGrant(responseStatus, network.network_id, endpointId, status.ownerId);
              if (stillCurrent(operation)) {
                setGrantState({scope, value: result});
                setMessage(result.state === 'active' ? 'Owner 授权已被 Hub 接受；当前状态 active。' :
                  'Hub 已接受授权，但当前绑定已变为 stale；请重新核对。');
              }
            } catch (error) {
              if (stillCurrent(operation)) {
                setManifestState(null);
                setMessage(accepted ? 'Hub 已确认接受授权，但状态读取未完成；请刷新权威授权状态。' : safeFailure(error));
              }
            } finally { await refresh(operation); finish(operation); }
          }},
        ], {cancelable: true, onDismiss: cancel});
    } catch (error) { reportFailure(operation, error); await refresh(operation); finish(operation); }
  };

  return <View style={styles.card}>
    <Text style={styles.title}>Network 公钥授权</Text>
    <Text style={styles.description}>独立 Owner 签名与手机确认分别生效。手机不保存 Owner 私钥，也不代 Node 发布候选或发送消息。</Text>
    {!readReady ? <Text style={styles.notice}>请先选择 ACTIVE Network，并建立获准的 v1.4 加密会话。原生验签或授权未就绪时操作关闭。</Text> : <>
      <Text style={styles.label}>{network?.name} · {network?.network_id}</Text>
      {(topology?.networks_truncated || topology?.network_endpoints_truncated) &&
        <Text style={styles.notice}>Hub 拓扑是有界投影，当前列表不完整；缺失项不表示不存在。</Text>}
      <Text style={styles.description}>选择当前 Network 中的本人 Endpoint</Text>
      {endpoints.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((item, index) =>
        <Pressable key={`${text(item, 'endpoint_id')}/${index}`} disabled={busy}
          accessibilityRole="button" accessibilityState={{disabled: busy, selected: text(item, 'endpoint_id') === endpointId}}
          style={[styles.endpoint, text(item, 'endpoint_id') === endpointId && styles.selected]}
          onPress={() => {
            setEndpointId(text(item, 'endpoint_id')); setManifestState(null); setGrantState(null); setProof(''); setMessage('');
          }}>
          <Text style={styles.label}>{text(item, 'name') || text(item, 'endpoint_id')}</Text>
          <Text style={styles.small}>{text(item, 'endpoint_id')}</Text>
        </Pressable>)}
      {endpoints.length === 0 && <Text style={styles.small}>当前投影中没有可选 Endpoint；Node 需显式登记并发布自己的 Network 候选。</Text>}
      {endpoints.length > PAGE_SIZE && <View style={styles.row}>
        <Action title="上一页" disabled={busy || page === 0} onPress={() => setPage(value => value - 1)} />
        <Text style={styles.small}>{page + 1} / {Math.ceil(endpoints.length / PAGE_SIZE)}</Text>
        <Action title="下一页" disabled={busy || (page + 1) * PAGE_SIZE >= endpoints.length} onPress={() => setPage(value => value + 1)} />
      </View>}
      <TextInput style={styles.input} value={ownerKeyId} editable={!busy} autoCapitalize="none" autoCorrect={false}
        placeholder="独立 Owner 公钥 ID" accessibilityLabel="Network 授权 Owner 公钥 ID" onChangeText={value => {
          setOwnerKeyId(value); setManifestState(null); setProof('');
        }} />
      <Action title="读取并验证候选" disabled={busy || !endpoint || !ownerKeyId.trim()} onPress={preview} />
      <Action title="刷新当前授权状态" disabled={busy || !endpoint} onPress={readStatus} secondary />
      {grant && <Text style={styles.small}>Hub 当前授权：{text(grant, 'state')} · {text(grant, 'accepted_at')}</Text>}
      {manifest && candidate && <View style={styles.evidence}>
        <Text style={styles.label}>设备已独立验证完整证明</Text>
        <Text selectable style={styles.small}>Endpoint：{text(manifest, 'endpoint_id')}{'\n'}Principal：{text(manifest, 'principal_id')}{'\n'}Node：{text(manifest, 'node_id')}{'\n'}原生 Session：{text(manifest, 'native_session_id')}{'\n'}Binding：{text(manifest, 'binding_id')} / epoch {String(manifest.binding_epoch)}{'\n'}Membership / Enrollment：{String(manifest.membership_revision)} / {String(manifest.endpoint_enrollment_revision)}{'\n'}候选版本：{String(candidate.version)}{'\n'}公钥指纹：{text(candidate, 'fingerprint')}{'\n'}Manifest：{text(manifest, 'digest')}</Text>
        <Text style={styles.description}>将当前 Hub、Network、Endpoint、Owner 与此 manifest 摘要交给独立签名器。返回的公开签名证明仅保留在当前页面内存中。</Text>
        <TextInput style={[styles.input, styles.proof]} value={proof} editable={!busy} multiline
          maxLength={MAX_PROOF_BASE64_LENGTH} autoCapitalize="none" autoCorrect={false}
          placeholder="外部 Owner 签名证明（base64）" accessibilityLabel="Network Owner 签名证明"
          onChangeText={setProof} />
        <Action title="验证签名并明确批准" disabled={busy || !writeReady || !endpoint || !ownerKeyId.trim() || !proof.trim()} onPress={reviewProof} />
      </View>}
      {status.uncertainNeedsReconciliation && <Text style={styles.notice}>存在待核实的业务结果；新授权关闭，可先读取当前授权状态。</Text>}
      {status.networkGrantReconciliationRequired && <Text style={styles.notice}>原 Network 授权结果仍待专门核实。普通状态刷新不会解除授权锁；可读取授权状态，新授权保持关闭。</Text>}
    </>}
    {!!message && <Text accessibilityLiveRegion="polite" style={styles.description}>{message}</Text>}
    {busy && <Text style={styles.small}>正在核对当前安全会话…</Text>}
  </View>;
}

function Action({title, disabled, onPress, secondary = false}: {
  title: string; disabled: boolean; onPress: () => void; secondary?: boolean;
}): React.JSX.Element {
  return <Pressable accessibilityRole="button" accessibilityState={{disabled}} disabled={disabled}
    onPress={onPress} style={[styles.button, secondary && styles.secondary, disabled && styles.disabled]}>
    <Text style={[styles.buttonText, secondary && styles.secondaryText]}>{title}</Text>
  </Pressable>;
}

const styles = StyleSheet.create({
  card: {borderRadius: 20, borderWidth: 1, borderColor: '#E1E7E3', backgroundColor: '#FFFFFF', padding: 18, marginBottom: 10},
  title: {fontSize: 17, fontWeight: '700', color: '#1A2D2B'},
  label: {fontSize: 13, fontWeight: '600', color: '#1A2D2B', marginTop: 6},
  description: {fontSize: 13, lineHeight: 19, color: '#697974', marginTop: 8},
  small: {fontSize: 12, lineHeight: 18, color: '#697974', marginTop: 6},
  notice: {fontSize: 12, lineHeight: 18, color: '#AE7025', backgroundColor: '#FFF5E3', padding: 12, borderRadius: 12, marginTop: 10},
  endpoint: {padding: 10, borderRadius: 12, borderWidth: 1, borderColor: '#E1E7E3', marginTop: 8},
  selected: {backgroundColor: '#E8F3EF', borderColor: '#186A63'},
  input: {borderWidth: 1, borderColor: '#E1E7E3', borderRadius: 12, padding: 12, marginTop: 12, color: '#1A2D2B', fontSize: 13},
  proof: {minHeight: 88, maxHeight: 150, textAlignVertical: 'top'},
  evidence: {marginTop: 12, paddingTop: 12, borderTopWidth: 1, borderTopColor: '#E1E7E3'},
  button: {paddingVertical: 12, paddingHorizontal: 14, backgroundColor: '#186A63', borderRadius: 12, marginTop: 10},
  buttonText: {color: '#FFFFFF', fontSize: 13, fontWeight: '600', textAlign: 'center'},
  secondary: {backgroundColor: '#F7F8F6'},
  secondaryText: {color: '#186A63'},
  disabled: {opacity: 0.4},
  row: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 8},
});
