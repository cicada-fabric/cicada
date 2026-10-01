import React, {useEffect, useRef, useState} from 'react';
import {Alert, AppState, Pressable, StyleSheet, Text, TextInput, View} from 'react-native';
import type {
  ClientHubApi, ClientHubCapabilities, ClientHubSessionCapabilities, ClientHubStatus,
} from '../platform/clientHub';
import {
  NodePairingLifecycle, nodeControlKeyBindingFromConfirmRpc, nodeControlKeyCandidateFromRpc,
  nodeDeviceBindingFromList, nodePairingOperationAllowed,
  nodePairingScopeKey, sameNodeControlKeyCandidate,
} from '../platform/nodePairing';
import type {
  NodeControlKeyCandidate, NodePairingOperation, NodePairingRequestToken,
} from '../platform/nodePairing';

interface Props {
  api: Pick<ClientHubApi, 'getStatus' | 'rpc' | 'scope'>;
  status: ClientHubStatus;
  publicCapabilities: ClientHubCapabilities | null;
  sessionCapabilities: ClientHubSessionCapabilities | null;
  onRefresh: () => Promise<unknown>;
}

interface ReviewState {
  scopeKey: string;
  candidate: NodeControlKeyCandidate;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function errorCode(error: unknown): string {
  if (!isRecord(error)) return '';
  if (typeof error.errorCode === 'string') return error.errorCode;
  if (typeof error.code === 'string') return error.code;
  return '';
}

function failureMessage(error: unknown): string {
  switch (errorCode(error)) {
    case 'PENDING_RECOVERY_REQUIRED':
    case 'RECOVERY_UNAVAILABLE':
    case 'STILL_PROCESSING':
      return 'Hub 有原始加密请求待恢复；先完成恢复，再重新读取 Node 候选。';
    case 'OUTCOME_UNCERTAIN':
      return '确认结果不确定；请先恢复原请求并重读已登记 Node 列表，不要重试旧候选。';
    case 'HUB_PROFILE_SCOPE_CHANGED':
    case 'NODE_PAIRING_STALE':
      return 'Hub、Owner、设备或权限范围已变化；候选已清除，请重新核对。';
    case 'NODE_PAIRING_RESULT_INVALID':
      return 'Node 配对响应未通过当前身份与审批证据核对；请刷新 nodes.list 核实权威状态。';
    default:
      return '操作未得到可验证结果；请重新读取当前 Hub 状态后再决定。';
  }
}

function responseFromRpc(value: unknown): {ok: boolean; result?: unknown; errorCode?: string} {
  if (!isRecord(value) || typeof value.ok !== 'boolean') {
    throw Object.assign(new Error('invalid encrypted RPC envelope'), {code: 'NODE_PAIRING_RESULT_INVALID'});
  }
  return {
    ok: value.ok,
    result: value.result,
    errorCode: typeof value.errorCode === 'string' ? value.errorCode : undefined,
  };
}

function reviewText(candidate: NodeControlKeyCandidate): string {
  return [
    `请求 ID：${candidate.request_id}`,
    `状态：${candidate.state} · 模式：${candidate.mode} · 候选版本：${candidate.version}`,
    `候选摘要：${candidate.candidate_digest}`,
    `到期：${candidate.expires_at}`,
    `Node：${candidate.node_name} · ${candidate.node_id}`,
    `Node key ID：${candidate.node_key_id}`,
    `Node key fingerprint：${candidate.node_key_fingerprint}`,
    `Node key epoch：${candidate.node_key_epoch}`,
    `Hub Node-Control key ID：${candidate.hub_node_control_key_id}`,
    `Hub Node-Control key version：${candidate.hub_node_control_key_version}`,
    `Hub Node-Control fingerprint：${candidate.hub_node_control_fingerprint}`,
    ...(candidate.binding_id ? [`目标现有绑定：${candidate.binding_id} · v${candidate.binding_version}`] : []),
  ].join('\n');
}

function trustedCheck(label: string, checked: boolean, disabled: boolean, onPress: () => void): React.JSX.Element {
  return <Pressable accessibilityRole="checkbox" accessibilityState={{checked, disabled}}
    disabled={disabled} onPress={onPress} style={styles.checkRow}>
    <View style={[styles.checkbox, checked && styles.checkboxChecked]}>
      {checked && <Text style={styles.checkmark}>✓</Text>}
    </View>
    <Text style={styles.checkText}>{label}</Text>
  </Pressable>;
}

/** One-time Node code and public key metadata remain in component memory only. */
export function NodePairingPanel({api, status, publicCapabilities, sessionCapabilities,
  onRefresh}: Props): React.JSX.Element {
  const [expanded, setExpanded] = useState(false);
  const [code, setCode] = useState('');
  const [review, setReview] = useState<ReviewState | null>(null);
  const [nodeTrusted, setNodeTrusted] = useState(false);
  const [hubNodeControlTrusted, setHubNodeControlTrusted] = useState(false);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const lifecycle = useRef(new NodePairingLifecycle());
  const mounted = useRef(true);
  const foreground = useRef(AppState.currentState === 'active');
  const busyRef = useRef(false);
  const busyGeneration = useRef<number | null>(null);
  const codeRef = useRef(code);
  codeRef.current = code;
  const scopeKey = nodePairingScopeKey(status, publicCapabilities, sessionCapabilities, api.scope);
  const scopeKeyRef = useRef(scopeKey);
  scopeKeyRef.current = scopeKey;

  const clearReview = (clearCode: boolean, nextMessage = '') => {
    lifecycle.current.invalidate();
    setReview(null);
    setNodeTrusted(false);
    setHubNodeControlTrusted(false);
    setMessage(nextMessage);
    if (clearCode) {
      codeRef.current = '';
      setCode('');
    }
  };

  useEffect(() => {
    mounted.current = true;
    const pairingLifecycle = lifecycle.current;
    return () => {
      mounted.current = false;
      pairingLifecycle.invalidate();
    };
  }, []);

  useEffect(() => {
    lifecycle.current.invalidate();
    setReview(null);
    setNodeTrusted(false);
    setHubNodeControlTrusted(false);
    setMessage('');
    codeRef.current = '';
    setCode('');
  // Scope deliberately includes profile selection, selected Network, caps, and all session fences.
  }, [scopeKey]);

  useEffect(() => {
    const listener = AppState.addEventListener('change', next => {
      const active = next === 'active';
      foreground.current = active;
      clearReview(true, active ? '' : '应用进入后台后，Node code 与候选已清除。');
      if (busyGeneration.current === null) {
        busyRef.current = false;
        setBusy(false);
      }
    });
    return () => listener.remove();
  }, []);

  const visibleCandidate = review?.scopeKey === scopeKey ? review.candidate : null;
  const previewAllowed = nodePairingOperationAllowed(status, publicCapabilities,
    sessionCapabilities, api.scope, 'nodes.preview');
  const confirmAllowed = nodePairingOperationAllowed(status, publicCapabilities,
    sessionCapabilities, api.scope, 'nodes.confirm');

  const begin = (): NodePairingRequestToken | null => {
    if (busyRef.current || !foreground.current) return null;
    busyRef.current = true;
    setBusy(true);
    const token = lifecycle.current.capture(scopeKeyRef.current);
    busyGeneration.current = token.generation;
    return token;
  };
  const current = (token: NodePairingRequestToken, requestedCode: string): boolean =>
    mounted.current && foreground.current &&
    lifecycle.current.isCurrent(token, scopeKeyRef.current) && codeRef.current.trim() === requestedCode;
  const finish = (token: NodePairingRequestToken) => {
    if (busyGeneration.current !== token.generation) return;
    busyGeneration.current = null;
    busyRef.current = false;
    if (mounted.current) setBusy(false);
  };
  const checkCurrentStatus = async (
    token: NodePairingRequestToken,
    requestedCode: string,
    operation: NodePairingOperation,
  ): Promise<ClientHubStatus> => {
    const latest = await api.getStatus();
    if (!current(token, requestedCode) ||
        nodePairingScopeKey(latest, publicCapabilities, sessionCapabilities, api.scope) !== token.scopeKey ||
        !nodePairingOperationAllowed(latest, publicCapabilities, sessionCapabilities, api.scope, operation)) {
      throw Object.assign(new Error('pairing scope changed'), {code: 'HUB_PROFILE_SCOPE_CHANGED'});
    }
    return latest;
  };
  const currentAfterConfirmation = async (token: NodePairingRequestToken): Promise<ClientHubStatus | null> => {
    if (!mounted.current || !foreground.current ||
        !lifecycle.current.isCurrent(token, scopeKeyRef.current)) return null;
    const latest = await api.getStatus();
    if (!mounted.current || !foreground.current ||
        !lifecycle.current.isCurrent(token, scopeKeyRef.current) ||
        nodePairingScopeKey(latest, publicCapabilities, sessionCapabilities, api.scope) !== token.scopeKey) return null;
    return latest;
  };

  const preview = async () => {
    const requestedCode = codeRef.current.trim();
    if (!requestedCode || !previewAllowed) return;
    const token = begin();
    if (!token) return;
    setReview(null);
    setNodeTrusted(false);
    setHubNodeControlTrusted(false);
    setMessage('');
    try {
      const latest = await checkCurrentStatus(token, requestedCode, 'nodes.preview');
      const envelope = responseFromRpc(await api.rpc({operation: 'nodes.preview',
        body: {user_code: requestedCode}}));
      if (!envelope.ok) throw Object.assign(new Error('preview refused'), {code: envelope.errorCode});
      const candidate = nodeControlKeyCandidateFromRpc(envelope.result, latest.hubId || '');
      if (!candidate) throw Object.assign(new Error('invalid candidate'), {code: 'NODE_PAIRING_RESULT_INVALID'});
      await checkCurrentStatus(token, requestedCode, 'nodes.preview');
      if (current(token, requestedCode)) {
        setReview({scopeKey: token.scopeKey, candidate});
        setMessage('候选来自当前 Hub 的加密 nodes.preview。请通过独立可信渠道分别核对 Node key 与 Hub Node-Control key，再提交最终确认。');
      }
    } catch (error) {
      if (current(token, requestedCode)) {
        setReview(null);
        setNodeTrusted(false);
        setHubNodeControlTrusted(false);
        setMessage(failureMessage(error));
      }
    } finally { finish(token); }
  };

  const confirm = async () => {
    const requestedCode = codeRef.current.trim();
    const reviewed = visibleCandidate;
    if (!requestedCode || !reviewed || !previewAllowed || !confirmAllowed ||
        !nodeTrusted || !hubNodeControlTrusted) return;
    const token = begin();
    if (!token) return;
    let waitingForAlert = false;
    try {
      await checkCurrentStatus(token, requestedCode, 'nodes.confirm');
      const freshEnvelope = responseFromRpc(await api.rpc({operation: 'nodes.preview',
        body: {user_code: requestedCode}}));
      if (!freshEnvelope.ok) throw Object.assign(new Error('fresh preview refused'), {code: freshEnvelope.errorCode});
      const freshStatus = await checkCurrentStatus(token, requestedCode, 'nodes.confirm');
      const fresh = nodeControlKeyCandidateFromRpc(freshEnvelope.result, freshStatus.hubId || '');
      if (!fresh) throw Object.assign(new Error('invalid refreshed candidate'), {code: 'NODE_PAIRING_RESULT_INVALID'});
      if (!current(token, requestedCode)) return;
      if (!sameNodeControlKeyCandidate(reviewed, fresh)) {
        setReview({scopeKey: token.scopeKey, candidate: fresh});
        setNodeTrusted(false);
        setHubNodeControlTrusted(false);
        setMessage('Node 或 Hub Node-Control 候选已变化；旧确认已取消。请重新核对完整信息并分别勾选可信渠道确认。');
        return;
      }

      waitingForAlert = true;
      let settled = false;
      const cancel = () => {
        if (settled) return;
        settled = true;
        finish(token);
      };
      const approve = () => {
        if (settled) return;
        settled = true;
        void (async () => {
          try {
            const confirmStatus = await checkCurrentStatus(token, requestedCode, 'nodes.confirm');
            if (!current(token, requestedCode)) return;
            if (Date.parse(fresh.expires_at) <= Date.now()) {
              setReview(null);
              setNodeTrusted(false);
              setHubNodeControlTrusted(false);
              setMessage('Node 候选已过期；未发送确认。请重新读取候选并重新核对。');
              return;
            }
            const envelope = responseFromRpc(await api.rpc({operation: 'nodes.confirm', body: {
              user_code: requestedCode,
              candidate_digest: fresh.candidate_digest,
              candidate_version: fresh.version,
            }}));
            if (!envelope.ok) throw Object.assign(new Error('confirmation refused'), {code: envelope.errorCode});
            if (!current(token, requestedCode)) return;

            const confirmedBinding = nodeControlKeyBindingFromConfirmRpc(envelope.result, fresh, confirmStatus);

            lifecycle.current.invalidate();
            codeRef.current = '';
            setCode('');
            setReview(null);
            setNodeTrusted(false);
            setHubNodeControlTrusted(false);
            const refreshScope = scopeKeyRef.current;
            const refreshToken = lifecycle.current.capture(refreshScope);
            if (!confirmedBinding) {
              setMessage('Hub 已确认接收加密请求，但返回的 Node-Control 绑定证据无法与本次审阅候选对应。正在刷新 nodes.list；不要重试旧 code。');
            } else {
              setMessage('已核对 nodes.confirm 的公开 Node-Control 绑定证据，正在读取 nodes.list 核对同一 Owner 绑定。');
            }
            try {
              const listValue = await onRefresh();
              const latest = await currentAfterConfirmation(refreshToken);
              if (!latest) return;
              if (!confirmedBinding) {
                setMessage('已刷新 nodes.list，但确认响应证据未通过审阅候选核对；请在 Hub 核实当前绑定，不要重试旧 code。');
              } else if (nodeDeviceBindingFromList(listValue, confirmedBinding, latest)) {
                setMessage('已核对 nodes.confirm 的 Node-Control 绑定证据，并在 nodes.list 找到同一 ACTIVE/authorized 绑定。Node 在线状态仍由其心跳报告。');
              } else {
                setMessage('确认响应的公开绑定证据已核对；nodes.list 尚未找到同一 ACTIVE/authorized 绑定版本。请刷新 Hub 状态，不要重试旧候选。');
              }
            } catch {
              if (mounted.current && foreground.current && lifecycle.current.isCurrent(refreshToken, scopeKeyRef.current)) {
                setMessage(confirmedBinding ?
                  '已核对确认响应的公开绑定证据，但 nodes.list 刷新失败。请刷新权威状态；不要重试旧候选。' :
                  'Hub 已确认接收加密请求，但绑定证据无法核对且 nodes.list 刷新失败。请刷新权威状态；不要重试旧 code。');
              }
            }
          } catch (error) {
            if (current(token, requestedCode)) {
              setReview(null);
              setNodeTrusted(false);
              setHubNodeControlTrusted(false);
              setMessage(failureMessage(error));
              try { await onRefresh(); } catch { /* Keep the original error message. */ }
            }
          } finally { finish(token); }
        })();
      };
      Alert.alert('核对并确认 Node-Control 密钥',
        `Client-Control Hub 固定身份：${status.hubId}\nHub Node-Control 密钥是独立身份，不能由手机固定的 Client-Control Hub 身份代替。\n\n${reviewText(fresh)}\n\n该操作仅确认此 Node-Control key 候选，不代表 Node 已在线。`, [
          {text: '取消', style: 'cancel', onPress: cancel},
          {text: '确认此候选', style: 'default', onPress: approve},
        ], {cancelable: true, onDismiss: cancel});
    } catch (error) {
      if (current(token, requestedCode)) {
        setReview(null);
        setNodeTrusted(false);
        setHubNodeControlTrusted(false);
        setMessage(failureMessage(error));
      }
    } finally {
      if (!waitingForAlert) finish(token);
    }
  };

  const onCodeChange = (value: string) => {
    codeRef.current = value;
    setCode(value);
    clearReview(false);
  };
  const allowedNow = previewAllowed && confirmAllowed;

  return <View style={styles.card}>
    <Pressable style={styles.heading} accessibilityRole="button"
      accessibilityState={{expanded}} onPress={() => setExpanded(value => !value)}>
      <View style={styles.headingText}>
        <Text style={styles.title}>Node 密钥绑定</Text>
        <Text style={styles.small}>加密候选预览 · 两个独立可信渠道核对 · 最终确认</Text>
      </View>
      <Text style={styles.toggle}>{expanded ? '收起' : '展开'}</Text>
    </Pressable>
    {expanded && <>
      <Text style={styles.description}>
        Client-Control Hub 固定 ID：{status.hubId || '未固定'}。下方 Hub Node-Control 公钥是另一套身份；固定 Client-Control Hub 不代表已经信任该 Node-Control 公钥。Node Principal ID 与 Owner Human ID 是不同身份，设备授权不会替代 Node key 信任。Node bearer 不会发送给手机或 Hub RPC。
      </Text>
      <TextInput style={styles.input} value={code} onChangeText={onCodeChange}
        placeholder="ABCD-EFGH-JKLM" autoCapitalize="characters" autoCorrect={false}
        secureTextEntry maxLength={64} accessibilityLabel="Node 一次性 user code" />
      <Action title={busy ? '正在读取候选…' : '读取 Node 候选'}
        disabled={busy || !foreground.current || !previewAllowed || !code.trim()}
        onPress={() => { void preview(); }} />

      {!allowedNow && <Text style={styles.notice}>
        当前固定 Hub、OwnerDeviceGrant、加密 session.capabilities、本地操作策略或恢复状态未允许 Node 操作。先恢复/刷新当前会话。
      </Text>}
      {visibleCandidate && <View style={styles.evidence}>
        <Text style={styles.sectionTitle}>加密 Node-Control 候选 · {visibleCandidate.mode}</Text>
        <Text style={styles.small}>Client-Control Hub ID：{status.hubId}</Text>
        <Text style={styles.small}>Node ID：{visibleCandidate.node_id} · {visibleCandidate.node_name}</Text>
        <Text selectable style={styles.small}>Node key ID：{visibleCandidate.node_key_id}</Text>
        <Text selectable style={styles.fingerprint}>Node key fingerprint：{visibleCandidate.node_key_fingerprint}</Text>
        <Text style={styles.small}>Node key epoch：{visibleCandidate.node_key_epoch}</Text>
        <Text selectable style={styles.small}>Hub Node-Control key ID：{visibleCandidate.hub_node_control_key_id}</Text>
        <Text style={styles.small}>Hub Node-Control key version：{visibleCandidate.hub_node_control_key_version}</Text>
        <Text selectable style={styles.fingerprint}>Hub Node-Control fingerprint：{visibleCandidate.hub_node_control_fingerprint}</Text>
        <Text selectable style={styles.fingerprint}>候选 digest：{visibleCandidate.candidate_digest}</Text>
        <Text style={styles.small}>候选 version：{visibleCandidate.version} · 状态：{visibleCandidate.state} · 到期：{visibleCandidate.expires_at}</Text>
        {visibleCandidate.binding_id && <Text style={styles.small}>
          目标绑定：{visibleCandidate.binding_id} · version {visibleCandidate.binding_version}
        </Text>}
        {trustedCheck('我通过独立可信渠道核对了完整 Node key fingerprint。', nodeTrusted, busy,
          () => setNodeTrusted(value => !value))}
        {trustedCheck('我通过独立可信渠道核对了 Hub Node-Control key ID 与 fingerprint；这不是手机固定的 Client-Control Hub key。',
          hubNodeControlTrusted, busy, () => setHubNodeControlTrusted(value => !value))}
        <Text style={styles.notice}>
          此候选仅供密钥身份审阅。确认前会重新读取候选并核对 digest/version；确认后核对公开审批证据，并用同一 Owner 绑定 ID 与 nodes.list 对照。
        </Text>
        <Action title={busy ? '正在再次核对…' : '核对完整信息并确认'}
          disabled={busy || !foreground.current || !confirmAllowed || !nodeTrusted || !hubNodeControlTrusted}
          onPress={() => { void confirm(); }} />
      </View>}
      {!!message && <Text accessibilityLiveRegion="polite" style={styles.description}>{message}</Text>}
    </>}
  </View>;
}

function Action({title, disabled, onPress}: {
  title: string; disabled: boolean; onPress: () => void;
}): React.JSX.Element {
  return <Pressable accessibilityRole="button" accessibilityState={{disabled}}
    disabled={disabled} onPress={onPress} style={[styles.button, disabled && styles.disabled]}>
    <Text style={styles.buttonText}>{title}</Text>
  </Pressable>;
}

const styles = StyleSheet.create({
  card: {borderRadius: 20, borderWidth: 1, borderColor: '#E1E7E3', backgroundColor: '#FFFFFF', padding: 18, marginBottom: 10},
  heading: {flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 12},
  headingText: {flex: 1},
  title: {fontSize: 17, fontWeight: '700', color: '#1A2D2B'},
  toggle: {fontSize: 13, fontWeight: '600', color: '#186A63', paddingVertical: 8},
  description: {fontSize: 13, lineHeight: 19, color: '#697974', marginTop: 8},
  small: {fontSize: 12, lineHeight: 18, color: '#697974', marginTop: 6},
  fingerprint: {fontSize: 12, lineHeight: 18, color: '#354741', marginTop: 6},
  sectionTitle: {fontSize: 14, fontWeight: '700', color: '#1A2D2B'},
  input: {borderWidth: 1, borderColor: '#CBD6D0', backgroundColor: '#FFFFFF', borderRadius: 12,
    paddingHorizontal: 12, paddingVertical: 10, color: '#1A2D2B', marginTop: 12},
  button: {paddingVertical: 11, paddingHorizontal: 14, backgroundColor: '#186A63', borderRadius: 12, marginTop: 10},
  buttonText: {color: '#FFFFFF', fontSize: 13, fontWeight: '600', textAlign: 'center'},
  disabled: {opacity: 0.4},
  evidence: {marginTop: 12, paddingTop: 12, borderTopWidth: 1, borderTopColor: '#E1E7E3'},
  notice: {fontSize: 12, lineHeight: 18, color: '#AE7025', backgroundColor: '#FFF5E3', padding: 10, borderRadius: 12, marginTop: 10},
  checkRow: {flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 8, marginTop: 4},
  checkbox: {width: 20, height: 20, borderWidth: 1, borderColor: '#82918A', borderRadius: 5,
    alignItems: 'center', justifyContent: 'center'},
  checkboxChecked: {backgroundColor: '#186A63', borderColor: '#186A63'},
  checkmark: {color: '#FFFFFF', fontSize: 14, fontWeight: '700'},
  checkText: {flex: 1, color: '#354741', fontSize: 12, lineHeight: 18},
});
