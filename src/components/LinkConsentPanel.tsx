import React, {useEffect, useRef, useState} from 'react';
import {Alert, AppState, Pressable, Text, TextInput, View} from 'react-native';
import type {HubProfileScope} from '../platform/clientHub';
import type {LinkReviewPolicy} from '../platform/linkReviewPolicyStatus';
import {observeLinkConsentDiagnostic} from '../platform/linkConsentDiagnostics';
import {
  LinkConsentReviewLifecycle, linkConsentReviewFromNative, linkConsentUiScope,
  linkOwnerProofInputValid, linkKeyGrantReceiptFromNative, linkConsentPrepareStatus,
} from '../platform/linkConsentFlow';
import type {LinkConsentApi, LinkConsentKind, LinkConsentPrepareStage, LinkConsentReview} from '../platform/linkConsentFlow';

interface Props {
  api: LinkConsentApi;
  scope: HubProfileScope;
  linkId: string;
  linkVersion: number;
  listGeneration: number;
}

const noReviewPolicy: LinkReviewPolicy = {mode: 'NONE', reviewers: [], max_failovers: 0,
  reviewer_lease_seconds: 0, max_review_age_seconds: 0};

/** Hidden until the native consent implementation and fixed release are accepted. */
export function LinkConsentPanel(props: Props): React.JSX.Element | null {
  const [kind, setKind] = useState<LinkConsentKind>('KEY');
  const [metadata, setMetadata] = useState(false);
  const [reviewerEndpoint, setReviewerEndpoint] = useState('');
  const [reviewerGroup, setReviewerGroup] = useState('');
  const [ownerId, setOwnerId] = useState('');
  const [ownerPublicIdentity, setOwnerPublicIdentity] = useState('');
  const [expectedFingerprint, setExpectedFingerprint] = useState('');
  const [proof, setProof] = useState('');
  const [review, setReview] = useState<LinkConsentReview | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [prepareStage, setPrepareStage] = useState<LinkConsentPrepareStage | null>(null);
  const preparationActive = useRef(false);
  const lifecycle = useRef(new LinkConsentReviewLifecycle());
  const scope = linkConsentUiScope(props.scope, props.linkId, props.linkVersion, props.listGeneration);
  const latest = useRef({scope, api: props.api, foreground: AppState.currentState === 'active'});
  latest.current = {...latest.current, scope, api: props.api};

  useEffect(() => {
    const hadPreparationOrReview = preparationActive.current;
    if (hadPreparationOrReview) observeLinkConsentDiagnostic('REVIEW_INVALIDATED');
    preparationActive.current = false;
    lifecycle.current.invalidate();
    setReview(null);
    setProof('');
    setOwnerPublicIdentity('');
    setExpectedFingerprint('');
    setMessage('');
    setPrepareStage(hadPreparationOrReview ? 'REVIEW_INVALIDATED' : null);
    setBusy(false);
  }, [scope, kind, metadata, reviewerEndpoint, reviewerGroup]);

  useEffect(() => {
    const current = lifecycle.current;
    const subscription = AppState.addEventListener('change', state => {
      latest.current.foreground = state === 'active';
      if (state !== 'active') {
        const hadPreparationOrReview = preparationActive.current;
        if (hadPreparationOrReview) observeLinkConsentDiagnostic('REVIEW_INVALIDATED');
        preparationActive.current = false;
        current.invalidate();
        setReview(null);
        setProof('');
        setOwnerPublicIdentity('');
        setExpectedFingerprint('');
        setMessage('');
        setPrepareStage(hadPreparationOrReview ? 'REVIEW_INVALIDATED' : null);
        setBusy(false);
      }
    });
    return () => {
      subscription.remove();
      if (preparationActive.current) observeLinkConsentDiagnostic('REVIEW_INVALIDATED');
      current.invalidate();
    };
  }, []);

  if (!props.api.linkConsentReady) return null;

  const prepare = async () => {
    if (busy) return;
    if (!latest.current.foreground) {
      setPrepareStage('REVIEW_INVALIDATED');
      return;
    }
    if (preparationActive.current) observeLinkConsentDiagnostic('REVIEW_INVALIDATED');
    lifecycle.current.invalidate();
    const generation = lifecycle.current.capture();
    const captured = latest.current;
    preparationActive.current = true;
    setReview(null);
    setProof('');
    setBusy(true);
    setPrepareStage('PREPARING');
    setMessage('');
    const policy: LinkReviewPolicy = metadata ? {mode: 'METADATA', reviewers: [{
      endpoint_id: reviewerEndpoint.trim(), group_id: reviewerGroup.trim(),
    }], max_failovers: 0, reviewer_lease_seconds: 60, max_review_age_seconds: 600} : noReviewPolicy;
    const isCurrent = () => captured.scope === latest.current.scope &&
      generation === lifecycle.current.capture() && latest.current.foreground;
    try {
      let raw: unknown;
      try {
        raw = await captured.api.prepareLinkConsent({linkId: props.linkId,
          expectedLinkVersion: props.linkVersion, kind,
          ...(kind === 'REVIEW_POLICY' ? {policy} : {})});
      } catch {
        if (isCurrent()) {
          preparationActive.current = false;
          setPrepareStage('PREPARE_API_REJECTED');
        }
        return;
      }

      if (!isCurrent()) return;
      let parsed: LinkConsentReview | null;
      try {
        parsed = linkConsentReviewFromNative(raw, props.linkId, props.linkVersion);
      } catch {
        parsed = null;
      }
      if (!parsed) {
        if (isCurrent()) {
          preparationActive.current = false;
          setPrepareStage('DTO_REJECTED');
        }
        return;
      }
      if (isCurrent() && lifecycle.current.receive(generation, captured.scope,
        latest.current.scope, parsed)) {
        setReview(parsed);
        setPrepareStage('REVIEW_READY');
      }
    } finally {
      if (isCurrent()) setBusy(false);
    }
  };

  const pinOwner = () => {
    const captured = latest.current;
    const input = {ownerId: ownerId.trim(), publicIdentityJson: ownerPublicIdentity,
      expectedFingerprint: expectedFingerprint.trim(), confirmed: true as const};
    Alert.alert('固定此 Owner 公钥？',
      `${input.ownerId}\n${input.expectedFingerprint}\n请通过独立可信渠道核对完整指纹。`, [
        {text: '取消', style: 'cancel'},
        {text: '已独立核对', onPress: () => { (async () => {
          if (!latest.current.foreground || latest.current.scope !== captured.scope) return;
          setBusy(true);
          if (preparationActive.current) observeLinkConsentDiagnostic('REVIEW_INVALIDATED');
          preparationActive.current = false;
          lifecycle.current.invalidate();
          setReview(null);
          setProof('');
          setPrepareStage(null);
          try {
            await captured.api.confirmLinkOwnerPin(input);
            if (latest.current.scope === captured.scope) setMessage('公钥固定已保存。请重新读取 Link 证明。');
          } catch {
            if (latest.current.scope === captured.scope) setMessage('公钥固定未确认；请核对完整公钥和指纹。');
          } finally {
            if (latest.current.scope === captured.scope) {
              setOwnerPublicIdentity(''); setExpectedFingerprint(''); setBusy(false);
            }
          }
        })(); }},
      ]);
  };

  const confirm = () => {
    if (!review || busy || !linkOwnerProofInputValid(proof)) return;
    const captured = latest.current;
    const reviewed = review;
    const signedProofBase64 = proof;
    observeLinkConsentDiagnostic('CONFIRM_OPENED');
    Alert.alert('提交此授权？',
      `${reviewed.linkId} · v${reviewed.linkVersion} · ${reviewed.side}\n` +
      `${reviewed.sourceEndpointId} / ${reviewed.sourceGroupId} → ${reviewed.targetEndpointId} / ${reviewed.targetGroupId}\n` +
      `${reviewed.direction} · ${reviewed.actions.join(', ')}\n范围：${reviewed.dataScopes.join(', ')}\n` +
      `到期 ${reviewed.expiresAt}\n合约 ${reviewed.contractDigest}\n双方公钥及当前绑定将再次核验。`, [
        {text: '取消', style: 'cancel'},
        {text: '明确授权', onPress: () => { (async () => {
          observeLinkConsentDiagnostic('CALLBACK_ENTERED');
          if (!latest.current.foreground || latest.current.scope !== captured.scope) {
            observeLinkConsentDiagnostic('SCOPE_GUARD_REJECTED');
            return;
          }
          observeLinkConsentDiagnostic('SCOPE_GUARD_PASSED');
          const accepted = lifecycle.current.consume(captured.scope, reviewed.reviewId,
            reviewed.consentDigest, Date.now());
          if (!accepted) {
            preparationActive.current = false;
            observeLinkConsentDiagnostic('REVIEW_INVALIDATED');
            setReview(null); setProof(''); setPrepareStage('REVIEW_INVALIDATED');
            setMessage('确认已失效，请重新读取证明。'); return;
          }
          preparationActive.current = false;
          observeLinkConsentDiagnostic('REVIEW_CONSUMED');
          setReview(null); setProof(''); setBusy(true);
          setPrepareStage(null);
          try {
            observeLinkConsentDiagnostic('UI_SUBMIT_DISPATCHED');
            await captured.api.submitLinkConsent({reviewId: accepted.reviewId,
              consentDigest: accepted.consentDigest, signedProofBase64, confirmed: true});
            observeLinkConsentDiagnostic('UI_RESPONSE_RETURNED');
            if (latest.current.scope === captured.scope) {
              setMessage('授权响应已返回。请重读双方证明状态；单方接受不代表 Link 已可用。');
            } else observeLinkConsentDiagnostic('RESPONSE_SCOPE_CHANGED');
          } catch {
            observeLinkConsentDiagnostic('UI_SUBMIT_REJECTED');
            if (latest.current.scope === captured.scope) {
              setMessage('授权结果未确认。原请求由设备保留；请恢复原包，不要重复提交。');
            } else observeLinkConsentDiagnostic('RESPONSE_SCOPE_CHANGED');
          } finally { if (latest.current.scope === captured.scope) setBusy(false); }
        })(); }},
      ]);
  };

  const readGrants = async () => {
    const captured = latest.current;
    if (busy || !captured.foreground) return;
    if (preparationActive.current) observeLinkConsentDiagnostic('REVIEW_INVALIDATED');
    preparationActive.current = false;
    lifecycle.current.invalidate(); setReview(null); setProof(''); setBusy(true);
    setPrepareStage(null);
    try {
      const raw = await captured.api.readLinkKeyGrants({linkId: props.linkId, expectedLinkVersion: props.linkVersion});
      const receipt = linkKeyGrantReceiptFromNative(raw, props.linkId, props.linkVersion);
      if (!receipt) throw new Error('INVALID_NATIVE_LINK_STATUS');
      if (captured.scope === latest.current.scope && latest.current.foreground) {
        setMessage(`SOURCE ${receipt.sourceStatus.currentStatus} · TARGET ${receipt.targetStatus.currentStatus}。` +
          (receipt.bilateralVerified ? '双方当前证明已独立核验；这不代表消息已投递或模型已消费。' : '双方当前授权尚未核验完整。'));
      }
    } catch {
      if (captured.scope === latest.current.scope) setMessage('当前双方证明读取或核验失败，请核对公钥固定与绑定后重读。');
    } finally { if (captured.scope === latest.current.scope) setBusy(false); }
  };

  const recover = async () => {
    const captured = latest.current;
    if (busy || !captured.foreground) return;
    if (preparationActive.current) observeLinkConsentDiagnostic('REVIEW_INVALIDATED');
    preparationActive.current = false;
    lifecycle.current.invalidate(); setReview(null); setProof(''); setBusy(true);
    setPrepareStage(null);
    try {
      await captured.api.recoverLinkConsent();
      if (captured.scope === latest.current.scope) setMessage('原包恢复响应已返回。请重新读取当前双方证明状态。');
    } catch {
      if (captured.scope === latest.current.scope) setMessage('尚未获得确定结果。设备保留待恢复请求并阻止重复授权。');
    } finally { if (captured.scope === latest.current.scope) setBusy(false); }
  };

  const prepareStatus = prepareStage ? linkConsentPrepareStatus(prepareStage) : null;

  return <View style={styles.panel}>
    <Text style={styles.title}>Link 授权</Text>
    <View style={styles.row}>
      <Action label="Endpoint 密钥" disabled={busy} onPress={() => setKind('KEY')} />
      <Action label="审阅策略" disabled={busy} onPress={() => setKind('REVIEW_POLICY')} />
    </View>
    {kind === 'REVIEW_POLICY' && <>
      <Action label={metadata ? 'METADATA · 仅审阅元数据' : 'NONE · 不委托审阅'}
        disabled={busy} onPress={() => setMetadata(!metadata)} />
      {metadata && <>
        <Input value={reviewerEndpoint} onChange={setReviewerEndpoint} placeholder="Reviewer Endpoint" />
        <Input value={reviewerGroup} onChange={setReviewerGroup} placeholder="Reviewer Group" />
        <Text style={styles.note}>租约 60 秒 · 审阅最长有效 600 秒 · 不转移 Reviewer</Text>
      </>}
    </>}
    <Input value={ownerId} onChange={setOwnerId} placeholder="Owner ID" />
    <Input value={ownerPublicIdentity} onChange={setOwnerPublicIdentity} placeholder="Owner 完整公开身份 JSON" multiline />
    <Input value={expectedFingerprint} onChange={setExpectedFingerprint} placeholder="独立核对的 sha256 指纹" />
    <Action label="核对并固定 Owner 公钥" disabled={busy || !ownerId || !ownerPublicIdentity || !expectedFingerprint}
      onPress={pinOwner} />
    <Action label={busy ? '核验中…' : '读取当前证明'} disabled={busy} onPress={() => prepare()} />
    {prepareStatus && (prepareStage !== 'REVIEW_READY' || review) && <Text
      testID="link-consent-prepare-state"
      accessibilityLabel={prepareStatus.accessibilityLabel}
      accessibilityLiveRegion="polite" style={styles.note}>{prepareStatus.text}</Text>}
    {review && <View style={styles.review}>
      <Text style={styles.title}>{review.side} · Link v{review.linkVersion}</Text>
      <Text style={styles.note}>{review.sourceEndpointId} / {review.sourceGroupId} → {review.targetEndpointId} / {review.targetGroupId}</Text>
      <Text style={styles.note}>{review.direction} · {review.actions.join(', ')} · {review.dataScopes.join(', ')}</Text>
      <Text style={styles.note}>到期 {review.expiresAt}</Text>
      <Text selectable style={styles.note}>Source Endpoint {review.sourceKeyFingerprint}</Text>
      <Text selectable style={styles.note}>Target Endpoint {review.targetKeyFingerprint}</Text>
      <Text selectable style={styles.note}>Owner {review.ownerKeyFingerprint}</Text>
      <Text selectable style={styles.note}>Peer Owner {review.peerOwnerKeyFingerprint}</Text>
      <Text selectable style={styles.note}>Manifest {review.manifestDigest}</Text>
      {!!review.policyDigest && <Text selectable style={styles.note}>Policy {review.policyDigest} · v{review.policyVersion}</Text>}
      {review.currentPolicyStatus && <Text style={styles.note}>
        当前策略 v{review.currentPolicyStatus.policyVersion} · SOURCE {review.currentPolicyStatus.sourceStatus} · TARGET {review.currentPolicyStatus.targetStatus}
        {review.currentPolicyStatus.bilateralVerified ? ' · 双方当前证明已核验' : ' · 尚未核验双方当前授权'}
      </Text>}
      {review.qualifications.map(q => <Text key={q.endpointId} style={styles.note}>
        {q.endpointId} / {q.groupId} · binding {q.bindingId} / {q.bindingEpoch} · 到期 {q.leaseExpiresAt}
      </Text>)}
      <Text style={styles.note}>请在外部 Owner 签名器中签署以下请求；手机只接收签名证明。</Text>
      <Text selectable style={styles.note}>{review.signingRequestJson}</Text>
      <Input value={proof} onChange={setProof} placeholder="Owner 签名证明 Base64" multiline bounded />
      <Action label="核对并明确授权" testID="link-consent-confirm" busy={busy}
        accessibilityHint={busy ? '正在核验，请稍候。' : linkOwnerProofInputValid(proof)
          ? '签名证明格式有效；请核对授权范围后继续。' : '签名证明输入无效，请检查后继续。'}
        disabled={busy || !linkOwnerProofInputValid(proof)} onPress={confirm} />
    </View>}
    <Action label="重读双方证明状态" testID="link-consent-key-status-read"
      disabled={busy} onPress={() => readGrants()} />
    <Action label="恢复原授权请求" disabled={busy} onPress={() => recover()} />
    {!!message && <Text testID="link-consent-message"
      accessibilityLiveRegion="polite" style={styles.note}>{message}</Text>}
  </View>;
}

function Input({value, onChange, placeholder, multiline = false, bounded = false}: {
  value: string; onChange: (value: string) => void; placeholder: string; multiline?: boolean; bounded?: boolean;
}): React.JSX.Element {
  return <TextInput style={[styles.input, bounded && styles.proofInput]}
    value={value} onChangeText={onChange} placeholder={placeholder}
    autoCapitalize="none" autoCorrect={false} multiline={multiline} maxLength={21_848} />;
}

function Action({label, disabled, busy = false, testID, accessibilityHint, onPress}: {
  label: string; disabled: boolean; busy?: boolean; testID?: string; accessibilityHint?: string; onPress: () => void;
}): React.JSX.Element {
  return <Pressable testID={testID} accessibilityRole="button" accessibilityLabel={label}
    accessibilityHint={accessibilityHint} accessibilityState={{disabled, busy}} disabled={disabled}
    style={[styles.button, disabled && styles.disabled]} onPress={onPress}>
    <Text style={styles.buttonText}>{label}</Text>
  </Pressable>;
}

const styles = {
  panel: {marginTop: 12, paddingTop: 10, borderTopWidth: 1, borderTopColor: '#E1E7E3', gap: 8},
  row: {flexDirection: 'row', gap: 8},
  title: {color: '#1A2D2B', fontSize: 14, fontWeight: '700'},
  note: {color: '#697974', fontSize: 12, lineHeight: 18},
  input: {borderWidth: 1, borderColor: '#D9E2DC', borderRadius: 10, padding: 10, color: '#1A2D2B'},
  proofInput: {height: 120, textAlignVertical: 'top'},
  button: {alignSelf: 'flex-start', padding: 10, borderRadius: 10, backgroundColor: '#E8F3EF'},
  buttonText: {color: '#186A63', fontSize: 13, fontWeight: '700'},
  disabled: {opacity: 0.5},
  review: {padding: 10, borderRadius: 10, backgroundColor: '#F7F8F6', gap: 8},
} as const;
