import React, {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {Alert, Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, View} from 'react-native';
import {SafeAreaView} from 'react-native-safe-area-context';
import {createClientHubApi, hubProfiles} from '../platform/clientHub';
import type {ClientHubApi, HubProfileRegistry, HubProfileSummary} from '../platform/clientHub';

export interface HubConnection {
  api: ClientHubApi;
  profile: HubProfileSummary;
  openProfiles(): void;
  selectNetwork(networkId: string): Promise<void>;
  setVoiceBusy(busy: boolean): void;
}

const codeOf = (error: unknown) => typeof error === 'object' && error !== null && 'code' in error ?
  String(error.code) : 'PROFILE_OPERATION_FAILED';

/** The keyed child owns transient Hub data; selection replaces that entire child. */
export function HubConnections({children}: {
  children(connection: HubConnection): React.ReactNode;
}): React.JSX.Element {
  const [registry, setRegistry] = useState<HubProfileRegistry | null>(null);
  const [visible, setVisible] = useState(false);
  const [label, setLabel] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [voiceBusy, setVoiceBusyState] = useState(false);
  const voiceBusyRef = useRef(false);
  const busyRef = useRef(false);
  const mounted = useRef(true);
  const accept = useCallback((next: HubProfileRegistry) => {
    if (mounted.current) setRegistry(previous => !previous ||
      next.activeScope.selectionGeneration >= previous.activeScope.selectionGeneration ? next : previous);
  }, []);
  const refresh = useCallback(async () => accept(await hubProfiles.list()), [accept]);
  useEffect(() => {
    mounted.current = true;
    refresh().catch(error => setMessage('无法读取 Hub 配置（' + codeOf(error) + '）'));
    return () => { mounted.current = false; };
  }, [refresh]);

  const api = useMemo(() => registry ? createClientHubApi(registry.activeScope) : null,
    [registry]);
  const profile = registry?.profiles.find(item => item.profileId === registry.activeScope.profileId);
  const setVoiceBusy = useCallback((value: boolean) => {
    voiceBusyRef.current = value;
    setVoiceBusyState(value);
  }, []);
  const change = async (operation: () => Promise<HubProfileRegistry>) => {
    if (voiceBusyRef.current || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setMessage('');
    try { accept(await operation()); }
    catch (error) {
      setMessage('配置操作未完成（' + codeOf(error) + '）。原会话与待恢复请求保留。');
      // A storage error may have advanced selection generation. Do not retain the old facade.
      await refresh().catch(() => undefined);
      throw error;
    } finally { busyRef.current = false; setBusy(false); }
  };
  const openProfiles = () => {
    if (voiceBusyRef.current) return;
    setVisible(true);
    refresh().catch(error => setMessage('读取配置失败（' + codeOf(error) + '）'));
  };
  const activate = (item: HubProfileSummary) => {
    if (!registry || voiceBusyRef.current || busyRef.current) return;
    const scope = {...registry.activeScope};
    Alert.alert('切换到 ' + item.label,
      '当前未发送文字、身份预览和确认界面将清空。每个 Hub 的密钥、授权、计数和待恢复密文保留在原配置。', [
        {text: '取消', style: 'cancel'},
        {text: '切换', onPress: () => {
          change(() => hubProfiles.activate(item.profileId, scope))
            .then(() => { setVisible(false); setLabel(''); }).catch(() => undefined);
        }},
      ]);
  };
  const remove = (item: HubProfileSummary) => {
    if (!registry || voiceBusyRef.current || busyRef.current) return;
    const scope = {...registry.activeScope};
    Alert.alert('移除本机配置？',
      item.label + ' 的本机密钥将删除。此操作不会撤销 Hub 上的设备。存在未解决的登记、RPC、Network 授权、Regroup 委托或 Monitor 操作时不能移除。', [
        {text: '取消', style: 'cancel'},
        {text: '移除', style: 'destructive', onPress: () => {
          change(() => hubProfiles.remove(item.profileId, scope)).catch(() => undefined);
        }},
      ]);
  };

  if (!registry || !api || !profile) return <SafeAreaView style={styles.loading}>
    <Text style={styles.title}>CICADA</Text>
    <Text style={styles.note}>{message || '读取本机 Hub 配置…'}</Text>
    {!!message && <Pressable onPress={() => { refresh().catch(() => undefined); }}>
      <Text style={styles.action}>重新读取</Text>
    </Pressable>}
  </SafeAreaView>;

  return <>
    {children({api, profile, openProfiles, setVoiceBusy, selectNetwork: async networkId => {
      if (voiceBusyRef.current || busyRef.current) throw new Error('PROFILE_SELECTION_BUSY');
      const scope = {...registry.activeScope};
      await change(() => hubProfiles.selectNetwork(networkId, scope));
    }})}
    <Modal visible={visible} animationType="slide" onRequestClose={() => setVisible(false)}>
      <SafeAreaView style={styles.screen}>
        <View style={styles.heading}><Text style={styles.title}>Hub 连接</Text>
          <Pressable onPress={() => setVisible(false)}><Text style={styles.action}>关闭</Text></Pressable>
        </View>
        <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
          <Text style={styles.note}>每个连接独立固定身份与授权。新增连接不会继承其他 Hub 的信任。</Text>
          {registry.profiles.map(item => {
            const active = item.profileId === registry.activeScope.profileId;
            return <View key={item.profileId} style={[styles.card, active && styles.selected]}>
              <Text style={styles.cardTitle}>{item.label}{active ? ' · 当前' : ''}</Text>
              <Text style={styles.note}>{item.hubId || '尚未固定 Hub 身份'}</Text>
              {!!item.baseUrl && <Text style={styles.note}>{item.baseUrl}</Text>}
              <Text style={styles.note}>{item.enrolled ? '设备已登记' : '设备未登记'}
                {item.activeNetworkId ? ' · Network ' + item.activeNetworkId : ' · 未选择 Network'}</Text>
              {!!(item.pendingOperationId || item.enrollmentRecoveryRequired ||
                item.uncertainNeedsReconciliation || item.networkGrantReconciliationRequired ||
                item.regroupReconciliationRequired) &&
                <Text style={styles.note}>原请求待恢复或对账</Text>}
              {!active && <View style={styles.actions}>
                <Pressable disabled={busy || voiceBusy} onPress={() => activate(item)}>
                  <Text style={styles.action}>选择此 Hub</Text>
                </Pressable>
                <Pressable disabled={busy || voiceBusy} onPress={() => remove(item)}>
                  <Text style={styles.remove}>移除本机配置</Text>
                </Pressable>
              </View>}
            </View>;
          })}
          {hubProfiles.available && <View style={styles.card}>
            <Text style={styles.cardTitle}>新增独立连接</Text>
            <TextInput value={label} onChangeText={setLabel} maxLength={80}
              placeholder="连接名称" placeholderTextColor="#697974" style={styles.input}
              accessibilityLabel="新 Hub 配置名称" />
            <Pressable disabled={busy || voiceBusy || !label.trim()} onPress={() => {
              const scope = {...registry.activeScope};
              change(() => hubProfiles.create(label.trim(), scope))
                .then(() => setLabel('')).catch(() => undefined);
            }}><Text style={[styles.action, !label.trim() && styles.disabled]}>
              {busy ? '处理中…' : '创建连接'}
            </Text></Pressable>
          </View>}
          {!!message && <Text style={styles.note}>{message}</Text>}
        </ScrollView>
      </SafeAreaView>
    </Modal>
  </>;
}

const styles = StyleSheet.create({
  screen: {flex: 1, backgroundColor: '#F7F8F6'},
  loading: {flex: 1, backgroundColor: '#F7F8F6', padding: 24, justifyContent: 'center', gap: 16},
  heading: {padding: 24, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center'},
  title: {fontSize: 24, color: '#1A2D2B', fontWeight: '600'},
  content: {padding: 24, gap: 16},
  card: {backgroundColor: '#FFFFFF', borderRadius: 16, padding: 18, gap: 10,
    borderWidth: 1, borderColor: '#E1E7E3'},
  selected: {borderColor: '#186A63'},
  cardTitle: {fontSize: 17, color: '#1A2D2B', fontWeight: '600'},
  note: {fontSize: 13, color: '#697974', lineHeight: 21},
  action: {fontSize: 14, color: '#186A63', fontWeight: '600', paddingVertical: 8},
  remove: {fontSize: 13, color: '#AE7025', paddingVertical: 8},
  actions: {flexDirection: 'row', justifyContent: 'space-between'},
  input: {borderWidth: 1, borderColor: '#E1E7E3', borderRadius: 10, padding: 12, color: '#1A2D2B'},
  disabled: {opacity: 0.35},
});
