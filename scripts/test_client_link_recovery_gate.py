"""Offline parser/identity/budget tests; no Docker or actual Hub restart."""
import copy
import datetime
import importlib.util
import json
import io
import os
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('link_gate', Path(__file__).with_name('client_link_recovery_gate.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class LinkGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source = dict(revision='synthetic', dirty=False, source_fingerprint='f'*64, catalog_sha256='c'*64)
        build = dict(source=self.source, image={'id':'sha256:'+'a'*64}, test_image={'id':'sha256:'+'b'*64})
        (root/'build.json').write_text(json.dumps(build))
        self.config = dict(suite=gate.SUITE, build=str(root/'build.json'), origin='http://127.0.0.1:4567', state=str(root/'state'), workspace=str(root/'workspaces'),
                           work_deadline=gate.time.monotonic()+1000, hub_cidfile=str(root/'hub.cid'), test_cidfile=str(root/'test.cid'), run_id='synthetic',
                           hub_name='synthetic-hub', test_name='synthetic-test', contract_revision='synthetic-v1', raw=str(root/'raw'), receipt=str(root/'receipt.json'))
        (root/'hub.cid').write_text('1'*64+'\n');(root/'test.cid').write_text('2'*64+'\n')
        self.watcher = gate.LinkGate(self.config)
        self.original_read_mountinfo=gate.read_owned_mountinfo
        patch=mock.patch.object(gate,'read_owned_mountinfo',side_effect=lambda pid:self.mountinfo('hub' if pid==1111 else 'test'))
        patch.start();self.addCleanup(patch.stop)

    def mountinfo(self, role):
        flags='rw,nosuid,nodev,'+('noexec,' if role=='hub' else '')+'relatime'
        return ('1253 1244 0:412 / /tmp '+flags+' - tmpfs tmpfs rw,size='+('131072' if role=='hub' else '786432')+'k,inode64\n').encode()

    def event(self, op=gate.OPS[0], digest='d'*64):
        return dict(Package=gate.PACKAGE, Action='output', Test=gate.TOP+'/'+op+'/uncertain', Time='1970-01-01T00:16:40Z',
                    Output='    link_proxy_test.go:436: FAULT_READY ROOT_RESTART_REQUIRED operation='+op+' request_sha256='+digest+'\n')

    def hub(self, started='before'):
        return dict(Id='1'*64, Name='/synthetic-hub', Image='sha256:'+'a'*64, RestartCount=0,
            Config={'User':str(gate.os.getuid())+':'+str(gate.os.getgid()),'Labels':{'org.cicada.test.run':'synthetic','org.cicada.test.role':'hub','org.cicada.test.suite':gate.SUITE}},
            HostConfig={'ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges'],'OomKillDisable':False,
                        'NanoCpus':1_000_000_000,'Memory':268435456,'MemorySwap':268435456,'PidsLimit':128,
                        'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=128m'},'PortBindings':{'8787/tcp':[{'HostIp':'127.0.0.1','HostPort':'4567'}]}},
            Mounts=[{'Destination':'/state','Source':self.config['state'],'Type':'bind','Mode':'','RW':True,'Propagation':'rprivate'},
                    {'Destination':'/workspace','Source':self.config['workspace'],'Type':'bind','Mode':'','RW':True,'Propagation':'rprivate'},
                    {'Destination':'/tmp','Source':'','Type':'tmpfs','Mode':'','RW':True,'Propagation':''}],
            State={'Running':True,'Status':'running','Pid':1111,'StartedAt':started})

    def runner(self):
        row=self.hub();row.update(Id='2'*64,Name='/synthetic-test',Image='sha256:'+'b'*64)
        row['Config'].update(Entrypoint=['go'],Cmd=gate.GO_ARGS,Env=[k+'='+v for k,v in {
            'CICADA_TEST_HUB_URL':self.config['origin'],'CICADA_TEST_HUB_DB':'/tmp/fixture-state/cicada.sqlite3',
            'CICADA_TEST_LINK_UNCERTAIN_RESTART':'external','GOCACHE':'/tmp/go-build','GOPROXY':'off','GOSUMDB':'off',
            'GOTOOLCHAIN':'local','GOENV':'off','CGO_ENABLED':'0','GOMAXPROCS':'2'}.items()])
        row['Config']['Labels']['org.cicada.test.role']='test'
        row['HostConfig'].update(NanoCpus=2_000_000_000,Memory=3221225472,MemorySwap=3221225472,PidsLimit=256,
                               Tmpfs={'/tmp':'rw,exec,nosuid,nodev,size=768m,mode=1777'},NetworkMode='host')
        row['Mounts']=[dict(row['Mounts'][0],Destination='/tmp/fixture-state'),row['Mounts'][2]]
        row['State']['Pid']=2222
        return row

    def test_exact_two_markers_only_restart_recorded_cid(self):
        self.watcher.end=100;self.watcher.baseline=gate.canonical(self.hub())
        with mock.patch.object(gate.time,'time',return_value=1000),mock.patch.object(gate.time,'monotonic',return_value=50),mock.patch.object(gate,'call',return_value=b'') as call, \
             mock.patch.object(self.watcher,'row',side_effect=[self.hub(),self.hub('after1'),self.hub('after1'),self.hub('after2')]),mock.patch.object(self.watcher,'ready'):
            self.watcher.event(self.event())
            self.watcher.event(self.event(gate.OPS[1],'e'*64))
            self.assertEqual([c.args[0] for c in call.call_args_list],[['docker','restart','--timeout','10','1'*64]]*2)
            with self.assertRaises(gate.GateFailure):self.watcher.event(self.event())
        self.assertEqual([r['status'] for r in self.watcher.result['restarts']],['PASS','PASS'])

    def test_marker_scope_digest_and_format_refuse_before_mutation(self):
        variants=[]
        wrong=self.event();wrong['Test']=gate.TOP+'/'+gate.OPS[0]+'/legacy';variants.append(wrong)
        wrong=self.event(gate.OPS[1]);variants.append(wrong)
        wrong=self.event();wrong['Package']='foreign';variants.append(wrong)
        wrong=self.event();wrong['Output']+=' arbitrary';variants.append(wrong)
        with mock.patch.object(gate,'call') as call:
            for event in variants:
                with self.subTest(event=event['Test']),self.assertRaises(gate.GateFailure):self.watcher.event(event)
            call.assert_not_called()
        self.watcher.result['restarts']=[{'operation':gate.OPS[0],'request_sha256':'d'*64,'status':'PASS'}]
        with mock.patch.object(gate,'call') as call,self.assertRaises(gate.GateFailure):self.watcher.event(self.event(gate.OPS[1]))
        call.assert_not_called()

    def test_marker_absolute_deadline_not_extended_by_buffering(self):
        with mock.patch.object(gate.time,'time',return_value=1045),self.assertRaisesRegex(gate.GateFailure,'MARKER_DEADLINE'):
            self.watcher.event(self.event())
        with mock.patch.object(gate.time,'time',return_value=999),self.assertRaisesRegex(gate.GateFailure,'MARKER_DEADLINE'):
            self.watcher.event(self.event())
        with mock.patch.object(gate.time,'monotonic',return_value=10),self.assertRaises(gate.GateFailure):gate.budget(10,0.5)

    def test_health_capability_and_same_hub_identity(self):
        healthy=dict(status='ok',**self.source)
        caps=dict(status='partial',catalog_sha256='c'*64,contract_revision='synthetic-v1',external_thread_links=False)
        with mock.patch.object(self.watcher,'get',side_effect=[healthy,{'hub_id':'synthetic-hub'},caps]):self.watcher.ready(self.config['work_deadline'])
        for response in [[healthy,{'hub_id':'different'},caps],[dict(healthy,dirty=True),{'hub_id':'synthetic-hub'},caps],
                         [healthy,{'hub_id':'synthetic-hub'},dict(caps,external_thread_links=True)]]:
            with mock.patch.object(self.watcher,'get',side_effect=response),self.assertRaises(gate.GateFailure):self.watcher.ready(self.config['work_deadline'])

    def test_unavailable_identity_poll_has_one_absolute_deadline(self):
        with mock.patch.object(self.watcher,'get',side_effect=OSError),mock.patch.object(gate.time,'monotonic',side_effect=[0,0,11]),mock.patch.object(gate.time,'sleep') as sleep:
            with self.assertRaises(gate.GateFailure):self.watcher.ready(10,poll=True)
            sleep.assert_called_once()

    def test_actual_get_short_timeout_and_no_redirect(self):
        response=mock.MagicMock();response.status=200;response.read.return_value=b'{}';response.__enter__.return_value=response
        with mock.patch.object(self.watcher.opener,'open',return_value=response) as opening:
            self.assertEqual(self.watcher.get('/healthz',self.config['work_deadline']),{})
            self.assertLessEqual(opening.call_args.kwargs['timeout'],0.5)
        with self.assertRaises(gate.GateFailure):gate.NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_cid_owner_mount_and_loopback_origin_fail_closed(self):
        row=self.hub()
        with mock.patch.object(gate,'call',return_value=json.dumps([row]).encode()):self.assertEqual(self.watcher.row('hub',self.config['work_deadline'])['Id'],'1'*64)
        for mutation in ['image','label','mount','port']:
            changed=copy.deepcopy(row)
            if mutation=='image':changed['Image']='sha256:'+'9'*64
            if mutation=='label':changed['Config']['Labels']['org.cicada.test.run']='foreign'
            if mutation=='mount':changed['Mounts'][0]['Source']='/foreign'
            if mutation=='port':changed['HostConfig']['PortBindings']['8787/tcp'][0]['HostIp']='0.0.0.0'
            with mock.patch.object(gate,'call',return_value=json.dumps([changed]).encode()),self.assertRaises(gate.GateFailure):self.watcher.row('hub',self.config['work_deadline'])
        for origin in ['http://localhost:1234','http://127.0.0.1:1234/path','http://127.0.0.1:99999','https://127.0.0.1:1234']:
            with self.assertRaises(gate.GateFailure):gate.LinkGate(dict(self.config,origin=origin))

    def test_mount_order_only_normalized(self):
        baseline=self.hub();reordered=copy.deepcopy(baseline);reordered['Mounts'].reverse()
        self.assertEqual(gate.canonical(baseline),gate.canonical(reordered))
        for field,value in [('Source','/other'),('RW',False),('Propagation','shared')]:
            changed=copy.deepcopy(baseline);changed['Mounts'][0][field]=value
            self.assertNotEqual(gate.canonical(baseline),gate.canonical(changed))
        changed=copy.deepcopy(baseline);changed['Config']['Labels']['extra']='value'
        self.assertNotEqual(gate.canonical(baseline),gate.canonical(changed))
        changed=copy.deepcopy(baseline);changed['HostConfig']['Memory']=123
        self.assertNotEqual(gate.canonical(baseline),gate.canonical(changed))

    def test_resident_started_at_and_config_are_compared_completely(self):
        root=Path(self.temp.name);row=self.hub();ids=row['Id'].encode()+b'\n'
        with mock.patch.object(gate,'call',side_effect=[ids,json.dumps([row]).encode()]):gate.snapshot(root/'before')
        reordered=copy.deepcopy(row);reordered['Mounts'].reverse()
        with mock.patch.object(gate,'call',side_effect=[json.dumps([reordered]).encode()]):gate.snapshot(root/'reordered',root/'before')
        for index,field in enumerate(['StartedAt','Config','HostConfig','OomKillDisable','Mounts','RestartCount']):
            changed=copy.deepcopy(row)
            if field=='StartedAt':changed['State']['StartedAt']='changed'
            if field=='Config':changed['Config']['Env']=['SYNTHETIC=changed']
            if field=='HostConfig':changed['HostConfig']['Memory']=456
            if field=='OomKillDisable':changed['HostConfig']['OomKillDisable']=None
            if field=='Mounts':changed['Mounts'][0]['Source']='/synthetic-changed-source'
            if field=='RestartCount':changed['RestartCount']=row['RestartCount']+1
            with mock.patch.object(gate,'call',side_effect=[json.dumps([changed]).encode()]),self.assertRaises(gate.GateFailure):gate.snapshot(root/('changed%d'%index),root/'before')

    def test_resident_evidence_never_contains_env_or_arbitrary_label_text(self):
        root=Path(self.temp.name);row=self.hub();secret='SYNTHETIC_SECRET_OnlyMemory_73a9'
        row['Config'].update(Env=['TOKEN='+secret],Labels={'untrusted-label':secret})
        row['HostConfig']['LogConfig']={'Type':'synthetic','Config':{'credential':secret}}
        ids=row['Id'].encode()+b'\n'
        with mock.patch.object(gate,'call',side_effect=[ids,json.dumps([row]).encode()]):gate.snapshot(root/'secret-before')
        changed=copy.deepcopy(row);changed['Config']['Labels']['untrusted-label']='different'
        with mock.patch.object(gate,'call',side_effect=[json.dumps([changed]).encode()]),self.assertRaisesRegex(gate.GateFailure,'RESIDENT_CHANGED'):
            gate.snapshot(root/'secret-after',root/'secret-before')
        gate.save(root/'result',self.watcher.result)
        for path in root.iterdir():
            if path.is_file():
                text=path.read_text();self.assertNotIn(secret,text);self.assertNotIn('untrusted-label',text);self.assertNotIn('"Env"',text)

    def test_resident_expected_snapshot_ignores_later_unrelated_container(self):
        root=Path(self.temp.name);row=self.hub();ids=row['Id'].encode()+b'\n'
        with mock.patch.object(gate,'call',side_effect=[ids,json.dumps([row]).encode()]):
            gate.snapshot(root/'before')
        foreign=copy.deepcopy(row);foreign['Id']='f'*64
        def current(argv, end):
            if argv == ['docker','ps','-q','--no-trunc']:
                return ids+foreign['Id'].encode()+b'\n'
            requested=argv[2:]
            return json.dumps([r for r in (row,foreign) if r['Id'] in requested]).encode()
        with mock.patch.object(gate,'call',side_effect=current) as read:
            gate.snapshot(root/'after',root/'before')
        self.assertEqual(read.call_args.args[0],['docker','inspect',row['Id']])
        self.assertEqual(json.loads((root/'before').read_text()),json.loads((root/'after').read_text()))

    def test_resident_empty_baseline_ignores_later_foreign_container(self):
        root=Path(self.temp.name)
        with mock.patch.object(gate,'call',return_value=b'') as before:
            gate.snapshot(root/'empty-before')
        self.assertEqual(before.call_args.args[0],['docker','ps','-q','--no-trunc'])
        self.assertEqual(json.loads((root/'empty-before').read_text()),[])
        foreign=self.hub()
        # If the code queried the live set, this now-running unrelated ID would be visible.
        def current(argv, end):
            if argv == ['docker','ps','-q','--no-trunc']:
                return foreign['Id'].encode()+b'\n'
            return json.dumps([foreign]).encode()
        with mock.patch.object(gate,'call',side_effect=current) as after:
            gate.snapshot(root/'empty-after',root/'empty-before')
        after.assert_not_called()
        self.assertEqual(json.loads((root/'empty-after').read_text()),[])

    def test_resident_expected_missing_or_stopped_still_refused(self):
        root=Path(self.temp.name);row=self.hub();ids=row['Id'].encode()+b'\n'
        with mock.patch.object(gate,'call',side_effect=[ids,json.dumps([row]).encode()]):
            gate.snapshot(root/'before')
        with mock.patch.object(gate,'call',side_effect=gate.GateFailure('DOCKER_COMMAND')),self.assertRaises(gate.GateFailure):
            gate.snapshot(root/'missing',root/'before')
        stopped=copy.deepcopy(row);stopped['State']['Running']=False
        with mock.patch.object(gate,'call',return_value=json.dumps([stopped]).encode()),self.assertRaises(gate.GateFailure):
            gate.snapshot(root/'stopped',root/'before')

    def test_resident_expected_duplicate_identity_refused_before_inspect(self):
        root=Path(self.temp.name);row=self.hub()
        gate.save(root/'duplicate',[{'Id':row['Id']},{'Id':row['Id']}])
        with mock.patch.object(gate,'call') as read,self.assertRaises(gate.GateFailure):
            gate.snapshot(root/'after-duplicate',root/'duplicate')
        read.assert_not_called()

    def test_workspace_and_actual_tmpfs_mounts_fail_closed(self):
        for role,row in [('hub',self.hub()),('test',self.runner())]:
            with mock.patch.object(gate,'call',return_value=json.dumps([row]).encode()):self.watcher.row(role,self.config['work_deadline'])
            for destination in [m['Destination'] for m in row['Mounts']]:
                for field,value in [('Type','volume'),('Source','/foreign'),('Destination','/unexpected'),('RW',False),('Mode','ro'),('Propagation','shared')]:
                    changed=copy.deepcopy(row)
                    next(m for m in changed['Mounts'] if m['Destination']==destination)[field]=value
                    with self.subTest(role=role,destination=destination,field=field),mock.patch.object(gate,'call',return_value=json.dumps([changed]).encode()),self.assertRaises(gate.GateFailure):
                        self.watcher.row(role,self.config['work_deadline'])

    def test_real_docker_tmpfs_api_shape_in_created_running_stopped(self):
        for role,row in [('hub',self.hub()),('test',self.runner())]:
            row['Mounts']=[m for m in row['Mounts'] if m['Destination']!='/tmp']
            for state in ['created','running','exited']:
                changed=copy.deepcopy(row);changed['State'].update(Status=state,Running=state=='running',Pid=row['State']['Pid'] if state=='running' else 0)
                before=len(self.watcher.result.get('kernel_tmpfs',[]))
                with mock.patch.object(gate,'call',return_value=json.dumps([changed]).encode()),mock.patch.object(gate,'read_owned_mountinfo',return_value=self.mountinfo(role)) as reading:
                    self.watcher.row(role,self.config['work_deadline'])
                self.assertEqual(reading.call_count,1 if state=='running' else 0)
                self.assertEqual(len(self.watcher.result.get('kernel_tmpfs',[]))-before,1 if state=='running' else 0)
        self.assertEqual(set(self.watcher.result['kernel_tmpfs'][0]),{'role','fstype','rw','nosuid','nodev','noexec','size_kib'})

    def test_kernel_tmpfs_flags_size_duplicate_and_oversize_refused(self):
        for role in ['hub','test']:
            data=self.mountinfo(role);self.assertEqual(gate.kernel_tmpfs(data,role)['noexec'],role=='hub')
            for value in [data.replace(b'/tmp',b'/other'),data.replace(b' - tmpfs tmpfs ',b' - ext4 rootfs '),
                          data.replace(b'rw,nosuid,nodev',b'ro,nosuid,nodev'),data.replace(b'nosuid,',b''),data.replace(b'nodev,',b''),
                          data.replace(b'131072k',b'4096k').replace(b'786432k',b'4096k'),data+data,
                          data.replace(b'noexec,',b'') if role=='hub' else data.replace(b'relatime',b'noexec,relatime')]:
                with self.subTest(role=role,data=value),self.assertRaises(gate.GateFailure):gate.kernel_tmpfs(value,role)
        with self.assertRaisesRegex(gate.GateFailure,'OWNED_MOUNTINFO_SIZE'):gate.kernel_tmpfs(b'x'*(gate.MOUNTINFO_LIMIT+1),'hub')
        with self.assertRaisesRegex(gate.GateFailure,'OWNED_KERNEL_TMPFS'):gate.kernel_tmpfs(b'\xff','hub')

    def test_owned_pid_owner_unreadable_and_bounded_read(self):
        for pid in [0,-1,True,'123']:
            with self.assertRaisesRegex(gate.GateFailure,'OWNED_PID'):self.original_read_mountinfo(pid)
        with mock.patch.object(gate.Path,'lstat',return_value=mock.Mock(st_mode=gate.stat.S_IFDIR,st_uid=os.getuid()+1)),mock.patch.object(gate.os,'open') as opening:
            with self.assertRaisesRegex(gate.GateFailure,'OWNED_PID_OWNER'):self.original_read_mountinfo(1111)
            opening.assert_not_called()
        with mock.patch.object(gate.Path,'lstat',side_effect=PermissionError),self.assertRaisesRegex(gate.GateFailure,'OWNED_MOUNTINFO_UNREADABLE'):
            self.original_read_mountinfo(1111)
        source=mock.MagicMock();source.__enter__.return_value=source;source.read.return_value=b'x'*(gate.MOUNTINFO_LIMIT+1)
        with mock.patch.object(gate.Path,'lstat',return_value=mock.Mock(st_mode=gate.stat.S_IFDIR,st_uid=os.getuid())), \
             mock.patch.object(gate.os,'open',return_value=123),mock.patch.object(gate.os,'fdopen',return_value=source), \
             mock.patch.object(gate.os,'fstat',return_value=mock.Mock(st_mode=gate.stat.S_IFREG,st_uid=os.getuid())):
            with self.assertRaisesRegex(gate.GateFailure,'OWNED_MOUNTINFO_SIZE'):self.original_read_mountinfo(1111)
            source.read.assert_called_once_with(gate.MOUNTINFO_LIMIT+1)

    def test_changed_pid_started_at_or_inspect_state_refused(self):
        row=self.hub()
        for field,value in [('Pid',9999),('StartedAt','changed'),('Running',False)]:
            changed=copy.deepcopy(row);changed['State'][field]=value
            with mock.patch.object(gate,'call',side_effect=[json.dumps([row]).encode(),json.dumps([changed]).encode()]),self.assertRaisesRegex(gate.GateFailure,'OWNED_PID_CHANGED'):
                self.watcher.row('hub',self.config['work_deadline'])
        self.assertFalse(self.watcher.kernel_verified);self.assertNotIn('kernel_tmpfs',self.watcher.result)

    def test_runner_false_null_default_preserves_original_snapshot_provenance(self):
        created=self.runner();created['State'].update(Running=False,Status='created',Pid=0)
        running=copy.deepcopy(created);running['State'].update(Running=True,Status='running',Pid=2222,StartedAt='after')
        running['HostConfig']['OomKillDisable']=None
        self.assertEqual(gate.runner_canonical(created),gate.runner_canonical(running))
        self.assertNotEqual(gate.canonical(created),gate.canonical(running))
        before,after=gate.runner_provenance(created),gate.runner_provenance(running)
        self.assertNotEqual(before['canonical_sha256'],after['canonical_sha256'])
        self.assertIs(before['oom_kill_disable'],False);self.assertIsNone(after['oom_kill_disable'])
        self.assertIs(created['HostConfig']['OomKillDisable'],False)
        with mock.patch.object(gate,'call',side_effect=[json.dumps([created]).encode(),json.dumps([running]).encode(),json.dumps([running]).encode()]):
            self.watcher.row('test',self.config['work_deadline'])
            self.assertNotIn('kernel_tmpfs',self.watcher.result)
            self.watcher.row('test',self.config['work_deadline'])
            self.assertEqual(len(self.watcher.result['kernel_tmpfs']),1)

    def test_oom_disable_true_unexpected_type_and_other_config_drift_refused(self):
        baseline=self.runner()
        for value in [True,0,1,'false',[],{}]:
            changed=copy.deepcopy(baseline);changed['HostConfig']['OomKillDisable']=value
            with self.subTest(value=value):
                with self.assertRaisesRegex(gate.GateFailure,'OWNED_OOM_KILL_DISABLE'):gate.runner_canonical(changed)
                for role in ['hub','test']:
                    with self.assertRaisesRegex(gate.GateFailure,'OWNED_OOM_KILL_DISABLE'):self.watcher.security(changed,role)
        changed=copy.deepcopy(baseline);del changed['HostConfig']['OomKillDisable']
        with self.assertRaisesRegex(gate.GateFailure,'OWNED_OOM_KILL_DISABLE'):gate.runner_canonical(changed)
        for field,value in [('Memory',123),('NanoCpus',3),('Tmpfs',{}),('CapDrop',[]),('ReadonlyRootfs',False)]:
            changed=copy.deepcopy(baseline);changed['HostConfig'][field]=value
            self.assertNotEqual(gate.runner_canonical(baseline),gate.runner_canonical(changed))
        changed=copy.deepcopy(baseline);changed['Config']['User']='foreign'
        self.assertNotEqual(gate.runner_canonical(baseline),gate.runner_canonical(changed))

    def test_command_stream_limit_accepts_exact_bound_and_refuses_overflow(self):
        with mock.patch.object(gate,'COMMAND_LIMIT',4096):
            reply=gate.call([sys.executable,'-c','import os;os.write(1,b"x"*4096)'],time.monotonic()+2)
            self.assertEqual(len(reply),4096)
            with self.assertRaisesRegex(gate.GateFailure,'DOCKER_COMMAND'):
                gate.call([sys.executable,'-c','import os\nwhile True:os.write(1,b"x"*65536)'],time.monotonic()+2)

    def test_command_deadline_and_nonzero_exit_are_failures(self):
        start=time.monotonic()
        with self.assertRaisesRegex(gate.GateFailure,'DOCKER_COMMAND'):
            gate.call([sys.executable,'-c','import time;time.sleep(10)'],start+2,0.1)
        self.assertLess(time.monotonic()-start,1.5)
        with self.assertRaisesRegex(gate.GateFailure,'DOCKER_COMMAND'):
            gate.call([sys.executable,'-c','raise SystemExit(7)'],time.monotonic()+2)

    def test_total_raw_cap_independent_of_small_chunks(self):
        raw=io.BytesIO();chunk=b'x'*65536
        for _ in range(gate.RAW_LIMIT//len(chunk)):self.watcher.capture(raw,chunk)
        self.assertEqual(raw.tell(),gate.RAW_LIMIT)
        with self.assertRaisesRegex(gate.GateFailure,'GO_RAW_TOTAL_SIZE'):self.watcher.capture(raw,b'x')
        self.assertEqual(raw.tell(),gate.RAW_LIMIT)

    def test_lifecycle_records_bound(self):
        event=dict(Package=gate.PACKAGE,Action='run',Test=gate.TOP)
        for _ in range(gate.LIFECYCLE_LIMIT):self.watcher.event(event)
        with self.assertRaisesRegex(gate.GateFailure,'GO_LIFECYCLE_SIZE'):self.watcher.event(event)
        self.assertEqual(len(self.watcher.result['tests']),64)

    def test_initial_host_security_resource_and_tmpfs_exact_for_both_roles(self):
        bad={'ReadonlyRootfs':False,'Privileged':True,'CapDrop':[], 'CapAdd':['SYS_ADMIN'],
             'SecurityOpt':['no-new-privileges','seccomp=unconfined'],'NanoCpus':3,'Memory':123,'MemorySwap':-1,'PidsLimit':0}
        for role in ['hub','test']:
            row=self.hub()
            if role=='test':row['HostConfig'].update(NanoCpus=2_000_000_000,Memory=3221225472,MemorySwap=3221225472,
                                                     PidsLimit=256,Tmpfs={'/tmp':'rw,exec,nosuid,nodev,size=768m,mode=1777'})
            self.watcher.security(row,role)
            for field,value in bad.items():
                changed=copy.deepcopy(row);changed['HostConfig'][field]=value
                with self.subTest(role=role,field=field),self.assertRaises(gate.GateFailure):self.watcher.security(changed,role)
            changed=copy.deepcopy(row)
            changed['HostConfig']['Tmpfs']['/tmp']=row['HostConfig']['Tmpfs']['/tmp'].replace('noexec','exec') if role=='hub' else row['HostConfig']['Tmpfs']['/tmp'].replace(',exec,',',noexec,')
            with self.assertRaises(gate.GateFailure):self.watcher.security(changed,role)

    def test_early_failure_private_copy_requires_created_directory(self):
        shell=Path(__file__).with_name('test-client-hub-interop.sh').read_text()
        begin=shell.index('  if [[ "$suite" == client-link-recovery && -f "$scratch/test.raw"')
        fragment=shell[begin:shell.index('  fi',begin)+len('  fi')]
        root=Path(self.temp.name);scratch=root/'scratch';output=root/'output';scratch.mkdir();output.mkdir()
        (scratch/'test.raw').write_bytes(b'SYNTHETIC_RAW')
        env=dict(os.environ,suite='client-link-recovery',scratch=str(scratch),output_root=str(output))
        first=subprocess.run(['bash','-e','-c',fragment],env=env,capture_output=True,timeout=2)
        self.assertEqual(first.returncode,0);self.assertFalse((output/'private').exists())
        (output/'private').mkdir()
        second=subprocess.run(['bash','-e','-c',fragment],env=env,capture_output=True,timeout=2)
        self.assertEqual(second.returncode,0);self.assertEqual((output/'private/test.raw').read_bytes(),b'SYNTHETIC_RAW')
        self.assertEqual((output/'private/test.raw').stat().st_mode & 0o777,0o600)

    def test_early_preflight_failure_formatter_preserves_not_run(self):
        shell=Path(__file__).with_name('test-client-hub-interop.sh').read_text()
        begin=shell.index('python3 - "$scratch/test.raw" "$output_root/test.log"')
        fragment=shell[begin:shell.index('\nPY',begin)+len('\nPY')]
        root=Path(self.temp.name);scratch=root/'scratch';output=root/'output';scratch.mkdir();output.mkdir()
        env=dict(os.environ,suite=gate.SUITE,scratch=str(scratch),output_root=str(output),test_exit='1')
        reply=subprocess.run(['bash','-c',fragment],env=env,capture_output=True,timeout=2)
        self.assertEqual(reply.returncode,1);self.assertNotIn(b'FileNotFoundError',reply.stderr)
        self.assertFalse((scratch/'test.raw').exists())
        self.assertEqual(json.loads((output/'test.log').read_text()), {
            'runner_exit_code':1,
            'required_tests_passed':[],
            'required_test_statuses':{'TestClientDockerHubLinkFaultFixture':'NOT_RUN'},
            'raw_present':False,
            'test_status':'NOT_RUN',
        })
        env['test_exit']='0'
        self.assertEqual(subprocess.run(['bash','-c',fragment],env=env,capture_output=True,timeout=2).returncode,1)

    def test_finish_missing_inputs_preserves_blocked_and_downgrades_pass(self):
        shell=Path(__file__).with_name('test-client-hub-interop.sh').read_text()
        begin=shell.index('  if [[ "$suite" == client-link-recovery ]]; then',shell.index('finish()'))
        fragment=shell[begin:shell.index('  python3 - "$output_root" "$scratch"',begin)]
        output=Path(self.temp.name)/'early-output';output.mkdir()
        for status,code,expected in [('BLOCKED','1','BLOCKED:1'),('PASS','0','FAIL:1'),('FAIL','7','FAIL:7')]:
            env=dict(os.environ,suite=gate.SUITE,output_root=str(output),status=status,exit_code=code)
            reply=subprocess.run(['bash','-e','-c',fragment+'printf "%s:%s" "$status" "$exit_code"'],env=env,capture_output=True,timeout=2)
            with self.subTest(status=status):
                self.assertEqual(reply.returncode,0);self.assertEqual(reply.stdout.decode(),expected)

    def test_formatter_preserves_existing_suite_required_tests(self):
        shell=Path(__file__).with_name('test-client-hub-interop.sh').read_text()
        begin=shell.index('python3 - "$scratch/test.raw" "$output_root/test.log"')
        fragment=shell[begin:shell.index('\nPY',begin)+len('\nPY')]
        root=Path(self.temp.name);scratch=root/'scratch';output=root/'output';scratch.mkdir();output.mkdir()
        cases={'client':['TestClientDockerHubSmoke','TestClientDockerHubRecoveryFixture',
                         'TestClientDockerHubHeadlessOperator'],
               'network-m1':['TestNetworkM1DockerHub'],
               'group-spaces-m2':['TestGroupSpacesM2DockerHub','TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS'],
               'capacity':['TestHubBoundedCapacityDocker']}
        for suite,names in cases.items():
            env=dict(os.environ,suite=suite,scratch=str(scratch),output_root=str(output),test_exit='0')
            for complete in [True,False]:
                events=[]
                for name in (names if complete else names[:-1]):
                    events.extend([{'Test':name,'Action':'run'},
                                   {'Test':name,'Action':'pass','Output':'SYNTHETIC_PRIVATE_ONLY'}])
                (scratch/'test.raw').write_text(''.join(json.dumps(e)+'\n' for e in events))
                reply=subprocess.run(['bash','-c',fragment],env=env,capture_output=True,timeout=2)
                with self.subTest(suite=suite,complete=complete):self.assertEqual(reply.returncode,0 if complete else 1)
                sanitized=(output/'test.log').read_text()
                self.assertNotIn('SYNTHETIC_PRIVATE_ONLY',sanitized)
                footer=json.loads(sanitized.splitlines()[-1])
                self.assertEqual(footer['test_status'],'PASS' if complete else 'FAIL')
                if suite=='client' and not complete:
                    self.assertEqual(footer['runner_exit_code'],0)
                    self.assertEqual(footer['required_test_statuses']['TestClientDockerHubHeadlessOperator'],'NOT_RUN')

    def test_client_docker_branch_dispatches_selected_tests_to_go(self):
        shell=Path(__file__).with_name('test-client-hub-interop.sh').read_text()
        anchor=shell.index('phase=protocol_test')
        begin=shell.index('else\n  docker run --cidfile "$scratch/test.cid"',anchor)+len('else\n')
        command=shell[begin:shell.index('\nfi\ntest_exit=$?',begin)]
        root=Path(self.temp.name);scratch=root/'scratch';fakebin=root/'fakebin'
        scratch.mkdir();fakebin.mkdir();(scratch/'test.env').write_text('')
        captured=root/'docker-args.json'
        docker=fakebin/'docker'
        docker.write_text('#!/usr/bin/env python3\nimport json, os, sys\nfrom pathlib import Path\nPath(os.environ["CAPTURE"]).write_text(json.dumps(sys.argv[1:]))\n')
        docker.chmod(0o700)
        selector='^TestClientDockerHub(Smoke|RecoveryFixture|HeadlessOperator)$'
        env=dict(os.environ,PATH=str(fakebin)+os.pathsep+os.environ['PATH'],CAPTURE=str(captured),
                 scratch=str(scratch),test_image_id='sha256:'+('a'*64),child_run_id='synthetic-run',
                 test_container='synthetic-test',hub_url='http://127.0.0.1:8787',test_selector=selector)
        reply=subprocess.run(['bash','-euo','pipefail','-c',command],env=env,capture_output=True,timeout=2)
        self.assertEqual(reply.returncode,0,reply.stderr.decode(errors='replace'))
        args=json.loads(captured.read_text())
        self.assertEqual(args[0],'run')
        self.assertEqual(args[args.index('--entrypoint')+1],'go')
        image=args.index('sha256:'+('a'*64))
        self.assertEqual(args[image+1:],[
            'test','-json','-p=1','./internal/server','./cmd/client-recovery-fixture',
            '-run',selector,'-count=1','-timeout=180s',
        ])

    def test_client_result_metadata_uses_named_test_terminal_and_separate_runner_exit(self):
        shell=Path(__file__).with_name('test-client-hub-interop.sh').read_text()
        marker='  python3 - "$output_root" "$scratch" "$status" "$phase" "$exit_code" "$test_exit" "$test_image_id" "$suite" <<\'PY\'\n'
        begin=shell.index(marker)+len(marker)
        code=shell[begin:shell.index('\nPY\n  rmdir "$output_root/.running"',begin)]
        root=Path(self.temp.name);output=root/'result-output';scratch=root/'scratch'
        output.mkdir();scratch.mkdir()
        rows=[
            {'test':'TestClientDockerHubSmoke','action':'run'},
            {'test':'TestClientDockerHubSmoke','action':'pass'},
            {'test':'TestClientDockerHubRecoveryFixture','action':'run'},
            {'test':'TestClientDockerHubRecoveryFixture','action':'pass'},
        ]
        cases=[([], 'NOT_RUN'),([{'test':'TestClientDockerHubHeadlessOperator','action':'run'}], 'FAIL'),
               ([{'test':'TestClientDockerHubHeadlessOperator','action':'run'},
                 {'test':'TestClientDockerHubHeadlessOperator','action':'pass'}], 'PASS'),
               ([{'test':'TestClientDockerHubHeadlessOperator','action':'run'},
                 {'test':'TestClientDockerHubHeadlessOperator','action':'skip'}], 'SKIP'),
               ([{'test':'TestClientDockerHubHeadlessOperator','action':'run'},
                 {'test':'TestClientDockerHubHeadlessOperator','action':'pass'},
                 {'test':'TestClientDockerHubHeadlessOperator','action':'run'}], 'FAIL')]
        for headless_events,expected in cases:
            (output/'test.log').write_text(''.join(json.dumps(row)+'\n' for row in rows+headless_events))
            reply=subprocess.run([sys.executable,'-',str(output),str(scratch),'FAIL','protocol_test','1','0',
                                  'sha256:'+('b'*64),'client'],input=code,text=True,capture_output=True,timeout=2)
            self.assertEqual(reply.returncode,0,reply.stderr)
            result=json.loads((output/'result.json').read_text())
            self.assertEqual(result['headless_operator_test']['status'],expected)
            self.assertEqual(result['headless_operator_test']['runner_exit_code'],0)
            self.assertNotIn('exit_code',result['headless_operator_test'])

    def test_changed_interop_receipt_families_use_v2_schema(self):
        shell=Path(__file__).with_name('test-client-hub-interop.sh').read_text()
        marker='  python3 - "$output_root" "$scratch" "$status" "$phase" "$exit_code" "$test_exit" "$test_image_id" "$suite" <<\'PY\'\n'
        begin=shell.index(marker)+len(marker)
        code=shell[begin:shell.index('\nPY\n  rmdir "$output_root/.running"',begin)]
        root=Path(self.temp.name);output=root/'schema-output';scratch=root/'scratch'
        output.mkdir();scratch.mkdir()
        cases=(
            ('client','cicada.client-hub-interop.v2','TestClientDockerHubSmoke'),
            ('client-link-recovery','cicada.client-link-recovery-interop.v2','TestClientDockerHubLinkFaultFixture'),
            ('network-m1','cicada.network-m1-interop.v2','TestNetworkM1DockerHub'),
            ('group-spaces-m2','cicada.group-spaces-m2-interop.v2','TestGroupSpacesM2DockerHub'),
            ('capacity','cicada.hub-bounded-capacity.v2','TestHubBoundedCapacityDocker'),
        )
        for suite,expected_version,test_name in cases:
            rows=[{'test':test_name,'action':'run'},{'test':test_name,'action':'pass'}]
            (output/'test.log').write_text(''.join(json.dumps(row)+'\n' for row in rows))
            reply=subprocess.run([sys.executable,'-',str(output),str(scratch),'PASS','protocol_test','0','0',
                                  'sha256:'+('c'*64),suite],input=code,text=True,capture_output=True,timeout=2)
            with self.subTest(suite=suite):
                self.assertEqual(reply.returncode,0,reply.stderr)
                result=json.loads((output/'result.json').read_text())
                self.assertEqual(result['schema_version'],expected_version)


if __name__ == '__main__':unittest.main()
