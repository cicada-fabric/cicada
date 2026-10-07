"""Proposal runner: exact effective owned Forwarder plus four Observer._connect calls."""
import argparse,builtins,contextlib,hashlib,io,json,os,re,subprocess,sys,time,types
from pathlib import Path
IMAGE='sha256:ebea4c9988e539d2da914e9cf451c35d5c5039cf99706cd1effc0a6d7b449b83'
RUN=None
FIXTURE='cicada.tls-only.v1'
SCRIPTS=Path('/home/zyf/CICADA/scripts')
OBS_SHA=None
BIND_SHA=None
SECRET='/gpu1-share/data/cicada/secrets/cicada-acceptance-zzswitch-20261003.env'
PROGRAM=r"""import builtins,io,os,sys,json,time,hashlib
# Persistent credential-content/metadata denial precedes Observer import.
def wrap(fn):
 def guard(path,*a,**kw):
  if isinstance(path,(str,bytes,os.PathLike)) and os.fsdecode(path).startswith(('/run/secrets','/gpu1-share')):raise PermissionError()
  return fn(path,*a,**kw)
 return guard
for owner,name in ((builtins,'open'),(io,'open'),(os,'open'),(os,'stat'),(os,'lstat')):setattr(owner,name,wrap(getattr(owner,name)))
for key in ('API_KEY','OPENAI_API_KEY','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'):os.environ.pop(key,None)
control=json.loads(sys.stdin.readline(1025))
if set(control)!={'gateway','port','deadline','observer_sha'} or type(control['port']) is not int or not 1<=control['port']<=65535:raise SystemExit(2)
with open('/probe/native_request_observer.py','rb') as source:
 if hashlib.sha256(source.read(65537)).hexdigest()!=control['observer_sha']:raise SystemExit(2)
sys.path.insert(0,'/probe')
import native_request_observer as observer
ns=os.stat('/proc/self/ns/time');link=os.readlink('/proc/self/ns/time')
if not link.startswith('time:[') or not link.endswith(']') or not link[6:-1].isdigit():raise SystemExit(2)
with open('/proc/sys/kernel/random/boot_id','rb') as boot:boot_sha=hashlib.sha256(boot.read(128)).hexdigest()
namespace={'dev':ns.st_dev,'ino':ns.st_ino,'link':link,'boot_id_sha256':boot_sha}
client=observer.Observer('https://api.zzswitch.com/v1','PUBLIC_SYNTHETIC',lambda row:None,enabled=False,
 gateway='http://'+control['gateway']+':'+str(control['port']),io_diagnostics_v2=True)
rows=[]
for attempt in range(1,5):
 diagnostic={'schema':observer.IO_SCHEMA_V2,'sequence':attempt-1,'POST_before':0,'POST_after':0,
 'shutdown_requested':False,'first_failure':None,'cleanup_failures':[],'cleanup_truncated':False,'upstream_eof':False,'local_tcp_port':None}
 sock=None;status='TLS_HANDSHAKE_FAILED';start=time.monotonic_ns()
 try:
  sock=client._connect(min(control['deadline'],time.monotonic()+12),diagnostic);status='TLS_HANDSHAKE_PASS'
 except BaseException:pass
 finally:
  if sock is not None:
   try:sock.close()
   except BaseException as error:observer._note_io(diagnostic,'CLOSE_UPSTREAM',error,cleanup=True)
 rows.append({'attempt':attempt,'status':status,'start_ns':start,'end_ns':time.monotonic_ns(),
  'diagnostic':observer.validate_io_diagnostic_v2(diagnostic)})
print(json.dumps({'schema':'cicada.tls-only.closed.v2','rows':rows,'application_POSTs':client.posts,
 'observer_handle_called':False,'default_CA_configured':True,'hostname_validation_configured':True,
 'ALPN_policy':'http/1.1','time_namespace':namespace},sort_keys=True))
"""

def sha(raw):return hashlib.sha256(raw).hexdigest()
def private(path,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw)
def namespace_metadata():
 value=os.stat('/proc/self/ns/time');link=os.readlink('/proc/self/ns/time')
 if not re.fullmatch(r'time:\[[0-9]+\]',link):raise ValueError('NAMESPACE')
 with open('/proc/sys/kernel/random/boot_id','rb') as boot:boot_sha=sha(boot.read(128))
 return {'dev':value.st_dev,'ino':value.st_ino,'link':link,'boot_id_sha256':boot_sha}

def validate_projection(value):
 from native_request_observer import validate_io_diagnostic_v2
 if type(value) is not dict or set(value)!={'schema','rows','application_POSTs','observer_handle_called','default_CA_configured','hostname_validation_configured','ALPN_policy','time_namespace'} or value['schema']!='cicada.tls-only.closed.v2':raise ValueError('SCHEMA')
 if type(value['application_POSTs']) is not int or value['application_POSTs']!=0 or value['observer_handle_called'] is not False or value['default_CA_configured'] is not True or value['hostname_validation_configured'] is not True or value['ALPN_policy']!='http/1.1':raise ValueError('SCOPE')
 namespace=value['time_namespace']
 if type(namespace) is not dict or set(namespace)!={'dev','ino','link','boot_id_sha256'} or any(type(namespace[k]) is not int or namespace[k]<0 for k in ('dev','ino')) or type(namespace['link']) is not str or not re.fullmatch(r'time:\[[0-9]+\]',namespace['link']) or type(namespace['boot_id_sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',namespace['boot_id_sha256']):raise ValueError('NAMESPACE')
 if type(value['rows']) is not list or len(value['rows'])!=4:raise ValueError('COUNT')
 for index,row in enumerate(value['rows']):
  if type(row) is not dict or set(row)!={'attempt','status','start_ns','end_ns','diagnostic'} or type(row['attempt']) is not int or row['attempt']!=index+1 or row['status'] not in ('TLS_HANDSHAKE_PASS','TLS_HANDSHAKE_FAILED') or any(type(row[k]) is not int or not 0<=row[k]<=2**63-1 for k in ('start_ns','end_ns')) or row['start_ns']>row['end_ns']:raise ValueError('ROW')
  diagnostic=validate_io_diagnostic_v2(row['diagnostic'])
  if diagnostic['sequence']!=index or diagnostic['POST_before']!=0 or diagnostic['POST_after']!=0:raise ValueError('POST')
  first=diagnostic['first_failure']
  if (row['status']=='TLS_HANDSHAKE_PASS')!=(first is None):raise ValueError('PRIMARY')
  failures=([first] if first is not None else [])+diagnostic['cleanup_failures']
  for failure in failures:
   if failure is first and failure['phase'] not in ('TLS_SETUP','TCP_CONNECT','PROXY_CONNECT_SEND','PROXY_CONNECT_READ','TLS_HANDSHAKE','ALPN_VALIDATE'):raise ValueError('PHASE')
   if failure['monotonic_ns'] is not None and not row['start_ns']<=failure['monotonic_ns']<=row['end_ns']:raise ValueError('TIME')
  if index and row['start_ns']<value['rows'][index-1]['end_ns']:raise ValueError('TIME')
 return value

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--execute-tls-only',action='store_true');parser.add_argument('--result-dir');parser.add_argument('--binding-sha');parser.add_argument('--probe-source-sha');parser.add_argument('--unique-run');args=parser.parse_args()
 if not args.execute_tls_only:print('{"status":"NONAUTH","effects":false}');return 0
 start=time.monotonic();normal=start+60;end=start+88
 guards=contextlib.ExitStack()
 def guard(fn):
  def wrapped(path,*a,**kw):
   if isinstance(path,(str,bytes,os.PathLike)) and (os.fsdecode(path).startswith(('/gpu1-share','/run/secrets'))):raise PermissionError()
   return fn(path,*a,**kw)
  return wrapped
 from unittest.mock import patch
 for owner,name in ((builtins,'open'),(io,'open'),(os,'open'),(os,'stat'),(os,'lstat')):guards.enter_context(patch.object(owner,name,guard(getattr(owner,name))))
 try:
  global RUN,BIND_SHA
  RUN=args.unique_run;BIND_SHA=args.binding_sha
  if not (type(RUN) is str and re.fullmatch(r'cicada-two-turn-[a-z0-9]{12,32}',RUN) and type(BIND_SHA) is str and re.fullmatch('[0-9a-f]{64}',BIND_SHA) and args.probe_source_sha==sha(Path(__file__).read_bytes()) and args.result_dir):raise ValueError('SOURCE_OR_INVOCATION')
  out=Path(args.result_dir)
  if out!=Path("/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007")/("tls-only-"+RUN):raise ValueError("RESULT_PATH")
  # Binding validation is read-only and credential/effect-denied before any fixture setup.
  sys.path[:0]=[str(SCRIPTS),str(SCRIPTS/"native_observer")]
  from unittest.mock import patch
  def preguard(fn):
   def guarded(path,*a,**kw):
    if isinstance(path,(str,bytes,os.PathLike)) and os.fsdecode(path).startswith(('/gpu1-share','/run/secrets')):raise PermissionError()
    return fn(path,*a,**kw)
   return guarded
  def denied(*a,**kw):raise PermissionError()
  import socket
  with contextlib.ExitStack() as preguards:
   for owner,name in ((builtins,'open'),(io,'open'),(os,'open'),(os,'stat'),(os,'lstat')):preguards.enter_context(patch.object(owner,name,preguard(getattr(owner,name))))
   for owner,name in ((socket,'socket'),(socket,'socketpair'),(socket,'create_connection'),(socket,'getaddrinfo'),(subprocess,'run'),(subprocess,'Popen'),(os,'system')):preguards.enter_context(patch.object(owner,name,denied))
   import request_observer_run as early_run
   with early_run.deny_preflight_effects():early_run.verify_binding(BIND_SHA)
  if time.monotonic()>=normal:raise TimeoutError()
  out.mkdir(mode=0o700,parents=False);config=out/'docker-config';config.mkdir(mode=0o700)
 except BaseException:
  guards.close();raise
 cleaning=False;objects=[];adapter=None;thread=None;process=None
 result={'scope':'ZERO_CREDENTIAL_ZERO_POST_TLS_ONLY','run_id':RUN,'image':IMAGE,'status':'UNKNOWN','rows':[],
 'cleanup':[],'default_CA_configured':True,'hostname_validation_configured':True,'handshake_attempts_required':4,
 'application_POSTs':0,'origin_application_HTTP_bytes':0,'Native_sessions':0,'models':0,'route':'Runtime->effective_owned_Forwarder->127.0.0.1:7890->api.zzswitch.com:443',
 'source_before_sha256':sha(Path(__file__).read_bytes()),'runner_pid':os.getpid(),
 'runner_start_ticks':int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]),
 'exception_subtype_scope':'V2_PRIMARY_BEFORE_CLOSE_AND_SEPARATE_CLEANUP',
 'forwarder_worker_reaped':'NOT_PROVEN'}
 env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','DOCKER_CONFIG':str(config),'PYTHONDONTWRITEBYTECODE':'1'}
 def command(argv,allow=False):
  left=(end if cleaning else normal)-time.monotonic()
  if left<=0:raise TimeoutError()
  p=subprocess.run(['docker',*argv],env=env,capture_output=True,timeout=left)
  if len(p.stdout)>65536 or len(p.stderr)>65536:raise ValueError()
  if p.returncode and not allow:raise RuntimeError()
  return p
 def inspect(kind,target):
  value=json.loads(command([kind,'inspect',target]).stdout)
  if type(value) is not list or len(value)!=1:raise ValueError()
  return value[0]
 def absent(p,target,kind):
  text=p.stderr.decode(errors='replace').strip()
  return p.returncode==1 and p.stdout.strip() in (b'',b'[]') and text in (
   'Error: No such object: '+target,'error: no such object: '+target,
   'Error response from daemon: No such container: '+target,
   'Error response from daemon: network '+target+' not found','Error: No such network: '+target)
 def own(obj):
  v=inspect(obj['kind'],obj['id']);labels=v.get('Labels') if obj['kind']=='network' else v.get('Config',{}).get('Labels')
  if v.get('Id')!=obj['id'] or type(labels) is not dict or labels.get('org.cicada.test.run')!=RUN or labels.get('org.cicada.test.fixture')!=FIXTURE:raise ValueError()
  if obj['kind']=='network' and v.get('Name')!=obj['name']:raise ValueError()
  if obj['kind']=='container' and (v.get('Image')!=IMAGE or v.get('Name')!='/'+obj['name']):raise ValueError()
  return v
 def create(kind,name,argv):
  if not absent(command([kind,'inspect',name],True),name,kind):raise ValueError()
  obj={'kind':kind,'name':name,'id':None};objects.append(obj)
  ident=command(argv).stdout.decode('ascii').strip()
  if not re.fullmatch('[0-9a-f]{64}',ident):raise ValueError()
  obj['id']=ident;own(obj);return obj
 try:
  # Public pinned imports only; no Gate constructor or legacy environment setup.
  sys.path[:0]=[str(SCRIPTS),str(SCRIPTS/'native_observer')]
  import request_observer_run as run
  import request_observer_gate as gate
  binding,binding_sha=run.verify_binding(BIND_SHA)
  delivery,_=run.bounded_json(run.ACTUAL/'actual-delivery.json')
  cls,_=gate.load_gate(delivery,binding,inspect_only=True)
  forwarder=cls.provider_forwarder
  result['effective_provider_sha256']=binding['effective_sources']['provider']
  result.update(binding_sha256=binding_sha,observer_sha256=binding['public_files'][str(SCRIPTS/'native_request_observer.py')]['sha256'],selected_relay_sha256=binding['client_read_cancellation']['diagnostic_relay_sha256'],PROGRAM_sha256=sha(PROGRAM.encode()))
  observer_path=SCRIPTS/'native_request_observer.py'
  observer_sha=binding['public_files'][str(observer_path)]['sha256']
  if sha(observer_path.read_bytes())!=observer_sha:raise ValueError()
  if inspect('image',IMAGE).get('Id')!=IMAGE:raise ValueError()
  labels=['--label','org.cicada.test.run='+RUN,'--label','org.cicada.test.fixture='+FIXTURE]
  network=create('network',RUN+'-a-net',['network','create','--driver','bridge',*labels,RUN+'-a-net'])
  n=own(network)
  if n.get('Internal') is not False or n.get('Driver')!='bridge':raise ValueError()
  container=create('container',RUN+'-probe',['create','--pull=never','--network',network['id'],'--user','1000:1000','--interactive','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--cpus','1','--memory','256m','--pids-limit','64',
   '--name',RUN+'-probe',*labels,'--mount','type=bind,src='+str(observer_path)+',dst=/probe/native_request_observer.py,readonly',
   '-e','OPENSSL_CONF=/dev/null','--entrypoint','python3',IMAGE,'-u','-B','-c',PROGRAM])
  command(['start',container['id']])
  c=own(container)
  if c['State']['Running'] is not True:raise ValueError()
  process=subprocess.Popen(['docker','attach','--sig-proxy=false',container['id']],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  fixture=types.SimpleNamespace(run_id=RUN,created_networks={network['name']:network['id']},inspect=inspect,
   policy=types.SimpleNamespace(started=start),provider_adapters={},provider_threads={},provider_errors={},provider_closing=False,args=types.SimpleNamespace(test_request_observer=True))
  node={'network':network['name']};forwarder(fixture,node)
  adapter=fixture.provider_adapters[network['name']];thread=fixture.provider_threads[network['name']]
  adapter.deadline=min(adapter.deadline,normal)
  gateway,port=adapter.listener.getsockname()
  wire=json.dumps({'gateway':gateway,'port':port,'deadline':normal,'observer_sha':observer_sha}).encode()+b'\n'
  host_ns=namespace_metadata()
  bracket_before=time.monotonic_ns()
  stdout,stderr=process.communicate(wire,timeout=max(.001,normal-time.monotonic()))
  bracket_after=time.monotonic_ns()
  if process.returncode!=0 or stderr or len(stdout)>8192:raise ValueError()
  projection=json.loads(stdout)
  validate_projection(projection)
  same=projection['time_namespace']==host_ns
  bracketed=all(bracket_before<=row['start_ns']<=row['end_ns']<=bracket_after for row in projection['rows'])
  result.update(host_time_namespace=host_ns,runtime_time_namespace=projection['time_namespace'],
   host_bracket_ns=[bracket_before,bracket_after],clock_comparability='VERIFIED_SAME_NAMESPACE_BRACKET' if same and bracketed else 'NOT_VERIFIED',
   forwarder_first_fatal_io=adapter.first_fatal_io,causality='NOT_PROVEN')
  result.update(status='TLS_HANDSHAKES_ONLY_NO_APPLICATION_OR_PAID_PARITY',rows=projection['rows'],application_POSTs=0,
   accepted_forwarder_connections=adapter.accepted,forwarder_process='IN_PROCESS_OWNED_THREAD')
 except BaseException:
  result['status']='UNKNOWN'
 finally:
  cleaning=True
  if adapter is not None:
   try:adapter.close()
   except BaseException:result['forwarder_cleanup']='UNKNOWN'
  if thread is not None:
   drain_end=min(end,time.monotonic()+3)
   thread.join(max(0,drain_end-time.monotonic()))
   while adapter.active and time.monotonic()<drain_end:time.sleep(min(.05,max(0,drain_end-time.monotonic())))
   result['forwarder_thread_absent']=not thread.is_alive()
   result['forwarder_active_zero']=adapter.active==0
   result['forwarder_listener_closed']=adapter.listener is not None and adapter.listener.fileno()==-1
  for obj in reversed(objects):
   row={**obj,'absence':False}
   try:
    if obj['id'] is None:raise ValueError()
    own(obj)
    if obj['kind']=='container':command(['stop','--time','1',obj['id']],True);command(['rm',obj['id']],True)
    else:command(['network','rm',obj['id']],True)
    p=command([obj['kind'],'inspect',obj['id']],True);row.update(absence=absent(p,obj['id'],obj['kind']),inspect_exit=p.returncode,stdout_sha256=sha(p.stdout),stderr_sha256=sha(p.stderr),stdout_bytes=len(p.stdout),stderr_bytes=len(p.stderr))
   except BaseException:row['cleanup_status']='UNKNOWN'
   result['cleanup'].append(row)
  if process is not None and process.poll() is None:
   process.terminate()
   try:process.wait(timeout=max(.001,min(1,end-time.monotonic())))
   except BaseException:result['docker_attach_process']='UNKNOWN'
  result['cleanup_complete']=len(objects)==2 and all(row['absence'] for row in result['cleanup']) and result.get('forwarder_thread_absent') is True and result.get('forwarder_active_zero') is True and result.get('forwarder_listener_closed') is True
  # Snapshot after close/drain, including failures published after probe stdout.
  result['forwarder_first_fatal_io']=adapter.first_fatal_io if adapter is not None else None
  fatal=result['forwarder_first_fatal_io'];matches=[]
  if fatal is not None and fatal['client_peer_port'] is not None:
   matches=[row for row in result['rows'] if row['diagnostic']['local_tcp_port']==fatal['client_peer_port']]
  result['fatal_port_correlation']='UNIQUE_MATCH' if len(matches)==1 else 'UNKNOWN'
  result['fatal_vs_primary_recording_order']='UNKNOWN'
  result['ordering_scope']='RECORDING_POINTS_ONLY_NOT_CAUSALITY'
  if result.get('clock_comparability')=='VERIFIED_SAME_NAMESPACE_BRACKET' and len(matches)==1 and fatal['monotonic_ns'] is not None:
   failure=matches[0]['diagnostic']['first_failure']
   if failure is not None and failure['monotonic_ns'] is not None:
    left,right=fatal['monotonic_ns'],failure['monotonic_ns']
    result['fatal_vs_primary_recording_order']='BEFORE' if left<right else ('EQUAL' if left==right else 'AFTER')
  try:
   final_binding,_=early_run.verify_binding(BIND_SHA)
   result['binding_after_exact']=final_binding==binding
  except BaseException:result['binding_after_exact']=False
  result['source_after_sha256']=sha(Path(__file__).read_bytes());result['elapsed_ms']=int((time.monotonic()-start)*1000)
  if not result['binding_after_exact'] or result['source_after_sha256']!=result['source_before_sha256']:result['status']='UNKNOWN'
  private(out/'result.NONAUTH.json',result);guards.close()
 return 0 if result['status']=='TLS_HANDSHAKES_ONLY_NO_APPLICATION_OR_PAID_PARITY' and result['cleanup_complete'] else 1
if __name__=='__main__':raise SystemExit(main())
