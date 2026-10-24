"""Install, upgrade and remove the service in a disposable network-free systemd container.

The image must be the separately built lifecycle fixture; no host paths are mounted.
Uses synthetic mail only. Never point this at a production container or data volume.
"""
import argparse,hashlib,json,os,re,subprocess,sys,time,uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'deploy/postgresql'))
from release_version import VERSION, valid as valid_version, precedence
sys.path.pop(0)
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--old-archive',type=Path,required=True)
parser.add_argument('--new-archive',type=Path,required=True)
parser.add_argument('--image',required=True)
parser.add_argument('--platform',choices=['linux/amd64','linux/arm64'],required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
ROOT=args.output.resolve()
ROOT.mkdir(mode=0o700,parents=True,exist_ok=False)
os.umask(0o077)
archives={}
for archive in [args.old_archive,args.new_archive]:
 match=re.fullmatch(rf'noisefence-({VERSION})-linux-(amd64|arm64)\.tar\.gz',archive.name)
 if not match or not valid_version(match[1]) or 'linux/'+match[2] != args.platform:raise ValueError('Archive must match the selected platform and release naming')
 archives[match[1]]=archive.resolve()
if len(archives)!=2:raise ValueError('Supply two distinct compatible releases, oldest first')
versions=list(archives)
if precedence(versions[0]) >= precedence(versions[1]):raise ValueError('The new release must be newer')
metadata=json.loads(subprocess.check_output(['docker','image','inspect',args.image]))[0]
if metadata['Config'].get('Labels',{}).get('org.noisefence.test-fixture')!='release-lifecycle':raise ValueError('Build tests/fixtures/lifecycle.Dockerfile first')
name='nf-lifecycle-'+uuid.uuid4().hex[:12]
def run(*args,timeout=90):
 return subprocess.check_output(['docker',*args],timeout=timeout,stderr=subprocess.STDOUT)
started=time.monotonic();checks=[];report=None
try:
 run('run','-d','--name',name,'--hostname','test-lifecycle','--platform',args.platform,'--network','none','--cgroupns','private','--privileged','--cpus','2','--memory','1536m','--pids-limit','256','--tmpfs','/run','--tmpfs','/tmp',args.image)
 for version in versions:
  archive=archives[version]
  expected=Path(str(archive)+'.sha256').read_text().split()[0]
  assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
  run('cp',str(archive),name+':/root/release-'+version+'.tar.gz')
  run('exec',name,'tar','-xzf','/root/release-'+version+'.tar.gz','-C','/root')
 config=Path(__file__).resolve().parents[1]/'config/docker.example.toml'
 run('cp',str(config),name+':/root/initial.toml')
 # The image is a synthetic lab template. Refuse to touch any preconfigured service.
 run('exec',name,'sh','-ec','test ! -e /etc/noisefence/config.toml; test ! -e /var/lib/noisefence/state.sqlite3')
 old='/root/'+archives[versions[0]].name.removesuffix('.tar.gz')
 new='/root/'+archives[versions[1]].name.removesuffix('.tar.gz')
 run('exec',name,'sh',old+'/deploy/install.sh',old,'/root/initial.toml')
 checks.append('fresh_install_'+versions[0])
 probe=r"""import json,time,urllib.request
for i in range(40):
 try:
  with urllib.request.urlopen('http://127.0.0.1:18080/healthz',timeout=2) as r: x=json.load(r)
  assert x['smtp_ready'];break
 except Exception: time.sleep(.5)
else: raise RuntimeError('No SMTP readiness')
print(json.dumps(x))
"""
 run('exec',name,'python3','-c',probe)
 submit=r"""import smtplib,sqlite3,json,hashlib
from pathlib import Path
with smtplib.SMTP('127.0.0.1',2525,timeout=30) as c:
 c.sendmail('sender@example.test',['alice@example.test'],b'From: sender@example.test\r\nTo: alice@example.test\r\nSubject: Synthetic lifecycle fixture\r\n\r\nNo external delivery.\r\n')
with sqlite3.connect('file:/var/lib/noisefence/state.sqlite3?mode=ro',uri=True) as db:
 rows=db.execute('select id from messages').fetchall();assert len(rows)==1
 Path('/root/accepted.json').write_text(json.dumps({'rows':rows,'digests':{id:hashlib.sha256((Path('/var/lib/noisefence/spool')/(id+'.eml')).read_bytes()).hexdigest() for (id,) in rows}}))
"""
 run('exec',name,'python3','-c',submit);checks.append('synthetic_smtp_acceptance')
 before=run('exec',name,'sha256sum','/etc/noisefence/config.toml')
 run('exec',name,'sh',new+'/deploy/install.sh',new)
 checks.append('upgrade_'+versions[1]);run('exec',name,'python3','-c',probe)
 assert run('exec',name,'sha256sum','/etc/noisefence/config.toml')==before
 run('exec',name,'sh',new+'/deploy/install.sh',new)
 checks.append('idempotent_reinstall')
 run('exec',name,'systemctl','disable','--now','noisefence.service')
 run('exec',name,'python3','-c',r"""import sqlite3,json,socket,hashlib
from pathlib import Path
with sqlite3.connect('file:/var/lib/noisefence/state.sqlite3?mode=ro',uri=True) as db:
 rows=db.execute('select id from messages').fetchall()
 saved=json.loads(Path('/root/accepted.json').read_text())
 assert [list(r) for r in rows]==saved['rows']
 for (id,) in rows: assert hashlib.sha256((Path('/var/lib/noisefence/spool')/(id+'.eml')).read_bytes()).hexdigest()==saved['digests'][id]
with socket.socket() as s:
 s.settimeout(1);assert s.connect_ex(('127.0.0.1',2525))!=0
""")
 checks.append('stopped_service_preserves_accepted_body_and_queue')
 run('exec',name,'rm','/etc/systemd/system/noisefence.service')
 run('exec',name,'systemctl','daemon-reload')
 checks.append('unit_removed_data_retained')
 report={'status':'validated_pending_cleanup','cleanup':False,'checks':checks,'elapsed_seconds':round(time.monotonic()-started,3),'network':'none','production_affected':False,'versions':versions,'image_id':metadata['Id'],'platform':args.platform,'archive_sha256':{version:hashlib.sha256(path.read_bytes()).hexdigest() for version,path in archives.items()}}
 (ROOT/'lifecycle-report.json').write_text(json.dumps(report,indent=2)+'\n')
except subprocess.CalledProcessError as e:
 (ROOT/'lifecycle-failure.log').write_bytes(e.output)
 try:(ROOT/'lifecycle-journal.log').write_bytes(run('exec',name,'journalctl','-u','noisefence','--no-pager','-n','50'))
 except Exception:pass
 print(json.dumps({'status':'failed','checks':checks,'log':str(ROOT/'lifecycle-failure.log')}),flush=True)
 raise
finally:
 try:
  run('rm','--force','--volumes',name)
 except BaseException:
  if report is not None:
   report.update(status='cleanup_failed',cleanup=False)
   (ROOT/'lifecycle-report.json').write_text(json.dumps(report,indent=2)+'\n')
  raise
# Successful checks alone do not prove that the disposable resources were removed.
report.update(status='passed',cleanup=True)
(ROOT/'lifecycle-report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)
