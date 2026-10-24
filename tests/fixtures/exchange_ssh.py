"""Disposable Linux-only SSH transport check; all activation receipts are synthetic."""
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from unittest.mock import patch

ROOT = Path('/fixture/exchange')
SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(SOURCE));sys.path.insert(0,str(SOURCE/'deploy/postgresql'))
from tests_python import test_upgrade_activation as fixtures
import upgrade_exchange as exchange
import upgrade_activation as activation


def run(*args):
    return subprocess.run(args,check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)


def main():
    assert os.environ.get('NOISEFENCE_DISPOSABLE_EXCHANGE_TEST')=='1' and os.geteuid()==0 and Path('/.dockerenv').exists()
    ROOT.mkdir(mode=0o700)
    for name in ['client','host','wrong']:
        run('/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(ROOT/name))
    fixture=fixtures.ActivationTests();fixture.setUp()
    try:
        fixture.commit();fixture.start();report=fixture.report(fixture.a)
    finally:fixture.doCleanups()
    operation=report['operation'];proposal=activation.checked_proposal(report['proposal'],operation)
    for name,value in [('report',report),('authorization',{'protocol':exchange.PROTOCOL,'operation':operation,
            'proposal_sha256':proposal,'node':'mx1','expires_at':int(time.time())+600})]:
        (ROOT/(name+'.json')).write_text(json.dumps(value));(ROOT/(name+'.json')).chmod(0o600)
    backend=ROOT/'synthetic_agent.py'
    backend.write_text('import sys,json,contextlib\nfrom pathlib import Path\n'
        'sys.path.insert(0,'+repr(str(SOURCE/'deploy/postgresql'))+')\nimport upgrade_exchange as e\n'
        'root=Path('+repr(str(ROOT))+')\ne.AUTHORIZATION=root/"authorization.json"\n'
        'class Synthetic:\n def __init__(self,operation): pass\n def report(self):\n'
        '  with (root/"calls").open("a") as f: f.write("status\\n")\n'
        '  return json.loads((root/"report.json").read_text())\n'
        'e.activation.Activation=Synthetic\ne.reservation.operation_lock=contextlib.nullcontext\ne.serve()\n')
    backend.chmod(0o600)
    key=(ROOT/'client.pub').read_text().strip()
    (ROOT/'authorized_keys').write_text('restrict,command="/usr/bin/python3 '+str(backend)+'" '+key+'\n')
    (ROOT/'authorized_keys').chmod(0o600)
    hosts=ROOT/'known_hosts'
    def pin(name):
        public=(ROOT/(name+'.pub')).read_text().split()[:2]
        hosts.write_text(''.join('noisefence-upgrade-'+node+' '+' '.join(public)+'\n' for node in ['mx1','mx2']))
        hosts.chmod(0o600)
    pin('host')
    config=ROOT/'sshd.conf';config.write_text('\n'.join([
        'Port 2222','ListenAddress 127.0.0.1','HostKey '+str(ROOT/'host'),
        'AuthorizedKeysFile '+str(ROOT/'authorized_keys'),'PidFile '+str(ROOT/'sshd.pid'),
        'PermitRootLogin prohibit-password','PasswordAuthentication no','KbdInteractiveAuthentication no',
        'PubkeyAuthentication yes','UsePAM yes','AllowTcpForwarding no','AllowAgentForwarding no',
        'X11Forwarding no','PermitTTY no','StrictModes yes','LogLevel ERROR'])+'\n')
    Path('/run/sshd').mkdir(mode=0o755,exist_ok=True)
    cfg={'protocol':exchange.PROTOCOL,'operation':operation,'proposal_sha256':proposal,'expires_at':int(time.time())+600,
        'coordinator':'mx1','ssh_key':str(ROOT/'client'),'known_hosts':str(hosts),
        'nodes':{node:{'host':'127.0.0.1','port':2222,'user':'root'} for node in ['mx1','mx2']}}
    exchange.configuration(cfg)
    with (ROOT/'sshd.log').open('wb') as log:
        process=subprocess.Popen(['/usr/sbin/sshd','-D','-e','-f',str(config)],stderr=log,stdout=subprocess.DEVNULL,start_new_session=True)
        try:
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                try:
                    with socket.create_connection(('127.0.0.1',2222),timeout=.1):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('Disposable SSH daemon did not listen')
            assert exchange.call(cfg,'mx1','status')==report
            before=(ROOT/'calls').read_bytes()
            def refused(value=cfg,node='mx1'):
                try:exchange.call(value,node,'status')
                except (ValueError,EOFError):pass
                else:raise AssertionError('Untrusted SSH exchange accepted')
                assert (ROOT/'calls').read_bytes()==before
            pin('wrong');refused();pin('host')
            refused(cfg|{'ssh_key':str(ROOT/'wrong')})
            command=exchange.ssh_command(cfg,'mx1');command[-1]='id'
            with patch.object(exchange,'ssh_command',return_value=command):refused()
            refused(node='mx2')
            auth=json.loads((ROOT/'authorization.json').read_text());auth['expires_at']=int(time.time())-1
            (ROOT/'authorization.json').write_text(json.dumps(auth));refused()
            print(json.dumps({'status':'passed','checks':6,'transport':'real OpenSSH loopback with pinned ephemeral keys',
                'activation_backend':'synthetic status only; native completion qualification remains separate'}))
        finally:
            with contextlib.suppress(ProcessLookupError):os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()


if __name__=='__main__':main()
