"""Real native completion exchange on disposable paired systemd installations."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, '/usr/local/libexec/noisefence-management')
import upgrade_activation as activation
import upgrade_exchange as exchange
from migration_protocol import Channel, atomic, canonical, identity, require

PRIVATE = Path('/root/paired-test')
FOLDER = Path('/etc/noisefence-upgrade')
HELPER = '/usr/local/libexec/noisefence-management/upgrade_exchange.py'


def command(*args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=15)


def prepare(node, operation):
    require(identity(operation), 'Invalid synthetic operation')
    report = activation.Activation(operation).report()
    require(report['node'] == node and report['phase'] == 'started', 'Actual started activation required')
    FOLDER.mkdir(mode=0o700, exist_ok=False)
    command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(FOLDER/'host'))
    if node == 'mx1':
        command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(FOLDER/'identity'))
    auth = {'protocol': exchange.PROTOCOL, 'operation': operation, 'node': node,
            'proposal_sha256': activation.checked_proposal(report['proposal'], operation),
            'expires_at': int(time.time())+600}
    atomic(FOLDER/'exchange.json', canonical(auth))
    return {'node': node, 'host_key': (FOLDER/'host.pub').read_text().strip(),
            'client_key': (FOLDER/'identity.pub').read_text().strip() if node == 'mx1' else None,
            'authorization': auth}



def retire(node, operation):
    """Retire only this completed synthetic authorization before another operation."""
    require(identity(operation), 'Invalid synthetic operation')
    report = activation.Activation(operation).report()
    require(report['node'] == node and report['phase'] == 'complete',
            'Complete the actual native exchange before retiring its authorization')
    require(FOLDER.is_dir() and not FOLDER.is_symlink(), 'Missing fixture authorization directory')
    authorization = json.loads((FOLDER/'exchange.json').read_text())
    require(authorization.get('protocol') == exchange.PROTOCOL
            and authorization.get('operation') == operation and authorization.get('node') == node,
            'Do not retire another operation authorization')
    retained = PRIVATE/('completed-exchange-'+operation)
    require(not retained.exists() and not retained.is_symlink()
            and not (PRIVATE/'drop-next-completion').exists(),
            'Pending fault or already retired fixture authorization')
    command('systemctl', 'stop', 'paired-upgrade-ssh.service')
    FOLDER.rename(retained)
    return {'node': node, 'operation': operation, 'phase': 'retired'}


def setup(node):
    public = (PRIVATE/'exchange-controller.pub').read_text().strip()
    require(public.startswith('ssh-ed25519 ') and '\n' not in public, 'Invalid temporary client key')
    # The test-only proxy executes the real installed agent and discards exactly
    # one response AFTER the real coordinator has persisted completion.
    forced = '/usr/bin/python3 /root/source/tests/fixtures/exchange_node.py proxy'
    atomic(FOLDER/'authorized_keys', ('restrict,command="'+forced+'" '+public+'\n').encode())
    port = 2221 if node == 'mx1' else 2222
    config = ('ListenAddress 127.0.0.1\nPort '+str(port)+'\nPasswordAuthentication no\n'
              'KbdInteractiveAuthentication no\nPermitRootLogin forced-commands-only\nUsePAM yes\n'
              'AllowUsers root\nDisableForwarding yes\nPermitTTY no\nStrictModes yes\n'
              'SetEnv NOISEFENCE_DISPOSABLE_PAIRED_TEST=1\n'
              'HostKey /etc/noisefence-upgrade/host\nAuthorizedKeysFile /etc/noisefence-upgrade/authorized_keys\n')
    atomic(FOLDER/'sshd.conf', config.encode())
    unit = ('[Unit]\nDescription=Disposable native upgrade proof exchange\n[Service]\n'
            'ExecStartPre=/usr/bin/mkdir -p /run/sshd\n'
            'ExecStart=/usr/sbin/sshd -D -e -f /etc/noisefence-upgrade/sshd.conf\n')
    Path('/etc/systemd/system/paired-upgrade-ssh.service').write_text(unit)
    command('systemctl', 'daemon-reload'); command('systemctl', 'start', 'paired-upgrade-ssh.service')
    if node == 'mx1': atomic(PRIVATE/'drop-next-completion', b'synthetic fault\n')
    return {'node': node, 'port': port, 'real_agent': HELPER}


def proxy():
    require(os.environ.get('SSH_ORIGINAL_COMMAND') == exchange.COMMAND, 'Unexpected SSH command')
    outer = Channel(sys.stdin.fileno(), sys.stdout.fileno(), time.monotonic()+120)
    request = exchange.receive(outer)
    process = subprocess.Popen(['/usr/bin/python3', HELPER, 'serve'], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        inner = Channel(process.stdout.fileno(), process.stdin.fileno(), time.monotonic()+120)
        exchange.send(inner, request); process.stdin.close()
        response = exchange.receive(inner)
        require(process.wait(timeout=5) == 0, 'Native agent failed')
        flag = PRIVATE/'drop-next-completion'
        if request['action'] == 'finish' and flag.exists():
            require(response['result']['phase'] == 'complete', 'Fault must follow actual durable completion')
            atomic(PRIVATE/'discarded-completion.json', canonical(response))
            flag.unlink()
            # No response bytes reach SSH, although the actual native operation
            # completed. The caller must recover from server receipts alone.
            raise SystemExit(74)
        exchange.send(outer,response)
    finally:
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError): os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        process.stdout.close(); process.stderr.close()
        if not process.stdin.closed: process.stdin.close()


def main():
    require(os.geteuid()==0 and Path('/.dockerenv').exists()
            and os.environ.get('NOISEFENCE_DISPOSABLE_PAIRED_TEST')=='1'
            and Path('/run/systemd/container').read_text().strip()=='docker', 'Disposable paired container required')
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['prepare','setup','retire','proxy'])
    parser.add_argument('--node',choices=['mx1','mx2']);parser.add_argument('--operation')
    args=parser.parse_args()
    if args.action=='proxy':
        require(args.node is None and args.operation is None,'Unexpected proxy arguments');proxy();return
    require(args.node is not None and json.loads((PRIVATE/'identity.json').read_text())['node']==args.node,
            'Unexpected fixture node')
    require((args.operation is not None) == (args.action in ('prepare','retire')), 'Unexpected fixture operation')
    result=(prepare(args.node,args.operation) if args.action=='prepare' else
            retire(args.node,args.operation) if args.action=='retire' else setup(args.node))
    print(json.dumps(result))


if __name__=='__main__':main()
