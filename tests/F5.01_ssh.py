"""FB1/FB2/FB3/FB4: real SSH transport, host pin before authentication, profiles and cancellation."""

from pathlib import Path
import json
import os
import selectors
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(Path(__file__).parent)]
from blocs.ssh import logic,runner
from ssh_fixture import server,settings,request,password_secret,PASSWORD,agent,fingerprint


def refused(action):
    try:
        action()
    except logic.SshError:
        return
    raise AssertionError('Unsafe configuration or request was accepted')


def abrupt_parent_death(api,cfg):
    """A killed package host must not orphan an authenticated network helper."""
    code='''import json,sys,types
package=types.ModuleType("owned_test");package.__path__=[sys.argv[1]];sys.modules["owned_test"]=package
from owned_test import runner
payload=json.load(sys.stdin);original=runner.subprocess.Popen
def observed(*args,**kwargs):
    child=original(*args,**kwargs);print(child.pid,flush=True);return child
runner.subprocess.Popen=observed
runner.execute(payload["request"],payload["config"],lambda _:payload["secret"])
'''
    before=len(api.commands);api.mode='hold';api.release.clear()
    parent=subprocess.Popen([sys.executable,'-B','-c',code,str(Path(__file__).parents[1])],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    selector=selectors.DefaultSelector();selector.register(parent.stdout,selectors.EVENT_READ);child=None
    try:
        parent.stdin.write(json.dumps({'config':cfg,'request':request(),'secret':password_secret(None)}));parent.stdin.close()
        assert selector.select(timeout=8),'Owned SSH parent did not create its helper'
        child=int(parent.stdout.readline())
        deadline=time.monotonic()+5
        while len(api.commands)==before and time.monotonic()<deadline:
            time.sleep(.01)
        assert len(api.commands)>before
        parent.kill();parent.wait(timeout=2)
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            status=Path('/proc')/str(child)/'status'
            if not status.exists() or 'State:\tZ' in status.read_text():
                child=None;break
            time.sleep(.01)
        else:
            raise AssertionError('SSH helper survived abrupt parent death')
    finally:
        selector.close()
        if parent.poll() is None:
            parent.kill();parent.wait(timeout=2)
        if child is not None:
            try:
                os.kill(child,signal.SIGKILL)
            except ProcessLookupError:
                pass
        parent.stdout.close();api.release.set();api.mode='ok'


def main():
    for raw in ({'shell':'ls'},{'enabled':True},{'timeout_sec':1000},{'max_output_bytes':True},{'agent_socket':'relative'}):
        refused(lambda:logic.configuration(raw))
    refused(lambda:logic.document('{"host":"x","host":"y"}'))
    with server() as api:
        cfg=logic.configuration(settings(api))
        for changes in ({'hostname':'-oProxyCommand=bad'},{'username':'root'},{'host_key_sha256':'unknown'},
            {'commands':['rm']},{'services':['*.service']},{'credential_ref':'inline-password'},{'paths':{'x':'/a/../b'}}):
            refused(lambda:logic.configuration({**cfg,'hosts':[{**cfg['hosts'][0],**changes}]}))
        for item in ({**request(),'command':'rm'},{**request(),'host':'other'},
            {**request(),'shell':'id'},{**request(),'args':{'option':'--help'}},request('disk',path='/etc/shadow'),
            request('service',service='fixture.service; id'),request('journal',service='fixture.service',lines=999)):
            refused(lambda:logic.request(item,cfg))
        disabled=runner.execute(request(),{**cfg,'enabled':False},password_secret)
        assert disabled['result']['code']=='disabled' and not api.connections
        result=runner.execute(request(),cfg,password_secret)
        assert result['result']['complete'] and result['result']['exit_code']==0,result
        assert result['result']['host_key_verified'] and api.commands==['/usr/bin/uptime']
        assert PASSWORD not in json.dumps(result) and 'user@example.test' not in result['stdout'] and 'fixture-token' not in result['stdout']
        assert '[REDACTED' in result['stdout'] and result['stderr']=='fixture warning\n'
        for profile,args in (('system',{}),('memory',{}),('processes',{}),('disk',{'path':'spaced'}),
            ('service',{'service':'fixture.service'}),('journal',{'service':'fixture.service','lines':2})):
            result=runner.execute(request(profile,**args),cfg,password_secret)
            assert result['result']['complete'],result
        assert "/usr/bin/df -P -- '/mnt/approved disk'" in api.commands
        assert all(not (' -c ' in c or 'sudo' in c or ' && ' in c) for c in api.commands)
        before=len(api.auth)
        wrong={**cfg,'hosts':[{**cfg['hosts'][0],'host_key_sha256':'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}]}
        denied=runner.execute(request(),wrong,password_secret)
        assert denied['result']['code']=='host_key_mismatch' and len(api.auth)==before,denied
        bad=runner.execute(request(),cfg,lambda _:json.dumps({'password':'wrong-password'}))
        assert bad['result']['code']=='authentication_failed',bad
        refused(lambda:runner.execute(request(),cfg,lambda _:(_ for _ in ()).throw(RuntimeError('wallet locked'))))
        key_result=runner.execute(request(),cfg,lambda _:json.dumps({'private_key':api.private_key}))
        assert key_result['result']['complete'] and api.auth[-1][0]=='publickey',key_result
        # A separate local test agent contains only the generated fixture key.
        with TemporaryDirectory(prefix='ssh-agent-test-') as temporary,agent(api,temporary) as sock:
            agent_cfg={**cfg,'agent_socket':sock,'hosts':[{**cfg['hosts'][0],'auth':'agent','credential_ref':'',
                'agent_key_sha256':fingerprint(api.client_key)}]}
            result=runner.execute(request(),agent_cfg)
            assert result['result']['complete'],result
            agent_cfg['hosts'][0]['agent_key_sha256']='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            before=len(api.auth);denied=runner.execute(request(),agent_cfg)
            assert denied['result']['code']=='agent_key_unavailable' and len(api.auth)==before,denied
        for mode in ('late_status','early_status','missing_status'):
            api.mode=mode;result=runner.execute(request(),cfg,password_secret)
            assert result['result']['complete']==(mode!='missing_status'),result
            if mode=='early_status':
                assert result['stdout'].endswith('late-tail\n'),result
        api.mode='ok';api.exit_code=7
        result=runner.execute(request(),cfg,password_secret)
        assert result['result']['code']=='remote_error' and result['result']['exit_code']==7,result
        api.mode='flood';result=runner.execute(request(),{**cfg,'max_output_bytes':1024},password_secret)
        assert result['result']['code']=='output_limit' and not result['stdout'] and not result['stderr'],result
        api.mode='hold';api.release.clear();before=len(api.commands)
        result=runner.execute(request(),{**cfg,'timeout_sec':1},password_secret)
        assert result['result']['code']=='timeout' and not result['stdout'],result
        started=time.monotonic();result=runner.execute(request(),cfg,password_secret,lambda:time.monotonic()-started>.25)
        assert result['result']['code']=='cancelled' and time.monotonic()-started<2 and not result['stdout'],result
        api.release.set()
        abrupt_parent_death(api,cfg)
        deadline=time.monotonic()+3
        while api.closed<api.connections and time.monotonic()<deadline:
            time.sleep(.01)
        assert api.closed==api.connections
        assert set(api.channels)=={'session'}
    clean=logic.redact(b'\x1b[31msecret-token\x1b[0m\nAuthorization: Bearer abc\n', ['secret-token'],logic.DEFAULTS)
    assert 'secret-token' not in clean and 'Bearer abc' not in clean and '\x1b' not in clean
    print('[ok] SSH host pin before auth, wallet key/password, isolated agent, fixed profiles, redaction, limits and cancellation')


if __name__=='__main__':
    main()
