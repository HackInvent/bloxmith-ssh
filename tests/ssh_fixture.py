"""Real disposable SSH transport and optional private agent; no host accounts or commands."""

from contextlib import contextmanager
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import threading
import time
from types import SimpleNamespace
import paramiko

REF='secret://workspace/ssh_fixture'
PASSWORD='fixture-private-password-9d41'


def fingerprint(key):
    return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


@contextmanager
def server():
    key=paramiko.RSAKey.generate(2048);client=paramiko.RSAKey.generate(2048)
    stream=io.StringIO();client.write_private_key(stream)
    api=SimpleNamespace(key=key,client_key=client,private_key=stream.getvalue(),mode='ok',
        commands=[],auth=[],channels=[],connections=0,closed=0,transports=[],release=threading.Event(),
        stdout=b'load: 0.4\ncontact=user@example.test\ntoken=fixture-token\n'+PASSWORD.encode()+b'\n',stderr=b'fixture warning\n',exit_code=0)
    class Interface(paramiko.ServerInterface):
        def __init__(self):
            self.ready=threading.Event();self.command=None
        def get_allowed_auths(self,username):
            return 'password,publickey'
        def check_auth_password(self,username,password):
            api.auth.append(('password',username))
            return paramiko.AUTH_SUCCESSFUL if username=='diagnostic' and password==PASSWORD else paramiko.AUTH_FAILED
        def check_auth_publickey(self,username,public):
            api.auth.append(('publickey',username))
            return paramiko.AUTH_SUCCESSFUL if username=='diagnostic' and public==client else paramiko.AUTH_FAILED
        def check_channel_request(self,kind,chanid):
            api.channels.append(kind)
            return paramiko.OPEN_SUCCEEDED if kind=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_exec_request(self,channel,command):
            self.command=command.decode('utf-8');api.commands.append(self.command);self.ready.set();return True
        def check_channel_pty_request(self,*args):
            raise AssertionError('The diagnostic client requested a PTY')
        def check_channel_shell_request(self,*args):
            raise AssertionError('The diagnostic client requested an interactive shell')
        def check_channel_forward_agent_request(self,*args):
            raise AssertionError('The diagnostic client requested agent forwarding')
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            api.connections+=1;transport=paramiko.Transport(self.request);api.transports.append(transport)
            try:
                transport.add_server_key(key);interface=Interface();transport.start_server(server=interface)
                channel=transport.accept(5)
                if channel is None:
                    return
                deadline=time.monotonic()+5
                while not interface.ready.wait(.02) and transport.is_active() and time.monotonic()<deadline:
                    pass
                if not interface.ready.is_set():
                    return
                if api.mode=='hold':
                    while not api.release.wait(.02) and transport.is_active():
                        pass
                if not transport.is_active():
                    return
                if api.mode=='flood':
                    channel.sendall(b'X'*524288)
                else:
                    channel.sendall(api.stdout);channel.sendall_stderr(api.stderr)
                if api.mode=='early_status':
                    channel.send_exit_status(api.exit_code);time.sleep(.1);channel.sendall(b'late-tail\n')
                channel.shutdown_write()
                if api.mode=='late_status':
                    time.sleep(.15)
                if api.mode!='missing_status':
                    channel.send_exit_status(api.exit_code)
                channel.close()
                deadline=time.monotonic()+2
                while transport.is_active() and time.monotonic()<deadline:
                    time.sleep(.01)
            except (EOFError,OSError,paramiko.SSHException):
                pass
            finally:
                transport.close();api.closed+=1
    class TCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    tcp=TCPServer(('127.0.0.1',0),Handler);api.port=tcp.server_address[1]
    thread=threading.Thread(target=tcp.serve_forever,daemon=True);thread.start()
    try:
        yield api
    finally:
        api.release.set()
        for transport in api.transports:
            transport.close()
        tcp.shutdown();tcp.server_close();thread.join(2)


def settings(api,**extra):
    return {'enabled':True,'hosts':[{'id':'fixture','hostname':'127.0.0.1','port':api.port,'username':'diagnostic',
        'host_key_sha256':fingerprint(api.key),'auth':'wallet','credential_ref':REF,
        'commands':['uptime','system','memory','processes','disk','service','journal'],
        'paths':{'root':'/','spaced':'/mnt/approved disk'},'services':['fixture.service']}],**extra}


def request(profile='uptime',**args):
    return {'request_id':'test-'+profile,'host':'fixture','command':profile,'args':args}


@contextmanager
def agent(api,directory):
    root=Path(directory);root.mkdir(exist_ok=True,parents=True)
    key=root/'ephemeral-key';api.client_key.write_private_key_file(str(key));os.chmod(key,0o600)
    sock=root/'agent.sock'
    process=subprocess.Popen(['ssh-agent','-D','-a',str(sock)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+5
        while not sock.exists() and process.poll() is None and time.monotonic()<deadline:
            time.sleep(.01)
        assert sock.exists(),'Disposable ssh-agent did not start'
        subprocess.run(['ssh-add',str(key)],env={'PATH':os.environ.get('PATH',''),'SSH_AUTH_SOCK':str(sock)},
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        yield str(sock)
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill();process.wait(timeout=2)


def password_secret(_):
    return json.dumps({'password':PASSWORD})
