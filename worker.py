"""One killable SSH connection; pin before auth, fixed exec only, no forwarding or PTY."""

import base64
import ctypes
from importlib import metadata
import io
import logging
import os
from pathlib import Path
import resource
import signal
import socket
import sys
import time
import types
from hmac import compare_digest

package=types.ModuleType('ssh_owned');package.__path__=[str(Path(__file__).resolve().parent)]
sys.modules['ssh_owned']=package
from ssh_owned import logic


def private_key(paramiko,auth):
    for cls in (paramiko.Ed25519Key,paramiko.ECDSAKey,paramiko.RSAKey):
        try:
            key=cls.from_private_key(io.StringIO(auth['private_key']),password=auth.get('passphrase'))
            if key.get_name()=='ssh-rsa' and key.get_bits()<2048:
                logic.fail('RSA keys must have at least 2048 bits.','credentials')
            return key
        except logic.SshError:
            raise
        except (ValueError,TypeError,paramiko.SSHException):
            continue
    logic.fail('Unsupported, invalid or locked SSH private key.','credentials')


def run(envelope):
    try:
        import paramiko
        if metadata.version('paramiko')!='5.0.0':
            raise ImportError()
    except (ImportError,metadata.PackageNotFoundError):
        logic.fail('Install the pinned Paramiko 5.0.0 dependency.','dependency')
    cfg=logic.configuration(envelope['config']);item,host,command=logic.request(envelope['request'],cfg)
    if not cfg['enabled']:
        logic.fail('SSH access is disabled.','disabled')
    auth=envelope['auth'];agent=None;transport=None;channel=None;connection=None
    started=time.monotonic();deadline=started+cfg['timeout_sec']
    result={'request_id':item.get('request_id'),'host':item['host'],'command':item['command'],
        'args':item['args'],'exit_code':None,'complete':False,'executed':False,'output_discarded':False}
    def remaining():
        left=deadline-time.monotonic()
        if left<=0:
            logic.fail('SSH deadline exceeded.','timeout')
        return left
    try:
        connection=socket.create_connection((host['hostname'],host['port']),timeout=min(cfg['connect_timeout_sec'],remaining()))
        transport=paramiko.Transport(connection,default_window_size=262144,default_max_packet_size=32768,
            disabled_algorithms={'keys':['ssh-rsa'],'pubkeys':['ssh-rsa']})
        options=transport.get_security_options()
        options.kex=tuple(k for k in options.kex if k in ('curve25519-sha256@libssh.org','ecdh-sha2-nistp256',
            'ecdh-sha2-nistp384','ecdh-sha2-nistp521','diffie-hellman-group14-sha256','diffie-hellman-group16-sha512'))
        options.ciphers=tuple(c for c in options.ciphers if c in ('aes128-ctr','aes192-ctr','aes256-ctr','aes128-gcm@openssh.com','aes256-gcm@openssh.com'))
        options.digests=tuple(d for d in options.digests if d.startswith(('hmac-sha2-256','hmac-sha2-512')))
        transport.banner_timeout=transport.auth_timeout=transport.channel_timeout=min(cfg['connect_timeout_sec'],remaining())
        transport.start_client(timeout=min(cfg['connect_timeout_sec'],remaining()))
        actual=transport.get_remote_server_key()
        if not compare_digest(logic.fingerprint(actual),host['host_key_sha256']):
            logic.fail('Host key is unknown or has changed.','host_key_mismatch')
        if actual.get_name()=='ssh-rsa' and actual.get_bits()<2048:
            logic.fail('The pinned RSA host key is too small.','host_key_mismatch')
        result['host_key_verified']=True
        remaining()
        if host['auth']=='agent':
            # Only the explicit socket is visible, and only its pinned key is tried.
            os.environ['SSH_AUTH_SOCK']=envelope['agent_socket']
            agent=paramiko.Agent()
            keys=[key for key in agent.get_keys() if compare_digest(logic.fingerprint(key),host['agent_key_sha256'])]
            if len(keys)!=1:
                logic.fail('The authorized key is not available from the configured agent.','agent_key_unavailable')
            if keys[0].get_name()=='ssh-rsa' and keys[0].get_bits()<2048:
                logic.fail('The authorized agent RSA key is too small.','credentials')
            transport.auth_publickey(host['username'],keys[0])
        elif 'private_key' in auth:
            transport.auth_publickey(host['username'],private_key(paramiko,auth))
        else:
            transport.auth_password(host['username'],auth['password'],fallback=False)
        if not transport.is_authenticated():
            logic.fail('SSH authentication did not complete.','authentication_failed')
        remaining()
        channel=transport.open_session(timeout=min(cfg['connect_timeout_sec'],remaining()))
        channel.settimeout(min(cfg['connect_timeout_sec'],remaining()))
        result['executed']=None  # The server might accept an exec whose acknowledgement is lost.
        channel.exec_command(command);result['executed']=True
        channel.shutdown_write()
        output=bytearray();errors=bytearray()
        while True:
            remaining();progress=False
            for ready,receive,target in ((channel.recv_ready,channel.recv,output),(channel.recv_stderr_ready,channel.recv_stderr,errors)):
                if ready():
                    chunk=receive(16384);target.extend(chunk);progress=bool(chunk) or progress
                    if len(target)>cfg['max_output_bytes']:
                        result['output_discarded']=True
                        logic.fail('SSH output exceeded its limit; all partial text was discarded.','output_limit')
            # Exit status may precede final bytes. Wait for EOF/close and drain both
            # buffers before reading the status, never block on status ahead of data.
            if (channel.eof_received or channel.closed) and channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                code=channel.recv_exit_status()
                if code<0:
                    logic.fail('Remote command ended without an exit status.','exit_status_missing')
                result.update(exit_code=code,complete=True,code='completed' if code==0 else 'remote_error')
                result['stdout_bytes']=len(output);result['stderr_bytes']=len(errors)
                # Encode bytes only for the owned parent pipe; the parent redacts
                # before anything becomes a graph output or log.
                return {'result':result,'stdout':base64.b64encode(output).decode(),'stderr':base64.b64encode(errors).decode()}
            if not transport.is_active() and not progress:
                logic.fail('SSH connection ended before a complete result.','connection_lost')
            if not progress:
                time.sleep(.01)
    except logic.SshError as exc:
        result.update(code=exc.code,detail=str(exc))
        return {'result':result,'stdout':'','stderr':''}
    except paramiko.AuthenticationException:
        result.update(code='authentication_failed',detail='SSH authentication was refused.')
        return {'result':result,'stdout':'','stderr':''}
    except (TimeoutError,socket.timeout):
        result.update(code='timeout',detail='SSH operation timed out.')
        return {'result':result,'stdout':'','stderr':''}
    except Exception:
        result.update(code='connection_error',detail='SSH connection or remote execution was unavailable.')
        return {'result':result,'stdout':'','stderr':''}
    finally:
        result['duration_sec']=round(time.monotonic()-started,3)
        result['remote_completion_unknown']=not result['complete'] and result['executed'] is not False
        if channel:
            channel.close()
        if transport:
            transport.close()
        if connection:
            connection.close()
        if agent:
            agent.close()


def main():
    if sys.platform!='linux' or len(sys.argv)!=2:
        raise SystemExit(2)
    parent=int(sys.argv[1]);libc=ctypes.CDLL(None,use_errno=True)
    libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    libc.prctl.restype=ctypes.c_int
    if os.getppid()!=parent or libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:
        raise SystemExit(2)
    resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
    logging.disable(logging.CRITICAL)
    try:
        envelope=logic.document(sys.stdin.buffer.read(logic.MAX_JSON+1))
        answer=run(envelope)
    except Exception as exc:
        answer={'result':{'code':exc.code if isinstance(exc,logic.SshError) else 'connection_error',
            'complete':False,'executed':False,'exit_code':None},'stdout':'','stderr':''}
    sys.stdout.buffer.write(logic.encoded(answer))


if __name__=='__main__':
    main()
