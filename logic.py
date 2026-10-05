"""Allowlisted Linux diagnostics, explicit SSH identities and bounded output redaction."""

from collections.abc import Mapping
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import PurePosixPath
import re
import shlex
import stat

MAX_JSON=4194304
DEFAULTS={"enabled":False,"hosts":[],"timeout_sec":30,"connect_timeout_sec":10,
    "max_output_bytes":131072,"agent_socket":"","redact_emails":True,"redact_secret_refs":[]}
PROFILES=("system","uptime","memory","disk","processes","service","journal")


class SshError(ValueError):
    def __init__(self,detail,code="invalid_request"):
        super().__init__(detail);self.code=code


def fail(detail,code="invalid_request"):
    raise SshError(detail,code)


def plain(value,depth=0):
    if depth>24:
        fail("JSON nesting is too deep.")
    if isinstance(value,Mapping):
        if any(not isinstance(k,str) for k in value):
            fail("JSON object keys must be strings.")
        return {k:plain(v,depth+1) for k,v in value.items()}
    if isinstance(value,(list,tuple)):
        return [plain(v,depth+1) for v in value]
    return value


def encoded(value):
    try:
        raw=json.dumps(plain(value),ensure_ascii=True,allow_nan=False,separators=(",",":")).encode()
        if len(raw)>MAX_JSON:
            raise ValueError()
        return raw
    except (ValueError,TypeError,UnicodeError,RecursionError):
        fail("Expected bounded finite JSON.")


def document(value):
    if isinstance(value,Mapping):
        value=encoded(value)
    if isinstance(value,str):
        value=value.encode('utf-8',errors='strict')
    if not isinstance(value,bytes) or len(value)>MAX_JSON:
        fail("Expected one bounded JSON object.")
    def pairs(items):
        result={}
        for key,item in items:
            if key in result:
                fail("Duplicate JSON key.")
            result[key]=item
        return result
    try:
        parsed=json.loads(value,object_pairs_hook=pairs,parse_constant=lambda _:fail("Finite JSON required."))
        if not isinstance(parsed,dict):
            raise ValueError()
        return plain(parsed)
    except (ValueError,TypeError,RecursionError,UnicodeError):
        fail("Expected one JSON object without duplicate keys.")


def text(value,maximum=512,empty=False):
    if not isinstance(value,str) or len(value)>maximum or not value and not empty or any(ord(c)<32 for c in value):
        fail("Expected bounded text without control characters.")
    return value


def ident(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',value):
        fail("Identifiers must contain 1–64 ASCII letters, digits, dots, underscores or hyphens.")
    return value


def integer(value,minimum,maximum):
    if type(value) is not int or not minimum<=value<=maximum:
        fail(f"Expected an integer between {minimum} and {maximum}.")
    return value


def pin(value):
    if not isinstance(value,str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',value):
        fail("Use an explicit OpenSSH SHA256 fingerprint, without padding.")
    try:
        raw=base64.b64decode(value[7:]+'=',validate=True)
        if len(raw)!=32 or 'SHA256:'+base64.b64encode(raw).decode().rstrip('=')!=value:
            raise ValueError()
    except ValueError:
        fail("Invalid SHA256 fingerprint.")
    return value


def fingerprint(key):
    return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def configuration(raw):
    if not isinstance(raw,Mapping) or set(raw)-set(DEFAULTS)-{'execution','runtime_path','runtime_path_label'}:
        fail("Unknown SSH setting. Free shell commands and inline credentials are not supported.")
    cfg=plain({**DEFAULTS,**{k:v for k,v in raw.items() if k in DEFAULTS}})
    if type(cfg['enabled']) is not bool or type(cfg['redact_emails']) is not bool:
        fail("Enable and redaction settings must be booleans.")
    integer(cfg['timeout_sec'],1,120);integer(cfg['connect_timeout_sec'],1,30)
    integer(cfg['max_output_bytes'],1024,262144)
    text(cfg['agent_socket'],4096,True)
    if cfg['agent_socket'] and not cfg['agent_socket'].startswith('/'):
        fail("Agent socket must be an absolute path, or empty to use the explicitly authorized system agent.")
    refs=cfg['redact_secret_refs']
    if not isinstance(refs,list) or len(refs)>8 or any(not isinstance(ref,str) or not ref.startswith('secret://') or len(ref)>512 for ref in refs):
        fail("Redaction secrets must be an array of up to eight wallet references.")
    hosts=cfg['hosts']
    if not isinstance(hosts,list) or len(hosts)>16:
        fail("Configure up to 16 explicit host aliases.")
    seen=set();normalized=[]
    for item in hosts:
        if not isinstance(item,dict) or set(item)-{'id','hostname','port','username','host_key_sha256','auth','credential_ref','agent_key_sha256','commands','paths','services'}:
            fail("Invalid host fields; no proxy, forwarding or arbitrary executable settings.")
        host={'port':22,'auth':'wallet','credential_ref':'','agent_key_sha256':'','commands':[], 'paths':{},'services':[],**item}
        ident(host.get('id'))
        if host['id'] in seen:
            fail("Host aliases must be distinct.")
        seen.add(host['id']);name=text(host.get('hostname'),253)
        try:
            ipaddress.ip_address(name)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',name) or any(not label or len(label)>63 or label.startswith('-') or label.endswith('-') for label in name.split('.')):
                fail("Use a literal IP address or DNS hostname, not an SSH URI or option.")
        integer(host['port'],1,65535)
        user=text(host.get('username'),64)
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',user) or user=='root':
            fail("Configure an explicit non-root diagnostic account.")
        pin(host.get('host_key_sha256'))
        if host['auth'] not in ('wallet','agent'):
            fail("Authentication is wallet or an explicitly authorized agent key.")
        reference=text(host['credential_ref'],512,True)
        if host['auth']=='wallet':
            if not reference.startswith('secret://') or host['agent_key_sha256']:
                fail("Wallet authentication requires only its secret reference.")
        elif reference or not pin(host['agent_key_sha256']):
            fail("Agent authentication requires its exact key fingerprint and no wallet credential reference.")
        commands=host['commands']
        if not isinstance(commands,list) or any(not isinstance(v,str) or v not in PROFILES for v in commands) or len(set(commands))!=len(commands):
            fail("Select distinct supported diagnostic profile IDs.")
        paths=host['paths']
        if not isinstance(paths,dict) or len(paths)>16:
            fail("Configure up to 16 named filesystem paths.")
        for name,path in paths.items():
            ident(name);text(path,1024)
            if not path.startswith('/') or '..' in PurePosixPath(path).parts:
                fail("Approved filesystem paths must be absolute and contain no parent traversal.")
        services=host['services']
        if not isinstance(services,list) or len(services)>32 or any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,126}\.service',v) for v in services):
            fail("Configure explicit .service names; patterns and shell characters are refused.")
        normalized.append(host)
    if cfg['enabled'] and not hosts:
        fail("Configure an approved host before enabling SSH.")
    cfg['hosts']=normalized;encoded(cfg)
    return cfg


def request(raw,cfg):
    item=document(raw)
    if set(item)-{'request_id','host','command','args'} or not {'host','command'}<=set(item):
        fail("Supply host alias, command profile, optional request_id and controlled args only.")
    if 'request_id' in item:
        ident(item['request_id'])
    ident(item['host']);ident(item['command'])
    host=next((host for host in cfg['hosts'] if host['id']==item['host']),None)
    if host is None or item['command'] not in host['commands']:
        fail("Host or diagnostic profile is not permitted.","not_allowed")
    args=item.get('args',{})
    if not isinstance(args,dict):
        fail("args must be a JSON object.")
    command=item['command']
    simple={'system':['/usr/bin/uname','-s','-r','-m'],'uptime':['/usr/bin/uptime'],
        'memory':['/usr/bin/free','-b'],'processes':['/usr/bin/ps','-eo','pid,ppid,stat,comm']}
    if command in simple:
        if args:
            fail("This diagnostic does not accept arguments.")
        argv=simple[command]
    elif command=='disk':
        if set(args)!={'path'} or not isinstance(args['path'],str) or args['path'] not in host['paths']:
            fail("Disk diagnostics require an approved path alias.")
        argv=['/usr/bin/df','-P','--',host['paths'][args['path']]]
    else:
        if set(args)-({'service','lines'} if command=='journal' else {'service'}) or args.get('service') not in host['services']:
            fail("Choose an explicitly permitted service name.")
        if command=='service':
            argv=['/usr/bin/systemctl','--no-pager','--plain','show','--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus','--',args['service']]
        else:
            lines=integer(args.get('lines',50),1,200)
            argv=['/usr/bin/journalctl','--no-pager','--output=short-iso','--lines='+str(lines),'--unit='+args['service']]
    # SSH exec transports a command string. Quote every fixed/allowlisted argument,
    # never interpolate an input command, environment, option or shell fragment.
    return {**item,'args':args},host,shlex.join(argv)


def material(cfg,host,resolver):
    secrets=[];auth=None;agent=''
    try:
        if host['auth']=='wallet':
            auth=document(resolver(host['credential_ref']))
            if set(auth) not in ({'password'},{'private_key'},{'private_key','passphrase'}):
                raise ValueError()
            if any(not isinstance(v,str) or not v or len(v)>32768 for v in auth.values()):
                raise ValueError()
            if 'private_key' in auth and not auth['private_key'].startswith('-----BEGIN '):
                raise ValueError()
            secrets.extend(auth.values())
        else:
            agent=cfg['agent_socket'] or os.environ.get('SSH_AUTH_SOCK','')
            if not agent or not agent.startswith('/'):
                fail("The authorized SSH agent socket is unavailable.","agent_unavailable")
            info=os.lstat(agent)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=os.getuid():
                fail("Agent socket must belong to the runtime user and must not be a symlink.","agent_unavailable")
        for ref in cfg['redact_secret_refs']:
            value=resolver(ref)
            if not isinstance(value,str) or not value or len(value)>4096:
                raise ValueError()
            secrets.append(value)
    except SshError as exc:
        if exc.code=='agent_unavailable':
            raise
        fail("Unlock the wallet and check SSH/redaction secret JSON.","credentials")
    except Exception:
        fail("Unlock the wallet and check SSH/redaction credentials.","credentials")
    return auth,agent,secrets


def redact(raw,secrets,cfg):
    """Bounded final text filtering, not a universal anonymization guarantee."""
    value=raw.decode('utf-8',errors='replace') if isinstance(raw,bytes) else str(raw)
    value=re.sub(r'\x1b(?:\][^\x07]*(?:\x07|$)|\[[0-?]*[ -/]*[@-~])','',value)
    value=''.join(c for c in value if ord(c)>=32 or c in '\n\t')
    for secret in sorted(set(secrets),key=len,reverse=True):
        clean=''.join(c for c in secret if ord(c)>=32 or c in '\n\t')
        if clean:
            value=value.replace(clean,'[REDACTED]')
    value=re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)','[REDACTED PRIVATE KEY]',value,flags=re.S)
    value=re.sub(r'(?im)\b(?:password|passwd|token|api[_-]?key|secret|authorization)\b["\x27]?\s*[:=]\s*[^\n]*','[REDACTED CREDENTIAL FIELD]',value)
    if cfg['redact_emails']:
        value=re.sub(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}','[REDACTED EMAIL]',value)
    return value
