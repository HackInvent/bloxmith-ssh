"""Supervise bounded private pipes and redact all remote output before publication."""

import base64
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
from . import logic


def execute(raw,configuration,resolver=None,cancel=lambda:False):
    cfg=logic.configuration(configuration);item,host,_=logic.request(raw,cfg)
    result={'request_id':item.get('request_id'),'host':item['host'],'command':item['command'],
        'args':item['args'],'complete':False,'executed':False,'exit_code':None}
    if not cfg['enabled']:
        return {'result':{**result,'code':'disabled'},'stdout':'','stderr':''}
    if cancel():
        return {'result':{**result,'code':'cancelled'},'stdout':'','stderr':''}
    auth,agent,secrets=logic.material(cfg,host,resolver)
    payload=bytearray(logic.encoded({'config':cfg,'request':item,'auth':auth,'agent_socket':agent}))
    process=subprocess.Popen([sys.executable,'-E','-B',str(Path(__file__).with_name('worker.py')),str(os.getpid())],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,
        env={key:value for key,value in os.environ.items() if key in {'PATH','LANG','LC_ALL'}})
    selector=selectors.DefaultSelector();output=bytearray();started=time.monotonic()
    try:
        os.set_blocking(process.stdin.fileno(),False);os.set_blocking(process.stdout.fileno(),False)
        selector.register(process.stdin,selectors.EVENT_WRITE,'input');selector.register(process.stdout,selectors.EVENT_READ,'output')
        while selector.get_map():
            if cancel():
                return {'result':{**result,'code':'cancelled','duration_sec':round(time.monotonic()-started,3),
                    'executed':None,'remote_completion_unknown':True},'stdout':'','stderr':''}
            if time.monotonic()-started>cfg['timeout_sec']+1:
                return {'result':{**result,'code':'timeout','duration_sec':round(time.monotonic()-started,3),
                    'executed':None,'remote_completion_unknown':True},'stdout':'','stderr':''}
            for key,_ in selector.select(timeout=.02):
                if key.data=='input':
                    try:
                        count=os.write(key.fd,payload);del payload[:count]
                    except BlockingIOError:
                        continue
                    if not payload:
                        selector.unregister(key.fileobj);process.stdin.close()
                else:
                    chunk=os.read(key.fd,65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    output.extend(chunk)
                    if len(output)>logic.MAX_JSON:
                        logic.fail('Owned SSH response exceeded its bound.','response_limit')
        try:
            process.wait(timeout=.3)
        except subprocess.TimeoutExpired:
            logic.fail('Owned SSH process did not finish.','connection_error')
        if process.returncode:
            logic.fail('Owned SSH process ended unexpectedly.','connection_error')
        parsed=logic.document(bytes(output));summary=parsed.get('result')
        if not isinstance(summary,dict) or type(summary.get('complete')) is not bool or not isinstance(summary.get('code'),str):
            logic.fail('Invalid SSH result.','invalid_response')
        streams={}
        for name in ('stdout','stderr'):
            data=base64.b64decode(parsed[name],validate=True)
            if len(data)>cfg['max_output_bytes']:
                logic.fail('SSH response exceeded its output limit.','response_limit')
            streams[name]=logic.redact(data,secrets,cfg)
        return {'result':{**result,**summary},**streams}
    finally:
        selector.close()
        if process.poll() is None:
            process.kill();process.wait(timeout=1)
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()
