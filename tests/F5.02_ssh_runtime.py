"""FB1/FB2/FB3/FB4/FB5: encrypted SSH, actual wallet, both runtimes and all package origins."""

import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(Path(__file__).parent)]
from blocs.ssh.block import SshBlock
from block_test_packages import install_test_package,prepare_release_run,surface_payload
from ssh_fixture import server as ssh_server,settings,request,PASSWORD
from ui_smoke_common import (isolated_server,http_json,graph_payload,text_node,data_edge,create_project_api,
    graph_storage_dir,create_run_api,wait_for_run_terminal,wait_for_run_predicate,stop_run_api)


def value(data,port):
    raw=data.get('output_values',{}).get('diagnostic:'+str(port),{}).get('value')
    return json.loads(raw) if raw and port==1 else raw or ({} if port==1 else '')


def main():
    for mode in ('centralized','zeromq_active'):
        for origin in (None,'managed','linked'):
            with ssh_server() as api,isolated_server() as server:
                node=SshBlock().build_node_payload(node_id='diagnostic',position={'x':430,'y':160},config_overrides=settings(api))
                node['outputs'].reverse()
                if origin:
                    model=install_test_package(server,'ssh',origin=origin);node['block_version']=model['version']
                    for surface in ('modal','inspector_panel','node_card'):
                        html=surface_payload(server,model,node,surface)['html']
                        assert '{{' not in html and PASSWORD not in html
                http_json(server.base_url,'/api/application/secrets/init',method='POST',payload={'password':'temporary-ssh-wallet'})
                http_json(server.base_url,'/api/application/secrets',method='POST',payload={'name':'ssh_fixture','value':json.dumps({'password':PASSWORD})})
                graph=graph_payload('Pinned SSH diagnostics',[text_node('source','Request','',60,160),node],
                    [data_edge('request','source',1,'diagnostic',1)])
                project=create_project_api(server,document=graph)['project']
                if mode=='centralized':
                    def send(obj):
                        graph['nodes'][0]['outputs'][0]['text']=json.dumps(obj)
                        (graph_storage_dir(server,project)/'graph.json').write_text(json.dumps({**graph,'graph_id':project['graph_id']}),encoding='utf-8')
                        http_json(server.base_url,f"/api/projects/{project['graph_id']}/graph/reload",method='POST',payload={})
                        run=create_run_api(server,graph,project_id=project['graph_id'],runtime_mode=mode)
                        data=wait_for_run_terminal(server,run['run_id'],timeout_sec=20)
                        assert data['status']=='success',data.get('logs')
                        assert PASSWORD not in json.dumps(data)
                        return data
                    data=send(request());assert value(data,1)['complete'],data
                    assert '[REDACTED' in value(data,2) and value(data,3)=='fixture warning\n'
                    assert api.commands==['/usr/bin/uptime']
                    before=len(api.commands);data=send({**request(),'command':'shell'})
                    assert value(data,1)['code']=='not_allowed' and len(api.commands)==before
                    assert value(data,2)==value(data,3)==''
                    http_json(server.base_url,'/api/application/secrets/lock',method='POST',payload={})
                    data=send(request());assert value(data,1)['code']=='credentials' and len(api.commands)==before
                else:
                    rid=prepare_release_run(server,project['graph_id'],graph)['run_id']
                    assert not api.connections,'Preparation authenticated'
                    http_json(server.base_url,f'/api/runs/{rid}/play',method='POST',payload={})
                    def send(obj):
                        http_json(server.base_url,f'/api/runs/{rid}/active/control',method='POST',payload={'action':'publish_output',
                            'node_id':'source','port_id':1,'value':json.dumps(obj),'content_type':'application/json'})
                    def wait(predicate):
                        data=wait_for_run_predicate(server,rid,lambda item:item.get('status')=='failed' or predicate(item),
                            'SSH request did not complete',timeout_sec=20)
                        assert data['status']!='failed',data.get('logs')
                        assert PASSWORD not in json.dumps(data)
                        return data
                    stopped=False
                    try:
                        assert not api.connections,'Play without an input authenticated'
                        send(request());data=wait(lambda data:value(data,1).get('complete'))
                        assert value(data,1)['host_key_verified'] and '[REDACTED' in value(data,2)
                        send({**request(),'command':'shell'});wait(lambda data:value(data,1).get('code')=='not_allowed')
                        assert len(api.commands)==1
                        api.mode='hold';api.release.clear();send({**request(),'request_id':'held'})
                        deadline=time.monotonic()+8
                        while len(api.commands)<2 and time.monotonic()<deadline:
                            time.sleep(.02)
                        assert len(api.commands)==2
                        started=time.monotonic();stop_run_api(server,rid)
                        ended=wait_for_run_terminal(server,rid,timeout_sec=15);stopped=True
                        assert time.monotonic()-started<8 and 'shutdown_timeout' not in str(ended.get('logs')),ended.get('logs')
                        deadline=time.monotonic()+3
                        while api.closed<api.connections and time.monotonic()<deadline:
                            time.sleep(.02)
                        assert api.closed==api.connections,'SSH connection survived actual Run Stop'
                    finally:
                        api.release.set()
                        if not stopped:
                            stop_run_api(server,rid);wait_for_run_terminal(server,rid,timeout_sec=15)
            print('[ok] SSH real transport + wallet + Stop '+mode+' '+str(origin),flush=True)


if __name__=='__main__':
    main()
