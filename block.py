"""SSH diagnostics through the framework's public execution and wallet services."""

import json
from bloxsmith_app.block_api import BlockDefinition,BlockRuntimeOutput,BlockRuntimePreparation,BlockRuntimeResult
from . import logic,runner,ui


# FB1 - Permit configured host aliases and fixed diagnostic profiles with constrained arguments only.
# FB2 - Verify the exact host key before wallet/agent authentication; never load ambient keys or SSH config.
# FB3 - Bound deadlines/output and redact credentials/control sequences before publishing complete results.
# FB4 - Close one owned connection per request, cancel locally and fence abrupt parent death.
# FB5 - Preserve both runtimes, wallet semantics and stable named ports in every package origin.
# FB6 - Translated responsive draft settings, exact JSON replacement and lossless inspector tabs.
class SshBlock(BlockDefinition):
    kind='ssh'

    def ui_assets(self,surface='modal'):
        return list(self.model.get('ui_assets',{}).get(surface,[]))

    def prepare_runtime(self,context):
        logic.configuration(context.config)
        return BlockRuntimePreparation()

    def execute_runtime(self,context):
        try:
            names={int(port.id):port.name for port in context.input_ports}
            inputs=[event.value for event in context.input_events if names.get(event.input_port_id)=='request'] if context.input_events else [
                context.input_value('request','1')] if context.has_input_value('request','1') else []
            if not inputs:
                return BlockRuntimeResult(status='skipped',outputs=[])
            if len(inputs)!=1 or context.input_events and len(inputs)!=len(context.input_events):
                logic.fail('Send one SSH diagnostic request per activation.')
            values=runner.execute(inputs[0],context.config,context.services.get('resolve_secret'),
                context.services.get('cancel_requested',lambda:False))
        except (ValueError,TypeError,OSError,RuntimeError) as exc:
            values={'result':{'code':exc.code if isinstance(exc,logic.SshError) else 'unavailable',
                'detail':str(exc) if isinstance(exc,logic.SshError) else 'SSH diagnostic is unavailable.',
                'complete':False,'executed':False,'exit_code':None},'stdout':'','stderr':''}
        outputs=[BlockRuntimeOutput(port_id=int(port.id),port_name=port.name,
            value=json.dumps(values[port.name],ensure_ascii=True,allow_nan=False) if port.name=='result' else values[port.name],
            content_type='application/json' if port.name=='result' else 'text/plain')
            for port in context.output_ports if port.name in values]
        return BlockRuntimeResult(status='success',outputs=outputs,metadata={'ssh':values['result']},
            logs=['[ssh] '+values['result']['code']])

    def handle_ui_action(self,*,node,action,values,payload=None):
        if action in {'save_settings','modal_update_fields','inspector_update_fields'}:
            patch=(values or {}).get('node_patch') or {}
            if 'config' in patch:
                try:
                    logic.configuration({**self.default_config(),**(node.get('config') or {}),**patch['config']})
                except (ValueError,TypeError) as exc:
                    return {'error':self.translate('block.ssh.error',{'detail':str(exc)},fallback='Invalid settings: {detail}')}
        return ui.replace_config(super().handle_ui_action(node=node,
            action='modal_update_fields' if action=='save_settings' else action,values=values,payload=payload),node)

    def render_modal(self,*,node,payload=None):
        return ui.modal(self,node,payload)

    def render_inspector_panel(self,*,node,payload=None):
        return ui.inspector(self,node,payload)

    def render_node_card(self,*,node,payload=None):
        cfg={**self.default_config(),**(node.get('config') or {})}
        key='enabled' if cfg['enabled'] else 'disabled'
        return ui.card(self,node,self.translate('block.ssh.'+key,fallback=key)+' · '+str(len(cfg['hosts'])))
