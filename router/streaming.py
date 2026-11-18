"""Bounded incremental Chat Completions SSE decoding (no partial tool execution)."""
import json
import time
from .telemetry import image_markers


class ChatStream:
    def __init__(self, metric, started, max_tokens, on_event=None, stop=None):
        self.metric=metric;self.started=started;self.max_tokens=max_tokens
        self.on_event=on_event;self.stop=stop
        self.pending=b'';self.data=[];self.done=False;self.finished=False
        self.message={'role':'assistant','content':''};self.tools={};self.usage={}
        self.model='';self.finish=None;self.generated_bytes=0;self.tails={}

    def fail(self, message, kind):
        from .providers import ProviderError
        raise ProviderError(message,False,kind=kind,error_type=kind)

    def image_overflow(self):
        sample=self.pending.lower()+b''.join(self.data).lower()
        if any(marker in sample for marker in (b'data:image/',b'"images"',b'"image_url"',
                                                 b'"image_generation"',b'"type":"image')):
            self.metric.update(response_image_generation_detected=b'"image_generation"' in sample,
                               response_image_content_detected=True)
            self.fail('Unexpected image-generation tool or image content in coding response','unexpected_image')

    def add(self, field, text):
        if not isinstance(text,str):self.fail('Invalid SSE text delta','invalid_stream')
        self.generated_bytes+=len(text.encode('utf-8'))
        if isinstance(field,str):
            self.metric['decoded_text_bytes']=self.metric.get('decoded_text_bytes',0)+len(text.encode('utf-8'))
        # Independent memory ceiling when upstream ignores its token budget.
        if self.generated_bytes>self.max_tokens*4:
            self.fail('Streaming output exceeded the local byte budget','output_limit')
        tail=(self.tails.get(field,'')+text)[-8192:];self.tails[field]=tail
        for width in range(128,min(1024,len(tail)//8)+1):
            if tail.endswith(tail[-width:]*8):
                self.fail('Repeated output stopped before applying any actions','repetition')
        if text and self.metric.get('time_to_first_token_seconds') is None:
            self.metric['time_to_first_token_seconds']=round(time.monotonic()-self.started,6)

    def feed(self, block):
        self.pending+=block
        if len(self.pending)>1024*1024:
            self.image_overflow();self.fail('SSE line exceeds 1 MiB','response_too_large')
        while b'\n' in self.pending:
            line,self.pending=self.pending.split(b'\n',1);line=line.rstrip(b'\r')
            if not line:
                if self.data:self.event(b'\n'.join(self.data));self.data=[]
            elif line.startswith(b'data:'):
                self.data.append(line[5:].lstrip(b' '))
                if sum(map(len,self.data))>1024*1024:
                    self.image_overflow();self.fail('SSE event exceeds 1 MiB','response_too_large')

    def event(self, raw):
        if raw==b'[DONE]':self.done=True;return
        if self.done:self.fail('SSE data after DONE','invalid_stream')
        try:event=json.loads(raw)
        except (ValueError,UnicodeError):self.fail('Invalid SSE JSON event','invalid_stream')
        if not isinstance(event,dict):self.fail('Invalid SSE event','invalid_stream')
        if event.get('error'):
            error=event['error']
            if isinstance(error,dict) and error.get('type')=='unexpected_image':
                self.metric.update(response_image_generation_detected=True,response_image_content_detected=True)
                self.fail('Unexpected image-generation tool or image content in coding response','unexpected_image')
            kind = 'invalid_prompt' if isinstance(error, dict) and error.get('code') == 'invalid_prompt' else 'stream_error'
            self.fail('Upstream SSE error: '+str(error)[:300],kind)
        markers=image_markers(event)
        self.metric.update(response_image_generation_detected=markers['image_generation_detected'],
                           response_image_content_detected=markers['image_content_detected'])
        if any(markers.values()):
            self.fail('Unexpected image-generation tool or image content in coding response','unexpected_image')
        self.model=event.get('model',self.model)
        if event.get('usage'):
            self.usage=event['usage']
            if self.usage.get('completion_tokens',0)>self.max_tokens:
                self.fail('Upstream exceeded max_tokens','output_limit')
        for choice in event.get('choices') or []:
            if choice.get('index',0)!=0:continue
            delta=choice.get('delta') or {}
            for field in ('content','reasoning_content','refusal'):
                value=delta.get(field)
                if value is not None:
                    self.add(field,value);self.message[field]=self.message.get(field,'')+value
                    if field == 'content' and value:
                        offsets = self.metric.setdefault('sse_content_ends', [])
                        if len(offsets) < 512:
                            offsets.append(len(self.message['content']))
                        self.metric['sse_content_chars'] = len(self.message['content'])
            for call in delta.get('tool_calls') or []:
                index=call.get('index',0)
                target=self.tools.setdefault(index,{'id':'','type':'function','function':{'name':'','arguments':''}})
                if call.get('id'):target['id']=call['id']
                for field in ('name','arguments'):
                    value=(call.get('function') or {}).get(field,'')
                    if value:
                        self.add(('tool',index,field),value);target['function'][field]+=value
            if choice.get('finish_reason') is not None:
                self.finish=choice['finish_reason'];self.finished=True
        if self.on_event:self.on_event(event)

    def result(self):
        if self.pending.strip() or self.data or not self.done or not self.finished:
            self.fail('Incomplete SSE response; partial actions discarded','incomplete_stream')
        if self.tools:self.message['tool_calls']=[self.tools[k] for k in sorted(self.tools)]
        return {'model':self.model,'choices':[{'index':0,'message':self.message,'finish_reason':self.finish}],
                'usage':self.usage}
