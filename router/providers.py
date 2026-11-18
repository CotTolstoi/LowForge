"""Small OpenAI-compatible transport; local servers need no API key."""
import json
import math
import hashlib
import email.utils
import http.client
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from .telemetry import image_markers, request_fields, response_fields


class Cancelled(Exception):
    pass


class ProviderError(Exception):
    def __init__(self, message, retryable=True, cooldown=0, kind='provider', status_code=None,
                 error_type=None, elapsed_seconds=None):
        super().__init__(message)
        self.retryable, self.cooldown = retryable, cooldown
        self.kind = kind
        self.status_code=status_code
        self.error_type=error_type or kind
        self.retry_after=cooldown
        self.elapsed_seconds=elapsed_seconds


def json_failure_shape(error, response_text=None, metric=None):
    """Describe a JSON parse failure without retaining response contents."""
    result = {'position': error.pos, 'trailing_kind': 'none', 'trailing_values': 0}
    if error.msg != 'Extra data':
        return result
    if isinstance(response_text, str) and metric:
        start = response_text.find(error.doc)
        offsets = metric.get('sse_content_ends', [])
        if (start >= 0 and response_text.find(error.doc, start + 1) < 0
                and metric.get('sse_content_chars') == len(response_text) and offsets):
            offset = start + error.pos
            result['sse_content_offset'] = offset
            result['sse_boundary'] = (
                'at_event_boundary' if offset in offsets else
                'inside_event' if offset < offsets[-1] else 'outside_tracked_events'
            )
    decoder = json.JSONDecoder()
    try:
        first, _ = decoder.raw_decode(error.doc, len(error.doc) - len(error.doc.lstrip()))
    except (ValueError, RecursionError):
        result['trailing_kind'] = 'unclassified'
        return result
    kinds = set()
    cursor = error.pos
    for _ in range(8):
        while cursor < len(error.doc) and error.doc[cursor] in ' \t\r\n':
            cursor += 1
        if cursor == len(error.doc):
            break
        try:
            value, cursor = decoder.raw_decode(error.doc, cursor)
        except (ValueError, RecursionError):
            kinds.add('non_json')
            break
        result['trailing_values'] += 1
        if isinstance(value, dict):
            kinds.add('duplicate_object' if isinstance(first, dict) and value == first else 'different_object')
        else:
            kinds.add('other_json_value')
    result['trailing_kind'] = '+'.join(sorted(kinds)) or 'unclassified'
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _TimedHTTPConnection(http.client.HTTPConnection):
    """Keep connect bounded while allowing a longer model-response read timeout."""
    connect_timeout=8
    def __init__(self,*args,connect_timeout=8,**kwargs):
        self.connect_timeout=connect_timeout
        super().__init__(*args,**kwargs)
    def connect(self):
        read_timeout=self.timeout
        self.timeout=min(self.connect_timeout,read_timeout or self.connect_timeout)
        try:super().connect()
        except (TimeoutError,socket.timeout) as error:
            error.lowforge_phase='connect';raise
        finally:
            self.timeout=read_timeout
            if self.sock:self.sock.settimeout(read_timeout)


class _TimedHTTPSConnection(http.client.HTTPSConnection):
    connect_timeout=8
    def __init__(self,*args,connect_timeout=8,**kwargs):
        self.connect_timeout=connect_timeout
        super().__init__(*args,**kwargs)
    def connect(self):
        read_timeout=self.timeout
        self.timeout=min(self.connect_timeout,read_timeout or self.connect_timeout)
        try:super().connect()  # Includes TCP connect and TLS handshake.
        except (TimeoutError,socket.timeout) as error:
            error.lowforge_phase='connect';raise
        finally:
            self.timeout=read_timeout
            if self.sock:self.sock.settimeout(read_timeout)


class _TimedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self,connect_timeout):
        super().__init__();self.connect_timeout=connect_timeout
    def http_open(self,req):
        return self.do_open(_TimedHTTPConnection,req,connect_timeout=self.connect_timeout)


class _TimedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self,connect_timeout,context=None):
        super().__init__(context=context);self.connect_timeout=connect_timeout
    def https_open(self,req):
        return self.do_open(_TimedHTTPSConnection,req,connect_timeout=self.connect_timeout,
                            context=self._context)


def _retry_after_seconds(value):
    value=str(value or '').strip()
    if value.isdigit():return min(86400,int(value))
    try:
        date=email.utils.parsedate_to_datetime(value)
        return max(0,min(86400,int(date.timestamp()-time.time())))
    except (TypeError,ValueError,OverflowError):return 0


def _network_error_kind(error):
    if isinstance(error,(TimeoutError,socket.timeout)):return 'timeout'
    if isinstance(error,ssl.SSLError):return 'tls'
    if isinstance(error,socket.gaierror):return 'dns'
    if isinstance(error,ConnectionResetError):return 'connection_reset'
    if isinstance(error,urllib.error.URLError):
        return _network_error_kind(error.reason) if isinstance(error.reason,BaseException) else 'connection'
    if isinstance(error,OSError):return 'connection'
    return type(error).__name__.lower()


def normalize_base(value, allow_insecure_http=False):
    value = str(value).strip().rstrip('/')
    url = urllib.parse.urlsplit(value)
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Base URL: потрібна адреса http(s) без пароля, query та fragment')
    if url.scheme == 'http' and url.hostname not in ('localhost', '127.0.0.1', '::1') and not allow_insecure_http:
        raise ValueError('HTTP дозволено для localhost; для віддаленого API використайте HTTPS')
    if not url.path:
        value += '/v1'
    if value.endswith(('/chat/completions', '/models', '/responses')):
        raise ValueError('Вкажіть Base URL, зазвичай http://127.0.0.1:1234/v1')
    return value


def validate_model(data):
    if not isinstance(data, dict):
        raise ValueError('Некоректний профіль')
    name, model = str(data.get('name', '')).strip(), str(data.get('model', '')).strip()
    if not name or not model or len(name) > 120 or len(model) > 200:
        raise ValueError('Потрібні назва профілю та Model ID')
    roles = data.get('roles', ['code'])
    if not isinstance(roles, list) or not roles or not set(roles) <= {'plan', 'code', 'review', 'supervisor'}:
        raise ValueError('Ролі: plan, code, review, supervisor')
    result = {k: data[k] for k in ('id',) if k in data}
    allow_insecure_http=data.get('allow_insecure_http',False)
    if type(allow_insecure_http) is not bool:
        raise ValueError('allow_insecure_http має бути перемикачем')
    result.update(name=name, model=model, base=normalize_base(data.get('base', ''),allow_insecure_http),
                  roles=roles, enabled=data.get('enabled', True), key_env=str(data.get('key_env', '')).strip())
    result['allow_insecure_http']=allow_insecure_http
    result['auto_compact']=data.get('auto_compact',True)
    if type(result['auto_compact']) is not bool:
        raise ValueError('auto_compact must be a boolean')
    result['api_protocol']=data.get('api_protocol','chat_completions')
    if result['api_protocol'] not in ('chat_completions','responses'):
        raise ValueError('api_protocol must be chat_completions or responses')
    for field,default in (('stream','luna' in model.lower() and result['api_protocol']=='chat_completions'),):
        result[field]=data.get(field,default)
        if type(result[field]) is not bool:raise ValueError(field+' має бути перемикачем')
    effort=data.get('reasoning_effort','low' if 'luna' in model.lower() else '')
    if effort not in ('','none','low','medium','high','xhigh','max'):raise ValueError('Invalid reasoning effort')
    result['reasoning_effort']=effort
    idle=data.get('idle_timeout',45)
    if type(idle) is not int or not 1<=idle<=300:raise ValueError('idle_timeout must be 1..300 seconds')
    result['idle_timeout']=idle
    if type(result['enabled']) is not bool:
        raise ValueError('enabled має бути перемикачем')
    result['structured_output']=data.get('structured_output',False)
    result['response_protocol']=data.get('response_protocol','text')
    if result['response_protocol'] not in ('text','json_object','json_schema','native'):
        raise ValueError('response_protocol must be text, json_object, json_schema, or native')
    if result['api_protocol']=='responses' and (result['stream'] or result['response_protocol']=='native'):
        raise ValueError('Responses currently requires stream=false and a text or JSON response protocol')
    if type(result['structured_output']) is not bool:
        raise ValueError('structured_output має бути перемикачем')
    if result['key_env'] and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', result['key_env']):
        raise ValueError('Вкажіть назву змінної середовища для API key')
    for key, default, low, high in (('priority', 10, 0, 1000), ('timeout', 300, 5, 3600),
                                    ('max_output', 4096, 256, 32768), ('context_chars', 48000, 4000, 500000),
                                    ('max_input_tokens', 16000, 256, 500000)):
        value = data.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'{key}: ціле число від {low} до {high}')
        result[key] = value
    return result


CONNECT_TIMEOUT_SECONDS=8
# Match validate_model's maximum. The configured profile may impose a lower cap.
MAX_CODING_OUTPUT_TOKENS=32768


def request(base, route, key='', body=None, timeout=10, allow_insecure_http=False,
            connect_timeout=CONNECT_TIMEOUT_SECONDS, telemetry=None, idle_timeout=45,
            on_event=None, stop=None, response_capture=None, response_limit_bytes=8*1024*1024):
    started=time.monotonic()
    deadline=started+timeout
    measured=telemetry if telemetry is not None else {}
    measured.update(response_bytes=0,sse_raw_bytes=0,decoded_text_bytes=0,time_to_first_token_seconds=None,
                    response_wire_limit_bytes=response_limit_bytes)
    if body is not None:measured.update(request_fields(body))
    if type(response_limit_bytes) is not int or response_limit_bytes<1:
        raise ValueError('response_limit_bytes must be a positive integer')
    streaming=bool(body and body.get('stream'))
    read_budget=min(timeout,idle_timeout) if streaming else timeout
    decoder=None
    if streaming:
        from .streaming import ChatStream
        cap=body.get('max_completion_tokens',body.get('max_tokens',body.get('max_output_tokens')))
        if type(cap) is not int or cap<1:
            raise ProviderError('Streaming requires an explicit output-token cap',False,kind='output_limit')
        decoder=ChatStream(measured,started,cap,on_event,stop)
        measured.update(idle_timeout_seconds=idle_timeout,local_output_byte_limit=cap*4)
    headers = {'Content-Type': 'application/json', 'User-Agent': 'LowForge/1.0'}
    if key:
        headers['Authorization'] = 'Bearer ' + key
    req = urllib.request.Request(normalize_base(base,allow_insecure_http) + route, headers=headers,
        data=None if body is None else json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
    capture=None
    try:
        if response_capture:capture=open(response_capture,'wb')
        opener=urllib.request.build_opener(NoRedirect(),_TimedHTTPHandler(connect_timeout),
                                           _TimedHTTPSHandler(connect_timeout))
        with opener.open(req, timeout=max(.05,min(read_budget,deadline-time.monotonic()))) as response:
            measured.update(http_status=response.status,content_type=response.headers.get('Content-Type'))
            if streaming and 'text/event-stream' not in (response.headers.get('Content-Type') or ''):
                raise ProviderError('Provider did not return SSE for stream=true',False,kind='invalid_stream')
            chunks=[];size=0
            while True:
                if stop is not None and stop.is_set():raise Cancelled()
                remaining=deadline-time.monotonic()
                if remaining<=0:
                    raise ProviderError(f'API total timeout after {timeout}s',True,kind='timeout',
                        error_type='total_timeout',elapsed_seconds=time.monotonic()-started)
                fp=getattr(response,'fp',None)
                raw_stream=getattr(fp,'raw',None)
                sock=getattr(raw_stream,'_sock',None)
                if sock:sock.settimeout(min(read_budget,remaining))
                reader=getattr(response,'read1',response.read)
                block=reader(min(64*1024,response_limit_bytes+1-size))
                if not block:break
                if capture and size<65536:capture.write(block[:65536-size])
                if not size:measured['first_body_byte_seconds']=round(time.monotonic()-started,6)
                if not streaming:chunks.append(block)
                size+=len(block)
                measured['response_bytes']=size
                if streaming:measured['sse_raw_bytes']=size
                if size>response_limit_bytes:break
                if decoder:decoder.feed(block)
                if decoder and decoder.done:break
            raw=b''.join(chunks)
            if size > response_limit_bytes:
                elapsed=time.monotonic()-started
                probe=raw.lower()
                if any(marker in probe for marker in (b'data:image/',b'"images"',b'"image_url"',
                                                        b'"image_generation"',b'"type":"image')):
                    measured.update(response_image_generation_detected=b'"image_generation"' in probe,
                                    response_image_content_detected=True)
                    raise ProviderError('Unexpected image-generation tool or image content in coding response',
                                        False,kind='unexpected_image',error_type='unexpected_image',elapsed_seconds=elapsed)
                raise ProviderError(f'Відповідь API перевищує локальну межу {response_limit_bytes} байтів',
                    False,kind='response_too_large',error_type='response_limit',elapsed_seconds=elapsed)
            value=decoder.result() if decoder else json.loads(raw)
            measured['decoded_response_bytes']=len(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode())
            if not streaming:
                choice=(value.get('choices') or [{}])[0]
                message=choice.get('message') or {}
                measured['decoded_text_bytes']=sum(len(message.get(field,'').encode('utf-8'))
                    for field in ('content','reasoning_content','refusal') if isinstance(message.get(field,''),str))
            if not streaming:
                measured['leading_whitespace_bytes']=len(raw)-len(raw.lstrip())
            measured['server_model']=value.get('model')
            measured.update(response_fields(value))
            if measured.get('image_generation_detected') or measured.get('image_content_detected'):
                measured.update(response_image_generation_detected=measured['image_generation_detected'],
                                response_image_content_detected=measured['image_content_detected'])
                raise ProviderError('Unexpected image-generation tool or image content in coding response',
                                    False,kind='unexpected_image',error_type='unexpected_image')
            return value
    except urllib.error.HTTPError as error:
        try:
            detail = error.read(2000).decode('utf-8', errors='replace')
            delay = _retry_after_seconds(error.headers.get('Retry-After'))
        finally:
            error.close()
        measured.update(http_status=error.code,response_bytes=len(detail.encode('utf-8')),
                        retry_after_seconds=delay,error_type='http_status')
        if key:
            detail = detail.replace(key, '[KEY]')
        image_error='unexpected_image' in detail.lower()
        oversized=('response_too_large' in detail.lower() or 'exceeds 8 MiB' in detail or 'перевищує 8 MiB' in detail or
                    ('response' in detail.lower() and 'too large' in detail.lower()))
        output_limit=('structured_output_failed' in detail and
                      ('finish_reason=length' in detail or 'output budget' in detail))
        if oversized:
            detail += ' The upstream reported a response-size limit; repeating the same request is unlikely to help.'
        elif output_limit:
            detail += ' Increase max_output or reduce the change size; repeating the same output budget cannot recover this response.'
        if image_error:measured.update(response_image_generation_detected='image_generation' in detail.lower(),
                                       response_image_content_detected=True)
        try:
            error_body = json.loads(detail)
            provider_error = error_body.get('error') if isinstance(error_body, dict) else None
        except (ValueError, RecursionError):
            provider_error = None
        quota_error = (error.code in (429,503) and isinstance(provider_error,dict) and
                       any(provider_error.get(field) in ('usage_limit_reached','model_cooldown')
                           for field in ('code','type')))
        if quota_error:
            for field in ('reset_seconds','resets_in_seconds','resets_at'):
                value=provider_error.get(field)
                if isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value):
                    seconds=value-time.time() if field=='resets_at' else value
                    delay=max(delay,min(86400,max(0,math.ceil(seconds))))
            measured['retry_after_seconds']=delay
        invalid_prompt = isinstance(provider_error, dict) and provider_error.get('code') == 'invalid_prompt'
        kind='invalid_prompt' if invalid_prompt else 'unexpected_image' if image_error else 'response_too_large' if oversized else 'structured_output_limit' if output_limit else 'http'
        retryable=(not (invalid_prompt or image_error or output_limit or oversized) and (error.code in (408,429) or error.code>=500)
                   and (quota_error or delay<=300))
        if quota_error:kind='rate_limit'
        raise ProviderError(f'API HTTP {error.code}: {detail}',retryable,delay,kind,
                            status_code=error.code,error_type='http_status',
                            elapsed_seconds=time.monotonic()-started) from None
    except ProviderError as error:
        measured.update(error_kind=error.kind,error_type=error.error_type)
        raise
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as error:
        cause=error.reason if isinstance(error,urllib.error.URLError) else error
        kind=_network_error_kind(cause)
        elapsed=time.monotonic()-started
        message = str(error).replace(key, '[KEY]') if key else str(error)
        error_type=type(cause).__name__
        if kind=='timeout':
            error_type=('total_timeout' if elapsed>=max(0,timeout-.05) else
                        'connect_timeout' if getattr(cause,'lowforge_phase','')=='connect' else
                        'idle_timeout' if streaming else
                        'read_timeout')
        measured.update(error_kind=kind,error_type=error_type)
        raise ProviderError('API недоступний: ' + message,not streaming or measured['response_bytes']==0,kind=kind,error_type=error_type,
                            elapsed_seconds=elapsed) from None
    except (ValueError, UnicodeError):
        raise ProviderError('API повернув некоректний JSON',True,kind='invalid_json',
                            error_type='response_decode',elapsed_seconds=time.monotonic()-started) from None
    finally:
        if capture:capture.close()
        measured['total_seconds']=round(time.monotonic()-started,6)


def json_object(text,allow_action_array=False):
    if not isinstance(text, str) or not text.strip():
        raise ValueError('Порожня відповідь моделі')
    text = re.sub(r'^\s*<think>.*?</think>\s*', '', text, flags=re.S).strip()
    for opening,closing in (('[actions]','[/actions]'),('<json>','</json>'),('<response>','</response>')):
        if text.startswith(opening) and text.endswith(closing):
            text=text[len(opening):-len(closing)].strip()
            break
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('Повторний ключ JSON: '+key)
            result[key]=value
        return result
    try:value=json.loads(text,object_pairs_hook=unique)
    except json.JSONDecodeError:
        # Some local models prepend an explanation despite the protocol prompt.
        # Accept one intact object, never repair truncated JSON or choose between objects.
        if text.startswith(('{','[')):raise
        blocks=list(re.finditer(r'```(?:json)?\s*([\s\S]*?)```',text,re.I))
        if blocks:
            if len(blocks)!=1:raise ValueError('Неоднозначна відповідь: декілька блоків JSON')
            block=blocks[0]
            outside=text[:block.start()]+text[block.end():]
            if any(c in outside for c in '{}[]`'):raise ValueError('Неоднозначна відповідь поза JSON')
            candidate=block.group(1).strip()
        else:
            start=text.find('{')
            if start<0 or any(c in text[:start] for c in '}[]`'):raise ValueError('Відповідь не містить єдиного JSON-об’єкта')
            candidate=text[start:]
        value=json.loads(candidate,object_pairs_hook=unique)
    if isinstance(value,list):
        if len(value)==1 and isinstance(value[0],dict):value=value[0]
        elif allow_action_array and value and len(value)<=12 and all(isinstance(a,dict) and ('type' in a or 'action' in a) for a in value):
            value={'actions':value}
        else:raise ValueError('Expected one JSON object; array must contain one object or an unambiguous array of coding actions')
    if not isinstance(value, dict):
        raise ValueError('Expected one JSON object with actions, not a scalar value')
    return value


def profile_request(model, key, body, *, timeout=None, telemetry=None, stop=None,
                    response_limit_bytes=1024*1024, transport=None):
    """Use only the explicitly selected endpoint, preserving the shared guards."""
    if stop is not None and stop.is_set():raise Cancelled()
    measured=telemetry if telemetry is not None else {}
    native=model.get('api_protocol','chat_completions')=='responses'
    route='/responses' if native else '/chat/completions'
    if native:
        from .responses import responses_payload,chat_response,phase_metadata
        payload=responses_payload(body)
    else:payload=body
    measured.update(request_fields(payload))
    measured.update(api_protocol=model.get('api_protocol','chat_completions'),
                    endpoint=normalize_base(model['base'],model.get('allow_insecure_http',False))+route)
    call=request if transport is None else transport
    deadline=model['timeout'] if timeout is None else timeout
    if call is request:
        value=call(model['base'],route,key,payload,deadline,model.get('allow_insecure_http',False),
                   telemetry=measured,idle_timeout=model.get('idle_timeout',45),stop=stop,
                   response_limit_bytes=response_limit_bytes)
    else:value=call(model['base'],route,key,payload,deadline)
    if native:
        measured['response_output_shapes']=phase_metadata(value)
        value=chat_response(value)
    return value


class Router:
    def __init__(self, models, stop, log, transport=request, keys=None):
        self.models = sorted([validate_model(m) for m in models if m.get('enabled', True)], key=lambda m: m['priority'])
        self.stop, self.log, self.transport = stop, log, transport
        self.keys = keys or {}
        self.cooldowns = {}
        self.calls = 0
        self.limit = 30
        self.usage = {'input_tokens': 0, 'output_tokens': 0}
        self.metrics = {'roles': {}, 'models': {}, 'quality': {}, 'retries': 0, 'requests': [],
                       'routing': {'adaptive':False,'complexity':'standard','decisions':[]}}
        self.last_server_model=''
        self.adaptive=False
        self.complexity='standard'

    def configure_adaptive(self, enabled, complexity='standard'):
        if type(enabled) is not bool or complexity not in ('low','standard','high'):
            raise ValueError('Некоректна стратегія маршрутизації')
        self.adaptive=enabled;self.complexity=complexity
        self.metrics['routing'].update(adaptive=enabled,complexity=complexity)

    def record_quality(self, model_id, passed):
        """Record independent verification outcome for a code profile."""
        if not isinstance(model_id,str) or type(passed) is not bool:return
        item=self.metrics['quality'].setdefault(model_id,{'passed':0,'failed':0})
        item['passed' if passed else 'failed']+=1

    def _dispatch(self, model, key, payload, metric, role):
        """Dispatch one bounded request and preserve cancellation/timeout behavior."""
        result={};done=threading.Event();started=time.monotonic()
        def send():
            try:
                result['value']=profile_request(model,key,payload,telemetry=metric,stop=self.stop,
                    response_limit_bytes=1024*1024 if role=='code' and not payload.get('stream') else 8*1024*1024,
                    transport=self.transport)
            except Exception as error:result['error']=error
            finally:done.set()
        threading.Thread(target=send,daemon=True).start()
        deadline=time.monotonic()+model['timeout']+1
        while not done.wait(.1):
            if self.stop.is_set():raise Cancelled()
            if time.monotonic()>=deadline:
                result['error']=ProviderError('Вичерпано час очікування API. Сервер ще може обчислювати відповідь.',False)
                break
        if self.stop.is_set():raise Cancelled()
        metric['wait_seconds']=round(time.monotonic()-started,4)
        if 'error' in result:raise result['error']
        return result['value']

    def _adaptive_score(self, model, role):
        metrics=self.metrics['models'].get(model['id'],{})
        calls=max(0,int(metrics.get('calls',0)))
        failures=max(0,int(metrics.get('failures',0)))
        failure_rate=(failures+1)/(calls+2)
        latency=float(metrics.get('seconds',0))/calls if calls else 0
        quality=self.metrics['quality'].get(model['id'],{}) if role=='code' else {}
        passed=max(0,int(quality.get('passed',0)));failed=max(0,int(quality.get('failed',0)))
        quality_rate=(passed+1)/(passed+failed+2)
        score=model['priority']/1000*0.08+failure_rate*0.45+min(latency,120)/120*0.12
        score-= (quality_rate-.5)*(.9 if self.limit-self.calls<=3 else .65)
        context_fit=min(1,max(0,(model['context_chars']-4000)/196000))
        output_fit=min(1,max(0,(model['max_output']-256)/7936))
        if self.complexity=='high':score-=context_fit*.16+output_fit*.10
        elif self.complexity=='low':score+=context_fit*.035+output_fit*.08
        return round(score,6)

    def _record_metric(self, role, model_id, elapsed, ok):
        for group, key in ((self.metrics['roles'], role), (self.metrics['models'], model_id)):
            item=group.setdefault(key, {'calls':0,'failures':0,'seconds':0.0})
            item['calls']+=1
            item['failures']+=0 if ok else 1
            item['seconds']=round(item['seconds']+elapsed,3)

    def has_role(self, role):
        return any(role in m['roles'] for m in self.models)

    def _continue_truncated(self, model, key, body, response, metric, role):
        """Join at most two exact text continuations within the existing call budget.

        No source is applied until the complete assembled contract parses. Native
        tool arguments retain their existing explicit failure behavior.
        """
        original_metric=metric
        parts=[]
        for continuation in range(3):
            choice=response['choices'][0]
            message=choice.get('message') or {}
            text=message.get('content')
            if message.get('tool_calls') or not isinstance(text,str) or not text:
                raise ProviderError('Truncated response has no continuable text; use smaller write_chunk actions.',
                                    False,kind='output_limit')
            parts.append(text)
            usage=response.get('usage') or {}
            for field,name in (('prompt_tokens','input_tokens'),('completion_tokens','output_tokens')):
                count=usage.get(field,0)
                if type(count) is int and count>=0:
                    self.usage[name]+=count;metric[name]=count
            original_metric['usage_accounted']=True
            metric['finish_reason']=choice.get('finish_reason')
            if choice.get('finish_reason') not in ('length','max_tokens'):
                metric['status']='ok'
                result=dict(response)
                result['choices']=[dict(choice,message=dict(message,content=''.join(parts)))]
                original_metric['continuation_calls']=continuation
                return result
            metric['status']='continued'
            if continuation>=2 or self.calls>=self.limit:
                raise ProviderError('Output continuation exhausted its two-call or total-call budget; use write_chunk.',
                                    False,kind='output_limit')
            combined=''.join(parts)
            retry_body=dict(body)
            retry_body.pop('response_format',None)
            retry_body['messages']=list(body['messages'])+[
                {'role':'assistant','content':combined},
                {'role':'user','content':'Continue exactly from the next character of the interrupted response. '
                 'Do not repeat any prefix, add commentary, or restart the file/JSON. Close the original contract.'}]
            content=''.join(str(m.get('content','')) for m in retry_body['messages'])
            if len(content)>model['context_chars'] or (len(content.encode('utf-8'))+2)//3>model['max_input_tokens']:
                raise ProviderError('Output continuation does not fit the context budget; use smaller write_chunk actions.',
                                    False,kind='output_limit')
            self.calls+=1
            metric={k:v for k,v in original_metric.items() if k not in
                ('usage_accounted','input_tokens','output_tokens','response_chars','finish_reason')}
            metric.update(call=self.calls,status='pending',continuation_of=original_metric['call'],
                          continuation_index=continuation+1)
            metric.update(request_fields(retry_body))
            self.metrics['requests']=(self.metrics['requests']+[metric])[-100:]
            self.log(f'Відповідь обрізана; продовження {continuation+1}/2 · виклик {self.calls}/{self.limit}')
            started=time.monotonic()
            try:
                response=self._dispatch(model,key,retry_body,metric,role)
                metric.update(response_fields(response))
                if metric.get('image_generation_detected') or metric.get('image_content_detected'):
                    raise ProviderError('Unexpected image content in continuation',False,kind='unexpected_image')
            except BaseException:
                metric['status']='error'
                self._record_metric(role,model['id'],time.monotonic()-started,False)
                raise
            self._record_metric(role,model['id'],time.monotonic()-started,True)

    def complete(self, role, system, make_user, exclude=(), attempt=1, one_shot=False):
        errors = []
        last_error=None
        excluded=set(exclude)
        candidates=[m for m in self.models if m['id'] not in excluded and role in m['roles']
                    and self.cooldowns.get(m['id'],0)<=time.monotonic()]
        if one_shot:candidates=candidates[:1]
        if self.adaptive:
            candidates.sort(key=lambda m:(self._adaptive_score(m,role),m['priority'],m['id']))
            if candidates:
                decision={'role':role,'complexity':self.complexity,'remaining_calls':max(0,self.limit-self.calls),
                          'selected':candidates[0]['id'],'scores':{m['id']:self._adaptive_score(m,role) for m in candidates}}
                self.metrics['routing']['decisions']=(self.metrics['routing'].get('decisions',[])+[decision])[-50:]
                self.log('Адаптивний маршрут · '+role+' · '+candidates[0]['name']+
                         ' · складність '+self.complexity+' · викликів залишилося '+str(decision['remaining_calls']))
        for model_index,model in enumerate(candidates):
            if self.stop.is_set():
                raise Cancelled()
            if self.calls >= self.limit:
                raise ProviderError('Вичерпано бюджет викликів моделі', False, kind='call_budget')
            context_started=time.monotonic()
            user = make_user(model)
            context_seconds=time.monotonic()-context_started
            request_text=system + user
            estimated_tokens=(len(request_text.encode('utf-8'))+2)//3
            if len(request_text) > model['context_chars']:
                errors.append(model['name'] + ': завеликий контекст; збільште context_chars або звузьте задачу')
                continue
            if estimated_tokens > model['max_input_tokens']:
                errors.append(model['name'] + f': оцінка контексту {estimated_tokens} токенів перевищує max_input_tokens {model["max_input_tokens"]}; звузьте задачу або змініть ліміт')
                continue
            key = self.keys.get(model['id']) or os.environ.get(model['key_env'], '')
            output_cap=min(model['max_output'],MAX_CODING_OUTPUT_TOKENS) if role=='code' else model['max_output']
            body = {'model': model['model'], 'messages': [{'role': 'system', 'content': system},
                    {'role': 'user', 'content': user}], 'max_tokens': output_cap, 'stream': model['stream']}
            if model['stream']:body['stream_options']={'include_usage':True}
            if model['reasoning_effort']:body['reasoning_effort']=model['reasoning_effort']
            protocol=model.get('response_protocol','text')
            if model.get('structured_output') or protocol=='json_schema':
                from .schemas import response_schema
                body['response_format']=response_schema(role)
            if protocol=='json_object':body['response_format']={'type':'json_object'}
            if protocol=='native' and role=='code':
                from .schemas import response_schema
                body['messages'][0]['content']+='\nTransport for this request: submit the response object only as arguments of the declared submit_actions function. Do not return assistant text or invoke other functions.'
                body.pop('response_format',None)
                body['tools']=[{'type':'function','function':{'name':'submit_actions',
                    'description':'Submit the next batch of project actions and verification flags to the host.',
                    'parameters':response_schema('code')['json_schema']['schema']}}]
                body['tool_choice']={'type':'function','function':{'name':'submit_actions'}}
            self.calls += 1
            self.log(f"Виклик {self.calls}/{self.limit} · {role} · {model['name']}")
            started=time.monotonic()
            metric={'call':self.calls,'role':role,'profile':model['id'],'model':model['model'],
                    'attempt':max(1,int(attempt)),'max_attempts':1 if one_shot else 3,
                    'endpoint':urllib.parse.urljoin(model['base'].rstrip('/')+'/', 'chat/completions'),
                    'timeout_seconds':model['timeout'],'connect_timeout_seconds':CONNECT_TIMEOUT_SECONDS,
                    'read_timeout_seconds':min(model['idle_timeout'],model['timeout']) if model['stream'] else model['timeout'],
                    'idle_timeout_seconds':model['idle_timeout'] if model['stream'] else None,'total_timeout_seconds':model['timeout'],
                    'proxy_mode':'urllib system proxy configuration',
                    'proxy_configured':bool(urllib.request.getproxies()),'http_client_reused':False,
                    'address_family_policy':'system getaddrinfo; no forced IPv6',
                    'context_seconds':round(context_seconds,4),'context_chars':len(request_text),
                    'context_sha256':hashlib.sha256(user.encode('utf-8')).hexdigest(),
                    'estimated_input_tokens':estimated_tokens,'max_output':model['max_output'],
                    'max_tokens':body.get('max_tokens'),'reasoning_effort':body.get('reasoning_effort'),
                    'parallel_tool_calls':body.get('parallel_tool_calls'), 'stream':body.get('stream',False),
                    'time_to_first_token_seconds':None,
                    'structured_output':model['structured_output'],'status':'pending',
                    'input_tokens':None,'cached_input_tokens':None,'output_tokens':None}
            metric.update(request_fields(body))
            self.metrics['requests']=(self.metrics['requests']+[metric])[-100:]
            if metric.get('image_generation_detected') or metric.get('image_content_detected'):
                self.log('Попередження: coding-запит містить image_generation або image-вміст; запит зупинено')
                metric.update(status='error',error_kind='unexpected_image')
                raise ProviderError('Coding request contains an image-generation tool or image content',
                                    False,kind='unexpected_image',error_type='unexpected_image')
            def fallback_text(reason, response_text=None):
                if one_shot:raise reason
                if role!='code' or protocol not in ('json_object','json_schema') and not model.get('structured_output'):
                    raise reason
                if isinstance(reason, json.JSONDecodeError):
                    primary = 'trailing_json_data' if reason.msg == 'Extra data' else 'invalid_json'
                    metric['structured_failure_position'] = reason.pos
                    metric['structured_failure_shape'] = json_failure_shape(reason, response_text, metric)
                elif isinstance(reason, ProviderError):
                    primary = reason.kind
                else:
                    primary = 'response_contract'
                metric['structured_failure_kind'] = primary
                metric.update(status='error',error_kind=getattr(reason,'kind','json_format'),
                    protocol_fallback='structured-to-local-json')
                self._record_metric(role,model['id'],time.monotonic()-started,False)
                retry_body=dict(body);retry_body.pop('response_format',None)
                retry_body['max_tokens']=min(MAX_CODING_OUTPUT_TOKENS,model['max_output'],max(output_cap*2,4096))
                retry_metric=dict(metric);retry_metric.update(call=self.calls+1,protocol_fallback='structured-to-local-json',
                    fallback_reason=getattr(reason,'kind',type(reason).__name__),max_tokens=retry_body['max_tokens'],status='pending')
                retry_metric.pop('sse_content_ends', None)
                retry_metric.pop('sse_content_chars', None)
                retry_metric.update(request_fields(retry_body));self.metrics['requests']=(self.metrics['requests']+[retry_metric])[-100:]
                if self.calls>=self.limit:raise ProviderError('Вичерпано бюджет викликів моделі; структурований fallback не вмістився.',False, kind='call_budget')
                self.calls+=1
                self.log(f'Structured output failed ({primary}); retrying once as tolerant text with local JSON validation.')
                fallback_started=time.monotonic()
                value=self._dispatch(model,key,retry_body,retry_metric,role)
                retry_metric.update(response_fields(value))
                if retry_metric.get('image_generation_detected') or retry_metric.get('image_content_detected'):
                    retry_metric['status']='error';retry_metric['error_kind']='unexpected_image'
                    self._record_metric(role,model['id'],time.monotonic()-fallback_started,False)
                    raise ProviderError('Unexpected image-generation tool or image content in coding response',False,kind='unexpected_image')
                usage_value=value.get('usage') or {}
                for usage_field,usage_name in (('prompt_tokens','input_tokens'),('completion_tokens','output_tokens')):
                    count=usage_value.get(usage_field,0)
                    if type(count) is int and count>=0:
                        self.usage[usage_name]+=count;retry_metric[usage_name]=count
                retry_metric['fallback_seconds']=round(time.monotonic()-fallback_started,4)
                choice=value['choices'][0]
                if choice.get('finish_reason') in ('length','max_tokens'):
                    retry_metric['status']='error';retry_metric['error_kind']='output_limit'
                    self._record_metric(role,model['id'],time.monotonic()-fallback_started,False)
                    raise ProviderError('Відповідь обрізано і після одного tolerant-text fallback; зменште розмір зміни.',False,kind='output_limit')
                text=choice.get('message',{}).get('content')
                from .protocol import decode_answer
                try:answer=decode_answer(text,json_object,role)
                except (ValueError,KeyError,TypeError,IndexError) as error:
                    retry_metric['status']='error';retry_metric['error_kind']='json_format'
                    if isinstance(error, json.JSONDecodeError):
                        retry_metric['fallback_failure_shape'] = json_failure_shape(error, text, retry_metric)
                    self._record_metric(role,model['id'],time.monotonic()-fallback_started,False)
                    raise
                retry_metric['status']='ok';self._record_metric(role,model['id'],time.monotonic()-fallback_started,True)
                return answer,value,text
            parse_started=time.monotonic()
            try:
                try:response=self._dispatch(model,key,body,metric,role)
                except ProviderError as transport_error:
                    is_structured_failure=(transport_error.kind=='structured_output_limit' or
                        'structured_output_failed' in str(transport_error).lower())
                    if not is_structured_failure:raise
                    answer,response,text=fallback_text(transport_error)
                    protocol_fallback_done=True
                else:protocol_fallback_done=False
                if not protocol_fallback_done:metric.update(response_fields(response))
                if metric.get('image_generation_detected') or metric.get('image_content_detected'):
                    metric.update(response_image_generation_detected=metric['image_generation_detected'],
                                  response_image_content_detected=metric['image_content_detected'])
                    self.log('Попередження: coding-відповідь містить image_generation або image-вміст; застосування зупинено')
                    raise ProviderError('Unexpected image-generation tool or image content in coding response',
                                        False,kind='unexpected_image',error_type='unexpected_image')
                self.last_server_model=str(response.get('model',''))[:200] if isinstance(response,dict) else ''
                choice = response['choices'][0]
                if (not protocol_fallback_done and role=='code' and protocol!='native'
                        and choice.get('finish_reason') in ('length','max_tokens')):
                    response=self._continue_truncated(model,key,body,response,metric,role)
                    choice=response['choices'][0]
                usage = response.get('usage') or {}
                if not protocol_fallback_done and not metric.get('usage_accounted'):
                    for field, name in (('prompt_tokens', 'input_tokens'), ('completion_tokens', 'output_tokens')):
                        value = usage.get(field, 0)
                        if type(value) is int and value >= 0:
                            self.usage[name] += value
                            metric[name]=value
                    details=usage.get('prompt_tokens_details') or usage.get('input_tokens_details') or {}
                    cached=details.get('cached_tokens') if isinstance(details,dict) else None
                    if type(cached) is int and cached>=0:metric['cached_input_tokens']=cached
                if not protocol_fallback_done:
                    text = None
                    try:
                        if choice.get('finish_reason') in ('length', 'max_tokens'):
                            raise ProviderError('Відповідь обрізано: збільште max_output або зменште розмір однієї зміни',False,kind='output_limit')
                        text = choice['message'].get('content')
                        from .protocol import decode_answer,decode_fast_path,native_answer
                        if protocol=='native' and role=='code':
                            answer=native_answer(choice['message'],json_object)
                            text=choice['message']['tool_calls'][0]['function']['arguments']
                        else:
                            if choice['message'].get('tool_calls'):
                                raise ValueError('Protocol mismatch: received native tool_calls but this request requires a JSON object in content; use the declared text actions contract')
                            answer=(decode_fast_path(text,json_object) if one_shot and role=='code'
                                    else decode_answer(text,json_object,role))
                    except (ProviderError,ValueError,KeyError,TypeError,IndexError) as parse_error:
                        structured_failure=(protocol in ('json_object','json_schema') or model.get('structured_output'))
                        if not structured_failure or isinstance(parse_error,ProviderError) and parse_error.kind!='output_limit':raise
                        answer,response,text=fallback_text(parse_error, text)
                metric.update(status='recovered' if protocol_fallback_done else 'ok',parse_seconds=round(time.monotonic()-parse_started,4),
                              response_chars=len(text))
                if not protocol_fallback_done:self._record_metric(role,model['id'],time.monotonic()-started,True)
                return answer, model['id']
            except (ProviderError, ValueError, KeyError, TypeError, IndexError) as error:
                last_error=error
                metric.update(status='error',parse_seconds=round(time.monotonic()-parse_started,4),
                              error_kind=getattr(error,'kind','json_format' if isinstance(error,ValueError) else 'response_format'))
                if isinstance(error,ProviderError):
                    metric.update(http_status=error.status_code if error.status_code is not None else metric.get('http_status'),error_type=error.error_type,
                                  retry_after_seconds=error.retry_after,
                                  failure_elapsed_seconds=error.elapsed_seconds)
                    if error.kind=='unexpected_image':
                        self.log('Попередження: виявлено image_generation або image-вміст у coding-потоці; відповідь відхилено')
                self._record_metric(role,model['id'],time.monotonic()-started,False)
                detail = str(error).replace(key, '[KEY]') if key else str(error)
                errors.append(model['name'] + ': ' + detail[:2000])
                if isinstance(error,ProviderError) and error.kind=='rate_limit':
                    self.cooldowns[model['id']]=time.monotonic()+error.retry_after
                    self.log(errors[-1])
                    raise ProviderError(errors[-1],error.retryable,error.retry_after,error.kind,
                        status_code=error.status_code,error_type=error.error_type,
                        elapsed_seconds=error.elapsed_seconds) from error
                if isinstance(error,ProviderError) and error.kind in ('invalid_prompt','refusal'):
                    self.log(errors[-1])
                    raise ProviderError(errors[-1],False,kind=error.kind,status_code=error.status_code,
                        error_type=error.error_type,elapsed_seconds=error.elapsed_seconds) from error
                delay = getattr(error, 'cooldown', 0)
                if isinstance(error, ProviderError) and not error.retryable:
                    delay = 86400
                self.cooldowns[model['id']] = time.monotonic() + delay
                if any(candidate['id'] not in excluded and role in candidate['roles'] and
                       self.cooldowns.get(candidate['id'],0)<=time.monotonic()
                       for candidate in candidates[model_index+1:]):
                    self.metrics['retries']+=1
                if isinstance(error,ProviderError):
                    self.log(f"API відмова · {metric['endpoint']} · {error.kind} · "
                             f"HTTP {error.status_code if error.status_code is not None else '—'} · "
                             f"{(error.elapsed_seconds if error.elapsed_seconds is not None else metric['wait_seconds']):.2f} с · "
                             f"спроба {metric['attempt']}/{metric['max_attempts']} · "
                             f"timeout connect/read/total 8/{model['timeout']}/{model['timeout']} с")
                self.log(errors[-1])
        retryable = (isinstance(last_error,ProviderError) and last_error.retryable) or any(
            m['id'] not in excluded and role in m['roles'] and
            self.cooldowns.get(m['id'], 0) <= time.monotonic() for m in self.models)
        raise ProviderError('\n'.join(errors) or 'Немає доступної моделі для ролі ' + role, retryable,
            getattr(last_error,'retry_after',0),getattr(last_error,'kind','provider'),
            status_code=getattr(last_error,'status_code',None),error_type=getattr(last_error,'error_type',None),
            elapsed_seconds=getattr(last_error,'elapsed_seconds',None))
