"""Content-free request/response measurements shared by providers and benchmarks."""
import hashlib
import json


def image_marker_evidence(value):
    """Return content-free flags for image-generation tools or image payloads."""
    generation = False
    image = False
    evidence = []
    safe_keys = {'output','content','tools','type','name','image','images','image_url',
                 'input_image','output_image','image_generation','image-generation',
                 'usage','input_tokens_details','output_tokens_details','text','format',
                 'schema','properties','choices','message','response','metadata'}
    def record(path, rule):
        if len(evidence)<32:evidence.append({'path':path,'rule':rule})
    def shape(item):
        if isinstance(item,dict):
            allowed={'type','url','b64_json','data','result','size','quality','background',
                     'output_format','output_compression','moderation','detail','enabled'}
            return {'kind':'object','fields':[{'name':k if k in allowed else '*',
                    'kind':type(v).__name__,
                    **({'name_sha256':hashlib.sha256(str(k).encode()).hexdigest()} if k not in allowed else {})}
                    for k,v in list(item.items())[:16]]}
        return {'kind':type(item).__name__}
    image_types = {'image', 'input_image', 'output_image', 'image_url', 'computer_screenshot'}
    def visit(item, key='', path='$'):
        nonlocal generation, image
        if isinstance(item, dict):
            for name, child in item.items():
                lowered = str(name).lower()
                child_path=path+'.'+(lowered if lowered in safe_keys else '*')
                if lowered in ('image_generation', 'image-generation'):
                    generation = True
                    record(child_path,'generation_key')
                if lowered in ('name', 'type') and isinstance(child, str):
                    normalized = child.lower().replace('-', '_')
                    if normalized == 'image_generation':
                        generation = True;record(child_path,'generation_type')
                    if normalized in image_types:
                        image = True;record(child_path,'image_type')
                if lowered in ('image', 'images', 'image_url', 'input_image', 'output_image') and child:
                    # Responses echoes this effective policy as metadata, not image bytes.
                    # Permit only the exact documented response-root shape; scan all
                    # output/tool content and any extra/unknown image fields normally.
                    policy_metadata=(lowered=='image' and path in ('$', '$.response')
                        and item.get('object')=='response' and isinstance(child,dict)
                        and set(child)=={'context_compression'}
                        and child['context_compression'] in ('enabled','disabled'))
                    if not policy_metadata:
                        image = True
                        record(child_path,'nonempty_image_key')
                        if evidence and evidence[-1]['path']==child_path:
                            evidence[-1]['shape']=shape(child)
                visit(child, lowered, child_path)
        elif isinstance(item, list):
            for child in item: visit(child, key, path+'[]')
        elif isinstance(item, str):
            if item.lower().startswith('data:image/'):
                image = True;record(path,'image_data_uri')
            if key == 'name' and item.lower().replace('-', '_') == 'image_generation': generation = True
    visit(value)
    return {'image_generation_detected': generation, 'image_content_detected': image}, evidence


def image_markers(value):
    return image_marker_evidence(value)[0]


def encode(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def request_fields(body):
    messages = body.get('messages') or (body.get('input') if isinstance(body.get('input'),list) else [])
    system = [m for m in messages if m.get('role') in ('system', 'developer')]
    raw = encode(body)
    markers=image_markers(body)
    return {'request_bytes': len(raw), 'request_sha256': hashlib.sha256(raw).hexdigest(),
            'input_bytes': len(encode(messages if messages else body.get('input', []))),
            'system_prompt_chars': sum(len(m.get('content') or '') for m in system)
                + len(body.get('instructions') or ''),
            'system_sha256': hashlib.sha256(encode(system or body.get('instructions', ''))).hexdigest(),
            'reasoning_effort': body.get('reasoning_effort', (body.get('reasoning') or {}).get('effort')),
            'verbosity': body.get('verbosity', (body.get('text') or {}).get('verbosity')),
            'max_output_tokens': body.get('max_output_tokens', body.get('max_completion_tokens', body.get('max_tokens'))),
            'stream': body.get('stream', False), 'tool_count': len(body.get('tools') or []),
            'parallel_tool_calls': body.get('parallel_tool_calls'),
            'request_field_order': list(body.keys()),
            'input_format': 'messages' if isinstance(body.get('messages'), list) else
                'responses_input' if isinstance(body.get('input'), (list, str)) else 'unknown',
            'prompt_cache_key_present': isinstance(body.get('prompt_cache_key'), str) and bool(body['prompt_cache_key']),
            **markers}


def response_fields(body):
    usage = body.get('usage') or {}
    details = usage.get('completion_tokens_details') or usage.get('output_tokens_details') or {}
    cached = usage.get('prompt_tokens_details') or usage.get('input_tokens_details') or {}
    choices = body.get('choices') or [{}]
    markers,evidence=image_marker_evidence(body)
    return {'image_marker_evidence':evidence,
            'input_tokens': usage.get('prompt_tokens', usage.get('input_tokens')),
            'output_tokens': usage.get('completion_tokens', usage.get('output_tokens')),
            'reasoning_tokens': details.get('reasoning_tokens'), 'cached_input_tokens': cached.get('cached_tokens'),
            'finish_reason': choices[0].get('finish_reason'), **markers}
