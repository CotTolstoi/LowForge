"""Stateless text Responses mapping. No automatic endpoint fallback.

Native Responses phase metadata, not JSON guessing, selects final output.
The ordinary LowForge strict action decoder still validates the selected text.
"""
import copy
import hashlib

from .providers import ProviderError


def responses_payload(chat):
    allowed = {'model','messages','max_tokens','max_completion_tokens','stream',
               'reasoning_effort','response_format'}
    if set(chat) - allowed or chat.get('stream'):
        raise ProviderError('Experimental Responses adapter requires stateless non-stream text input',
                            False, kind='adapter_request')
    messages = chat.get('messages')
    if not isinstance(messages,list) or not messages:
        raise ProviderError('Responses adapter requires text messages',False,kind='adapter_request')
    for message in messages:
        if (not isinstance(message,dict) or set(message)-{'role','content','phase'}
                or message.get('role') not in ('system','developer','user','assistant')
                or not isinstance(message.get('content'),str)):
            raise ProviderError('Unsupported Responses input message',False,kind='adapter_request')
        if message['role']=='assistant' and message.get('phase') not in ('commentary','final_answer'):
            raise ProviderError('Assistant replay requires preserved phase; none will be invented',
                                False,kind='adapter_request')
        if message['role']!='assistant' and 'phase' in message:
            raise ProviderError('Only assistant messages may have phase',False,kind='adapter_request')
    cap=chat.get('max_completion_tokens',chat.get('max_tokens'))
    if type(cap) is not int or cap<1:
        raise ProviderError('An explicit output cap is required',False,kind='adapter_request')
    if 'max_tokens' in chat and 'max_completion_tokens' in chat:
        raise ProviderError('Conflicting output caps',False,kind='adapter_request')
    payload={'model':chat['model'],'input':copy.deepcopy(messages),
             'max_output_tokens':cap,'stream':False,'store':False}
    if chat.get('reasoning_effort') is not None:
        payload['reasoning']={'effort':chat['reasoning_effort']}
    fmt=chat.get('response_format')
    if fmt is not None:
        if not isinstance(fmt,dict):
            raise ProviderError('Response format must be an object',False,kind='adapter_request')
        if fmt.get('type')=='json_schema':
            schema=fmt.get('json_schema')
            if not isinstance(schema,dict) or set(schema)-{'name','schema','strict','description'}:
                raise ProviderError('Unsupported structured-output shape',False,kind='adapter_request')
            payload['text']={'format':{'type':'json_schema',**copy.deepcopy(schema)}}
        elif fmt.get('type') in ('text','json_object'):
            payload['text']={'format':{'type':fmt['type']}}
        else:
            raise ProviderError('Unsupported response format',False,kind='adapter_request')
    return payload


def phase_metadata(response):
    if not isinstance(response,dict):return [{'type':'invalid_response'}]
    if response.get('type') in ('response.completed','response.incomplete','response.failed'):
        response=response.get('response') or {}
    if not isinstance(response,dict):return [{'type':'invalid_response'}]
    if not isinstance(response.get('output'),list):return [{'type':'invalid_output'}]
    result=[]
    for item in (response.get('output') or [])[:32]:
        if not isinstance(item,dict):
            result.append({'type':'invalid_item'});continue
        kind=item.get('type')
        phase=item.get('phase')
        record={'type':kind if kind in ('message','reasoning','function_call','image_generation_call') else 'unknown',
                'phase':phase if phase in (None,'commentary','final_answer') else 'unknown','parts':[]}
        if not isinstance(item.get('content',[]),list):
            result.append({'type':'invalid_content'});continue
        for part in (item.get('content') or [])[:16]:
            if not isinstance(part,dict):
                record['parts'].append({'type':'invalid_part'});continue
            kind=part.get('type')
            shape={'type':kind if kind in ('output_text','refusal') else 'unknown'}
            if part.get('type')=='output_text' and isinstance(part.get('text'),str):
                raw=part['text'].encode('utf-8')
                shape.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            record['parts'].append(shape)
        result.append(record)
    return result


def chat_response(response):
    if not isinstance(response,dict):
        raise ProviderError('Responses body must be an object',False,kind='response_format')
    if response.get('type') in ('response.completed','response.incomplete','response.failed'):
        response=response.get('response') or {}
    if not isinstance(response,dict):
        raise ProviderError('Malformed Responses envelope',False,kind='response_format')
    for field,expected in (('output',list),('usage',dict),('incomplete_details',dict)):
        if response.get(field) is not None and not isinstance(response[field],expected):
            raise ProviderError('Malformed Responses '+field,False,kind='response_format')
    error=response.get('error')
    if error:
        kind='invalid_prompt' if isinstance(error,dict) and error.get('code')=='invalid_prompt' else 'response_failed'
        raise ProviderError('Responses endpoint returned an error; no action was selected',False,kind=kind)
    if response.get('status')!='completed':
        reason=(response.get('incomplete_details') or {}).get('reason')
        raise ProviderError('Responses endpoint did not complete: '+str(reason or response.get('status')),
                            False,kind='refusal' if reason=='content_filter' else 'response_incomplete')
    output=response.get('output')
    if not isinstance(output,list):
        raise ProviderError('Responses output array is missing',False,kind='response_format')
    messages=[]
    for item in output:
        if not isinstance(item,dict):
            raise ProviderError('Malformed Responses output item',False,kind='response_format')
        kind=item.get('type')
        if kind=='reasoning':
            continue
        if kind!='message':
            raise ProviderError('Unexpected non-message output in text-only Responses flow',
                                False,kind='unexpected_image' if kind=='image_generation_call' else 'unexpected_tool')
        if item.get('role')!='assistant':
            raise ProviderError('Unexpected output role',False,kind='response_format')
        phase=item.get('phase')
        if phase not in (None,'commentary','final_answer'):
            raise ProviderError('Unknown assistant phase',False,kind='response_format')
        chunks=[]
        if not isinstance(item.get('content'),list):
            raise ProviderError('Malformed message content',False,kind='response_format')
        for part in item.get('content') or []:
            if not isinstance(part,dict):
                raise ProviderError('Malformed content part',False,kind='response_format')
            if part.get('type')=='refusal':
                raise ProviderError('Provider returned refusal output; no action was selected',False,kind='refusal')
            if part.get('type')!='output_text' or not isinstance(part.get('text'),str):
                raise ProviderError('Unsupported response content part',False,kind='response_format')
            chunks.append(part['text'])
        messages.append((phase,''.join(chunks)))
    finals=[text for phase,text in messages if phase=='final_answer']
    if finals:
        selected=''.join(finals)
    elif len(messages)==1 and messages[0][0] is None:
        selected=messages[0][1]
    else:
        raise ProviderError('No unambiguous final answer phase; refusing to guess',False,kind='ambiguous_response')
    if not selected.strip():
        raise ProviderError('Empty final answer',False,kind='response_format')
    raw_usage=response.get('usage') or {};usage={}
    for source,target in (('input_tokens','prompt_tokens'),('output_tokens','completion_tokens'),('total_tokens','total_tokens')):
        value=raw_usage.get(source)
        if type(value) is int and value>=0:usage[target]=value
    if isinstance(raw_usage.get('input_tokens_details'),dict):usage['prompt_tokens_details']=raw_usage['input_tokens_details']
    if isinstance(raw_usage.get('output_tokens_details'),dict):usage['completion_tokens_details']=raw_usage['output_tokens_details']
    return {'id':response.get('id'),'model':response.get('model'),'usage':usage,
            'choices':[{'message':{'role':'assistant','content':selected},'finish_reason':'stop'}]}

