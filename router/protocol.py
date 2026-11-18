"""Bounded, explicit aliases for the coding action contract; no code repair."""
import json
import re


ACTION_TYPES={'read','search','symbols','write','write_chunk','edit','delete','lsp','mcp','verify'}


def aliases(value, mapping, where):
    value=dict(value)
    for alias,canonical in mapping.items():
        if alias in value:
            if canonical in value:
                raise ValueError(f'{where}: conflicting keys {alias!r} and {canonical!r}; use only {canonical!r}')
            value[canonical]=value.pop(alias)
    return value


def normalize_code(value):
    if len(value)==1 and next(iter(value),None) in ('response','result'):
        value=value[next(iter(value))]
        if not isinstance(value,dict):raise ValueError('response/result wrapper must contain exactly one object')
    value=aliases(value,{'operations':'actions','changes':'actions','done':'finish','completed':'finish','description':'summary'},'response')
    if 'type' in value or 'action' in value:
        value={'actions':[value]}
    if 'actions' not in value:return value
    if not isinstance(value['actions'],list) or len(value['actions'])>12:
        raise ValueError('response.actions must be an array of at most 12 actions')
    result=[]
    for index,action in enumerate(value['actions']):
        if not isinstance(action,dict):raise ValueError(f'actions[{index}] must be an object')
        action=aliases(action,{'action':'type','tool':'type','file':'path','file_path':'path',
                              'old_text':'old','oldText':'old','new_text':'new','newText':'new'},f'actions[{index}]')
        kind=action.get('type')
        kind={'read_file':'read','write_file':'write','replace':'edit','delete_file':'delete'}.get(kind,kind)
        if kind not in ACTION_TYPES:raise ValueError(f'actions[{index}].type={kind!r} is not an allowed action; shell commands are not actions')
        action['type']=kind
        if kind in ('write','write_chunk'):action=aliases(action,{'text':'content'},f'actions[{index}]')
        if kind=='verify':
            if set(action)-{'type','check_stage'}:raise ValueError('verify action accepts only check_stage; use the top-level verify flag')
            if 'verify' in value:raise ValueError('verify specified both as flag and action')
            value['verify']=True
            if 'check_stage' in action:
                if 'check_stage' in value:raise ValueError('check_stage specified twice')
                value['check_stage']=action['check_stage']
        else:result.append(action)
    value['actions']=result
    return value


def decode_answer(text, parse_object, role='code'):
    if role!='code':return parse_object(text)
    try:
        return normalize_code(parse_object(text,allow_action_array=True))
    except (ValueError,TypeError) as original:
        # A complete named-file block is also an explicit action contract.
        # Unterminated fences are never applied as partial source files.
        try:
            return fast_path_answer(text,parse_object)
        except (ValueError,TypeError):
            # Do not obscure a useful JSON/schema error with an unrelated
            # FILE-block error unless the response actually used that format.
            if isinstance(text,str) and text.lstrip().startswith(('FILE:', 'SUMMARY:')):
                raise
            raise original


def fast_path_answer(text, parse_object):
    """Decode simple FILE blocks first, then fall back to the normal contract."""
    if not isinstance(text,str):
        raise ValueError('Fast-path response must be text')
    lines=text.replace('\r\n','\n').replace('\r','\n').splitlines(keepends=True)
    actions=[];summary='One-shot patch';index=0
    while index<len(lines) and not lines[index].strip():index+=1
    if index<len(lines) and lines[index].startswith('SUMMARY:'):
        summary=lines[index][len('SUMMARY:'):].strip() or summary
        index+=1
    while index<len(lines):
        while index<len(lines) and not lines[index].strip():index+=1
        if index>=len(lines):break
        if lines[index].strip().lower()=='finish: true':
            index+=1
            if any(line.strip() for line in lines[index:]):raise ValueError('Unexpected text after fast-path finish marker')
            break
        match=re.fullmatch(r'FILE:\s*(\S[^\n]*)\n?',lines[index].rstrip('\n'))
        if not match:raise ValueError('Not a fast-path FILE block response')
        path=match.group(1).strip();index+=1
        if index>=len(lines) or not re.fullmatch(r'```[A-Za-z0-9_+.-]*\n?',lines[index].rstrip('\n')):
            raise ValueError('Fast-path FILE block is missing its code fence')
        index+=1;body=[];closed=False
        while index<len(lines):
            if lines[index].rstrip('\n')=='```':
                closed=True;index+=1;break
            body.append(lines[index]);index+=1
        if not closed:raise ValueError('Fast-path FILE block has an unterminated code fence')
        content=''.join(body)
        actions.append({'type':'write','path':path,'content':content})
        if len(actions)>12:raise ValueError('Fast-path response contains more than 12 files')
    if not actions:raise ValueError('Fast-path response contains no file blocks')
    return normalize_code({'summary':summary,'actions':actions,'finish':True})


def decode_fast_path(text, parse_object):
    try:
        return fast_path_answer(text,parse_object)
    except (ValueError,TypeError):
        # Preserve compatibility with the ordinary JSON action contract.
        return decode_answer(text,parse_object,'code')


def native_answer(message, parse_object):
    calls=message.get('tool_calls') or []
    if len(calls)!=1 or calls[0].get('function',{}).get('name')!='submit_actions':
        raise ValueError('Native protocol requires exactly one declared submit_actions function call')
    # Ordinary tool responses may include narration. It never becomes a host
    # instruction: only the single declared function's validated arguments do.
    return decode_answer(calls[0]['function']['arguments'],parse_object)
