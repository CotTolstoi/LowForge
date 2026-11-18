"""Optional local-server structured output. Runtime validation remains authoritative."""


def object_schema(properties, required=()):
    return {'type':'object','properties':properties,'required':list(required),'additionalProperties':False}


def response_schema(role):
    string={'type':'string'}
    strings={'type':'array','items':string}
    nullable_string={'anyOf':[string,{'type':'null'}]}
    nullable_integer={'anyOf':[{'type':'integer'},{'type':'null'}]}
    if role=='plan':
        schema=object_schema({'plan':dict(strings,minItems=1,maxItems=12)},['plan'])
    elif role=='supervisor':
        citation=object_schema({'type':{'type':'string','enum':['check']},'name':string,'detail':string},['type','name','detail'])
        schema=object_schema({'diagnosis':string,'instruction':string,'evidence':{'type':'array','items':citation,'minItems':1,'maxItems':5}},
                             ['diagnosis','instruction','evidence'])
    elif role=='review':
        check_citation=object_schema({'type':{'type':'string','enum':['check']},'name':string,'detail':string},['type','name','detail'])
        file_citation=object_schema({'type':{'type':'string','enum':['file']},'path':string,'detail':string},['type','path','detail'])
        assessment=object_schema({'id':string,'met':{'type':'boolean'},
            'evidence':{'type':'array','items':{'anyOf':[check_citation,file_citation]},'minItems':1,'maxItems':8}},['id','met','evidence'])
        schema={'anyOf':[
            object_schema({'read_files':dict(strings,maxItems=8)},['read_files']),
            object_schema({'approved':{'type':'boolean'},'issues':strings,'criteria':{'type':'array','items':assessment}},['approved','issues','criteria'])]}
    else:
        actions=[]
        for kind,extra,required,has_path in (
            ('read',{'start_line':nullable_integer,'end_line':nullable_integer},('start_line','end_line'),True),
            ('search',{'query':string,'paths':{'type':'array','items':string,'maxItems':20}},('query','paths'),False),
            ('symbols',{'query':string,'paths':{'type':'array','items':string,'maxItems':20}},('query','paths'),False),
            ('lsp',{'operation':{'type':'string','enum':['document_symbols','workspace_symbols','definition','references']},
                'line':nullable_integer,'character':nullable_integer,'query':string},('operation','line','character','query'),True),
            ('mcp',{'server':string,'tool':string,'arguments':string},('server','tool','arguments'),False),
            ('write',{'content':string},('content',),True),
            ('write_chunk',{'content':string,'offset_bytes':{'type':'integer','minimum':0}},('content','offset_bytes'),True),
            ('edit',{'old':string,'new':string},('old','new'),True),
            ('delete',{},(),True)):
            properties={'type':{'type':'string','enum':[kind]},**({'path':string} if has_path else {}),**extra}
            actions.append(object_schema(properties,['type',*(['path'] if has_path else []),*required]))
        schema=object_schema({'summary':string,'actions':{'type':'array','items':{'anyOf':actions},'maxItems':12},
            'finish':{'type':'boolean'},'verify':{'type':'boolean'},
            'check_stage':{'anyOf':[{'type':'string','enum':['all','fast','integration','e2e','acceptance','regression']},{'type':'null'}]},
            'blocked':nullable_string},['summary','actions','finish','verify','check_stage','blocked'])
    return {'type':'json_schema','json_schema':{'name':'lowforge_'+role,'strict':True,'schema':schema}}
