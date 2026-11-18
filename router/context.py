"""Bounded context without duplicate history or partial source files."""
import copy
import json
from pathlib import Path
import re

from .checks import failure_feedback
from .redaction import redact
from .workspace import files


def compact_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def merge_observation_ranges(previous, current):
    """Keep compatible explicit reads of the same file, with gaps labelled."""
    def parse(value):
        if not isinstance(value, str):
            return None
        spans = []
        for part in re.split(r'\n\n(?=\[LINES \d+-\d+\]\n)', value):
            marker = re.match(r'^\[LINES (\d+)-(\d+)\]\n', part)
            if marker is None:
                return None
            start, end = map(int, marker.groups())
            lines = part[marker.end():].splitlines(keepends=True)
            if not lines or start < 1 or len(lines) > end - start + 1:
                return None
            spans.append((start, lines))
        return spans

    new_spans = parse(current)
    if new_spans is None:
        return current
    old_spans = parse(previous) or []
    rows = {}
    for start, lines in old_spans + new_spans:
        for number, line in enumerate(lines, start):
            if number in rows and rows[number] != line:
                return current
            rows[number] = line

    spans = []
    for number in sorted(rows):
        if not spans or number != spans[-1][0] + len(spans[-1][1]):
            spans.append((number, []))
        spans[-1][1].append(rows[number])
    return '\n\n'.join(
        f'[LINES {start}-{start + len(lines) - 1}]\n' + ''.join(lines)
        for start, lines in spans
    )


def observation_excerpt(name, content, char_budget, byte_budget):
    """Return a clearly labelled prefix of whole lines that fits both budgets."""
    if not isinstance(content, str):
        return None
    requested = re.match(r'^\[LINES (\d+)-(\d+)\]\n', content)
    if content.startswith('[LINES ') and not requested:
        return None
    start = int(requested.group(1)) if requested else 1
    requested_end = int(requested.group(2)) if requested else None
    body = content[requested.end():] if requested else content
    # Multiple explicit slices must not be silently relabelled as one range.
    if requested and '\n\n[LINES ' in body:
        return None
    lines = body.splitlines(keepends=True)
    if requested and (requested_end < start or len(lines) > requested_end - start + 1):
        return None
    if len(lines) < 2:
        return None
    def make(count):
        last = start + count - 1
        total = f'REQUESTED {start}-{requested_end}' if requested else str(len(lines))
        header = (f'[LINES {start}-{last} OF {total}; PARTIAL FILE. '
                  f'Use read with start_line={last + 1} for the rest.]\n')
        return header + ''.join(lines[:count])
    lo, hi, best = 1, len(lines) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        value = make(mid)
        serialized = compact_json({name: value})
        if len(serialized) <= char_budget and len(serialized.encode('utf-8')) <= byte_budget:
            best = value
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def initial_observations(workspace, max_files=12, max_chars=8000):
    """Preload small code-only repositories; larger projects use normal tools."""
    tree=files(workspace.work)
    if len(tree)>max_files:return {}
    suffixes={'.py','.js','.mjs','.cjs','.ts','.tsx','.jsx','.cs','.rs','.go','.html','.css','.sql'}
    result={};used=2
    for name in tree:
        if Path(name).suffix.lower() not in suffixes:continue
        try:text=workspace.text(name)
        except (OSError,ValueError,UnicodeError):continue
        # Never preload credentials or a truncated file that could be overwritten.
        if redact(text)!=text:continue
        size=len(compact_json({name:text}))
        if used+size>max_chars:continue
        result[name]=text;used+=size
    return result


def step_context(steps, fallback=''):
    """Send each recent step once; keep a short digest of older decisions."""
    recent=steps[-4:]
    older='\n'.join(str(item.get('summary',''))[:180] for item in steps[:-4])[-1500:]
    markers=list(re.finditer(r'(?m)^(?:Step|Крок) (\d+):',str(fallback)))
    recent_ids={str(item.get('step')) for item in recent}
    historical=[]
    for i,match in enumerate(markers):
        if match.group(1) not in recent_ids:
            end=markers[i+1].start() if i+1<len(markers) else len(fallback)
            historical.append(fallback[match.start():end].strip())
    if historical:older='\n'.join(historical)[-1500:]
    return recent, older if steps else str(fallback)[-1500:]


def compact_evidence(evidence):
    result={}
    for name,item in evidence.items():
        row=dict(item)
        if row.get('status')=='passed' and len(row.get('report',''))>350:
            row['report']=row['report'][-350:]
            row['report_excerpt']=True
        result[name]=row
    return result


def fits_hard_context_budget(text, model, system, reserve=512):
    """Use the same content limits as Router, with explicit framing headroom."""
    return (len(system) + len(text) + reserve <= model['context_chars']
            and len(system.encode('utf-8')) + len(text.encode('utf-8')) + reserve
            <= model['max_input_tokens'] * 3)


def fit_context(payload, model, system, preferred_observations=None, prefer_complete_observations=False):
    """Prune expendable context before the hard limit, keeping source files whole.

    Uses the same conservative UTF-8/3 estimate as Router. The goal, plan,
    acceptance criteria, verification status/signatures and tool contracts are
    never shortened. If these alone exceed the limit, Router rejects the call.
    This is deterministic compaction; it consumes no additional model calls.
    """
    original = compact_json(payload)
    if not model.get('auto_compact', True):
        return original, None
    char_limit = max(0, int(model['context_chars'] * .8) - len(system))
    byte_limit = max(0, int(model['max_input_tokens'] * 3 * .8) - len(system.encode('utf-8')))
    def fits(value):
        text = compact_json(value)
        return len(text) <= char_limit and len(text.encode('utf-8')) <= byte_limit
    if fits(payload):
        return original, None
    if prefer_complete_observations and fits_hard_context_budget(original, model, system):
        size = len(original.encode('utf-8'))
        return original, {'before_bytes':size, 'after_bytes':size,
                          'before_chars':len(original), 'after_chars':len(original),
                          'removed':[], 'target_met':True,
                          'target_policy':'hard_limit_with_512_framing_reserve',
                          'soft_target_met':False, 'preserved_complete_observations':True}
    value = copy.deepcopy(payload)
    removed = []
    def excerpt(text, limit):
        text = str(text)
        if len(text) <= limit:return text
        marker = '\n[Middle omitted; re-read the source or rerun the check for full output.]\n'
        return text[:limit//2] + marker + text[-limit//2:]
    # Older complete observations are removed, never presented as truncated files.
    observations = value.get('observations', {})
    for name in reversed(list(observations)):
        if fits(value):break
        if len(observations) == 1:
            index = value.get('repository_index')
            if isinstance(index, str) and len(index) > 1500:
                value['repository_index'] = excerpt(index, 1500)
                removed.append('repository_index')
            recent = value.get('recent_steps', [])
            while len(recent) > 1 and not fits(value):
                step = recent.pop(0)
                line = f"Step {step.get('step', '?')}: {str(step.get('summary', ''))[:200]}"
                value['history_digest'] = (str(value.get('history_digest', '')) + '\n' + line)[-1500:]
                removed.append('old_step')
            if fits(value):break
        del observations[name]
        omitted = value.setdefault('omitted_observations', [])
        if name not in omitted:omitted.append(name)
        removed.append('observation:' + name)
    recent = value.get('recent_steps', [])
    while len(recent) > 1 and not fits(value):
        step = recent.pop(0)
        line = f"Step {step.get('step', '?')}: {str(step.get('summary', ''))[:200]}"
        value['history_digest'] = (str(value.get('history_digest', '')) + '\n' + line)[-1500:]
        removed.append('old_step')
    if not fits(value):
        for name, item in value.get('verification', {}).items():
            report = item.get('report')
            if isinstance(report, str) and len(report) > 800:
                item['report'] = excerpt(report, 800)
                item['report_excerpt'] = True
                removed.append('check_report:' + name)
        for key, limit in (('feedback', 1400), ('repository_index', 1500), ('history_digest', 700)):
            if not fits(value) and isinstance(value.get(key), str) and len(value[key]) > limit:
                value[key] = failure_feedback(value[key], limit) if key == 'feedback' else excerpt(value[key], limit)
                removed.append(key)
    if not fits(value) and len(value.get('files', [])) > 30:
        value['omitted_file_count'] = len(value['files']) - 30
        value['files'] = value['files'][:30]
        value['file_tree_excerpt'] = True
        removed.append('file_tree')
    # Observations are ordered newest first by the executor. If compaction
    # removed the newest read, return a labelled prefix in remaining space so
    # the model can select a line range instead of repeatedly requesting it.
    original_observations = payload.get('observations', {})
    if original_observations and fits(value):
        preferred_observations = preferred_observations or {}
        name = next((name for name in preferred_observations if name in original_observations),
                    next(iter(original_observations)))
        if name not in value.get('observations', {}) and name in value.get('omitted_observations', []):
            current = compact_json(value)
            remaining_chars = char_limit - len(current) - 64
            remaining_bytes = byte_limit - len(current.encode('utf-8')) - 64
            preferred = preferred_observations.get(name)
            serialized = compact_json({name: preferred}) if preferred else ''
            if preferred and len(serialized) <= remaining_chars and len(serialized.encode('utf-8')) <= remaining_bytes:
                partial = preferred
            else:
                partial = observation_excerpt(name, preferred or original_observations[name],
                    remaining_chars, remaining_bytes)
            if partial:
                value.setdefault('observations', {})[name] = partial
                if fits(value):
                    removed.append('observation_excerpt:' + name)
                else:
                    del value['observations'][name]
    compacted = compact_json(value)
    metric = {'before_bytes': len(original.encode('utf-8')),
              'after_bytes': len(compacted.encode('utf-8')),
              'before_chars': len(original), 'after_chars': len(compacted),
              'removed': removed, 'target_met': fits(value)}
    return compacted, metric
