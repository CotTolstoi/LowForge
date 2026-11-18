"""Conservative masking for credentials in persisted logs and check reports."""
import re

_PATTERNS=(
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{12,}'),
    re.compile(r'''(?i)(\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|passwd)\b\s*[:=]\s*["']?)[^\s"'&,;]{8,}'''),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
)


def redact(value):
    """Mask common credential forms while preserving useful context around them."""
    text=str(value)
    text=_PATTERNS[0].sub('[REDACTED_AWS_KEY]',text)
    text=_PATTERNS[1].sub(r'\1[REDACTED]',text)
    text=_PATTERNS[2].sub(r'\1[REDACTED]',text)
    return _PATTERNS[3].sub('[REDACTED_PRIVATE_KEY]',text)
