"""Custom JSON helpers for vault data — handles datetime.date from YAML frontmatter.

Importowany jako `from . import json_utils as json`, więc MUSI być drop-inem dla
funkcji stdlib, których używają narzędzia: `dumps` (z custom encoderem), `loads`
oraz wyjątek `JSONDecodeError`. W21 (audyt s1099): brakowało `loads`/`JSONDecodeError`
→ `search._search_ripgrep` (parsujący `rg --json`) wywalał się na AttributeError przy
pierwszej linii wyniku, więc wyszukiwanie z ripgrepem było całkowicie zepsute na
maszynach z `rg` (VPS). Domknięcie aliasu jako pełnego drop-ina naprawia ścieżkę.
"""

import datetime
import json
from json import JSONDecodeError  # re-export — alias `as json` wymaga `json.JSONDecodeError`

__all__ = ["JSONDecodeError", "VaultEncoder", "dumps", "loads"]


class VaultEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        return super().default(obj)


def dumps(obj, **kwargs):
    """json.dumps z VaultEncoder — drop-in replacement."""
    return json.dumps(obj, cls=VaultEncoder, **kwargs)


def loads(s, **kwargs):
    """json.loads — drop-in replacement (parę z custom dumps; W21)."""
    return json.loads(s, **kwargs)
