"""Custom JSON encoder for vault data — handles datetime.date from YAML frontmatter."""

import datetime
import json


class VaultEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        return super().default(obj)


def dumps(obj, **kwargs):
    """json.dumps with VaultEncoder — drop-in replacement."""
    return json.dumps(obj, cls=VaultEncoder, **kwargs)
