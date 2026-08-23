from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ApiTokenRecord:
    """Server-side record backing one opaque API token.

    The caller holds ``"{id}|{secret}"``; this record stores only the SHA-256
    hex digest of the secret, so a leaked store cannot mint valid tokens.
    ``abilities`` reuse the scope vocabulary (``["*"]`` = unrestricted), so
    ``require_scopes`` works unchanged on token-authenticated requests.
    """

    id: str
    user_id: Any
    token_hash: str
    name: str | None = None
    abilities: list[str] = field(default_factory=lambda: ["*"])
    last_used_at: float | None = None
    expires_at: float | None = None
    created_at: float = field(default_factory=lambda: time.time())

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < time.time()
