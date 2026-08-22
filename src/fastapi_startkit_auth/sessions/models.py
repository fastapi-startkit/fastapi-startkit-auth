from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SessionRecord:
    """Server-side record backing one session cookie.

    The cookie carries only the opaque ``id``; everything else lives in the
    store, so invalidation is authoritative. ``csrf_token`` is issued here so
    Phase 2's CSRF protection can bind to the session without a model change.
    """

    id: str
    user_id: Any
    guard: str
    csrf_token: str
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    expires_at: float | None = None

    def expired(self, idle_ttl: float | None = None, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        if self.expires_at is not None and self.expires_at < now:
            return True
        return idle_ttl is not None and self.last_activity + idle_ttl < now
