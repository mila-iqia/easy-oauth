from __future__ import annotations

from dataclasses import dataclass, field

registered_capabilities = {}


@dataclass(frozen=True, eq=False)
class Capability:
    name: str = None
    implies: frozenset[Capability] = field(default_factory=frozenset)

    def __contains__(self, cap):
        return cap is self or any(cap in cap2 for cap2 in self.implies)

    def __str__(self):
        return self.name or "&".join(map(str, self.implies)) or "none"

    __repr__ = __str__
