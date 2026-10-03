"""Deterministic evidence correlation and temporal indexing."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json
from datetime import datetime, timedelta
from fas.domain.evidence import Evidence
from fas.domain.common import EvidenceId

@dataclass(frozen=True, slots=True)
class CorrelationGroup:
    fingerprint: str
    evidence_ids: tuple[EvidenceId, ...]

@dataclass(frozen=True, slots=True)
class TemporalEvidence:
    evidence_ids: tuple[EvidenceId, ...]
    complete: bool

class EvidenceCorrelationEngine:
    """Correlates evidence without changing or weakening evidence records."""

    @staticmethod
    def fingerprint(evidence: Evidence) -> str:
        location = evidence.metadata.get("location", "")
        payload = {
            "type": evidence.type.value,
            "claim": " ".join(evidence.claim.split()),
            "location": location,
            "observed_value": evidence.observed_value,
            "artifact_ids": tuple(sorted(evidence.related_artifact_ids)),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return "sha256:" + sha256(canonical.encode("utf-8")).hexdigest()

    def groups(self, evidence: tuple[Evidence, ...]) -> tuple[CorrelationGroup, ...]:
        buckets: dict[str, list[EvidenceId]] = {}
        for item in evidence:
            buckets.setdefault(self.fingerprint(item), []).append(item.id)
        return tuple(
            CorrelationGroup(key, tuple(sorted(ids)))
            for key, ids in sorted(buckets.items())
        )

    def within(self, evidence: tuple[Evidence, ...], *, start: datetime | None = None,
               end: datetime | None = None, window: timedelta | None = None) -> TemporalEvidence:
        if start is not None and (start.tzinfo is None or start.utcoffset() is None):
            raise ValueError("start must be timezone-aware")
        if end is not None and (end.tzinfo is None or end.utcoffset() is None):
            raise ValueError("end must be timezone-aware")
        if start is not None and end is not None and end < start:
            raise ValueError("end cannot precede start")
        if window is not None and window < timedelta(0):
            raise ValueError("window cannot be negative")
        values = sorted(evidence, key=lambda item: (item.observed_at, item.id))
        if window is not None:
            if start is None:
                raise ValueError("window requires start")
            end = start + window
        selected = tuple(item.id for item in values
                         if (start is None or item.observed_at >= start)
                         and (end is None or item.observed_at <= end))
        return TemporalEvidence(selected, True)
