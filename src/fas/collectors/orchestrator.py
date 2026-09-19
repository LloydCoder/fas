"""Deterministic bounded collection orchestration."""
from __future__ import annotations
from dataclasses import dataclass
from time import monotonic
from .base import CollectionBatch
from .contracts import CollectionPlan,CollectionResult,CollectionStatus,CollectionSummary,CollectorOutcome,RetryDisposition
from .raw import stable_run_id
from .executor import CancellationToken

@dataclass(slots=True)
class CollectionOrchestrator:
    def run(self,plan:CollectionPlan,*,cancel:CancellationToken|None=None)->CollectionResult:
        outcomes=[]; artifacts={}; observations={}; warnings=[]; skipped=0
        run_id=stable_run_id(plan.context)
        for collector,spec in zip(plan.collectors,plan.specs):
            if not spec.enabled: continue
            if cancel and cancel.cancelled:
                outcomes.append(CollectorOutcome(collector.name,CollectionStatus.CANCELLED,0,error="cancelled"))
                if plan.fail_fast: break
                continue
            started=monotonic(); batch=CollectionBatch(); status=CollectionStatus.SUCCESS; error=None; retry=RetryDisposition.DO_NOT_RETRY; attempts=0
            while attempts<spec.max_attempts:
                attempts+=1
                try:
                    batch=collector.collect(plan.context)
                    status=CollectionStatus.SUCCESS if batch.complete else CollectionStatus.PARTIAL
                    break
                except TimeoutError as exc:
                    status=CollectionStatus.TIMEOUT; error=str(exc); retry=RetryDisposition.RETRY if attempts<spec.max_attempts else RetryDisposition.DO_NOT_RETRY
                except (ValueError,TypeError) as exc:
                    status=CollectionStatus.INVALID_INPUT; error=str(exc); retry=RetryDisposition.DO_NOT_RETRY; break
                except Exception as exc:
                    status=CollectionStatus.FAILED; error=f"{type(exc).__name__}: {exc}"
                    retry=RetryDisposition.RETRY if attempts<spec.max_attempts else RetryDisposition.DO_NOT_RETRY
                if retry==RetryDisposition.DO_NOT_RETRY: break
            duration=int((monotonic()-started)*1000)
            outcomes.append(CollectorOutcome(collector.name,status,attempts,batch,error,duration,retry))
            for a in batch.artifacts: artifacts[a.id]=a
            for o in batch.observations: observations[o.id]=o
            skipped+=batch.skipped; warnings.extend(batch.warnings)
            if plan.fail_fast and status not in {CollectionStatus.SUCCESS,CollectionStatus.PARTIAL}: break
        merged=CollectionBatch(tuple(artifacts[k] for k in sorted(artifacts)),tuple(observations[k] for k in sorted(observations)),all(o.status in {CollectionStatus.SUCCESS,CollectionStatus.PARTIAL} for o in outcomes),skipped,tuple(warnings))
        if any(o.status in {CollectionStatus.FAILED,CollectionStatus.TIMEOUT,CollectionStatus.CANCELLED,CollectionStatus.TOOL_ERROR,CollectionStatus.RESOURCE_LIMIT,CollectionStatus.INVALID_INPUT} for o in outcomes):
            overall=CollectionStatus.PARTIAL if any(o.batch.artifacts or o.batch.observations for o in outcomes) else CollectionStatus.FAILED
        elif any(o.status==CollectionStatus.PARTIAL for o in outcomes): overall=CollectionStatus.PARTIAL
        else: overall=CollectionStatus.SUCCESS
        summary=CollectionSummary(overall,tuple(outcomes),len(merged.artifacts),len(merged.observations),merged.skipped,merged.warnings)
        return CollectionResult(plan,tuple(outcomes),merged,summary,run_id,True)
