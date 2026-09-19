"""Phase 3 collection baseline benchmark.

Engineering baseline only; it is not a production capacity claim.
"""
from __future__ import annotations
import json,tempfile,time
from pathlib import Path
from fas.adapters import SemgrepAdapter
from fas.collectors import CollectionContext,ObservationNormalizer,RepositoryDiscoveryCollector
from fas.domain.common import new_id

def main():
    with tempfile.TemporaryDirectory() as raw:
        root=Path(raw)
        for index in range(250):
            (root/f"module_{index:04d}.py").write_text("value = 1\n",encoding="utf-8")
        context=CollectionContext(analysis_id=new_id("analysis"),snapshot_id=new_id("snapshot"),root=root,repository="benchmark")
        start=time.perf_counter(); batch=RepositoryDiscoveryCollector().collect(context); discovery=time.perf_counter()-start
        payload={"results":[{"check_id":"R1","path":f"module_{i:04d}.py","start":{"line":1,"col":1},"end":{"line":1,"col":9},"extra":{"message":"candidate"}} for i in range(1000)]}
        start=time.perf_counter(); observations=SemgrepAdapter().parse(payload,context); parse=time.perf_counter()-start
        start=time.perf_counter(); evidence=ObservationNormalizer().normalize_many(observations,context); normalize=time.perf_counter()-start
        print(json.dumps({"artifacts":len(batch.artifacts),"observations":len(observations),"evidence":len(evidence),"discovery_seconds":round(discovery,6),"adapter_seconds":round(parse,6),"normalization_seconds":round(normalize,6)},sort_keys=True))

if __name__=="__main__":
    main()
