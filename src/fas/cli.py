"""Small structured CLI for deterministic Phase 5 verification.

The CLI accepts explicit JSON snapshot/graph contracts and never executes repository commands.
Product-scale API/worker orchestration remains Phase 6.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from fas import __version__
from fas.domain import AttackPath, Finding, Remediation, Snapshot
from fas.graph import GraphEngine
from fas.verification import VerificationEngine


def _load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _dump(value) -> None:
    print(json.dumps(value.model_dump(mode="json") if hasattr(value,"model_dump") else value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="fas",description="Forensic Agent Security")
    p.add_argument("--version",action="version",version=__version__)
    sub=p.add_subparsers(dest="command")
    verify=sub.add_parser("verify",help="verify remediation between two explicit snapshots")
    for name in ("finding","remediation","original-snapshot","candidate-snapshot","original-graph","candidate-graph"):
        verify.add_argument(f"--{name}",required=True)
    verify.add_argument("--original-paths",required=True,help="JSON array of persisted AttackPath objects")
    return p


def main(argv: list[str] | None = None) -> None:
    parser=build_parser()
    args=parser.parse_args(argv)
    if args.command=="verify":
        finding=Finding.model_validate(_load(args.finding))
        remediation=Remediation.model_validate(_load(args.remediation))
        original=Snapshot.model_validate(_load(args.original_snapshot))
        candidate=Snapshot.model_validate(_load(args.candidate_snapshot))
        before=GraphEngine.from_json(Path(args.original_graph).read_text(encoding="utf-8"))
        after=GraphEngine.from_json(Path(args.candidate_graph).read_text(encoding="utf-8"))
        paths=tuple(AttackPath.model_validate(x) for x in _load(args.original_paths))
        outcome=VerificationEngine().verify(
            finding=finding,remediation=remediation,original_snapshot=original,candidate_snapshot=candidate,
            original_graph=before,candidate_graph=after,original_paths=paths,
        )
        _dump(outcome.result)
        return
    parser.print_help()


if __name__=="__main__":
    main()
