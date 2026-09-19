"""First-class FAS CLI. API and CLI share the ProductService and never fabricate security conclusions."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from fas.domain import AttackPath, Finding, Remediation, Snapshot
from fas.graph import GraphEngine
from fas.verification import VerificationEngine
from fas import __version__
from fas.product import ProductService, load_settings
from fas.product.tools import discover

def dump(value: object, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(value, sort_keys=True, indent=2))
    else:
        if isinstance(value, dict):
            for k,v in value.items(): print(f"{k}: {v}")
        else: print(value)

def build_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="fas",description="Forensic Agent Security")
    p.add_argument("--version",action="version",version=__version__)
    p.add_argument("--config",default=None,help="JSON configuration file")
    p.add_argument("--format",choices=("human","json"),default="human")
    sub=p.add_subparsers(dest="command",required=True)
    subcommands=[]
    verify=sub.add_parser("verify",help="verify remediation from explicit persisted contracts")
    for name in ("finding","remediation","original-snapshot","candidate-snapshot","original-graph","candidate-graph","original-paths"):
        verify.add_argument(f"--{name}",required=True)
    subcommands.append(verify)
    a=sub.add_parser("analyze"); subcommands.append(a); a.add_argument("path"); a.add_argument("--project",default=None)
    for name,help_text in (
        ("status","show analysis status"),("findings","show findings"),
        ("report","generate or show report")):
        q=sub.add_parser(name,help=help_text); subcommands.append(q); q.add_argument("id")
    doctor=sub.add_parser("doctor"); tools=sub.add_parser("tools"); api=sub.add_parser("api")
    subcommands.extend((doctor,tools,api))
    for command in subcommands:
        command.add_argument("--format",choices=("human","json"),default=argparse.SUPPRESS)
    return p

def main(argv: list[str]|None=None) -> int:
    args=build_parser().parse_args(argv)
    settings=load_settings(args.config)
    service=ProductService(settings)
    if args.command=="doctor":
        result=service.doctor()
        dump(result,args.format); return 0 if result["ok"] else 2
    if args.command=="tools":
        dump(discover(),args.format); return 0
    if args.command=="api":
        from fas.product.api import ApiServer
        ApiServer(service).serve(settings.api_host,settings.api_port); return 0
    if args.command=="verify":
        def load(path: str): return json.loads(Path(path).read_text(encoding="utf-8"))
        finding=Finding.model_validate(load(args.finding)); remediation=Remediation.model_validate(load(args.remediation))
        original=Snapshot.model_validate(load(args.original_snapshot)); candidate=Snapshot.model_validate(load(args.candidate_snapshot))
        before=GraphEngine.from_json(Path(args.original_graph).read_text(encoding="utf-8"))
        after=GraphEngine.from_json(Path(args.candidate_graph).read_text(encoding="utf-8"))
        paths=tuple(AttackPath.model_validate(x) for x in load(args.original_paths))
        outcome=VerificationEngine().verify(finding=finding,remediation=remediation,original_snapshot=original,candidate_snapshot=candidate,original_graph=before,candidate_graph=after,original_paths=paths)
        dump(outcome.result,args.format)
        return 0 if outcome.result.result.value not in {"UNKNOWN", "REMEDIATION_FAILED", "REGRESSED"} else 2
    if args.command=="analyze":
        root=Path(args.path).resolve()
        project=service.create_project(args.project or root.name,str(root))
        result=service.analyze_sync(project.id,root)
        dump(result,args.format)
        status=result["analysis"].get("status")
        return 2 if status in {"PARTIAL","FAILED","CANCELLED"} else 0

    if args.command=="status":
        dump(service.get_analysis(args.id).model_dump(mode="json"),args.format); return 0
    if args.command=="findings":
        dump({"items":service.findings(args.id)},args.format); return 0
    if args.command=="report":
        report=service.report(args.id)
        dump(report,args.format)
        summary=report.get("content",{}).get("executive_summary",{})
        return 2 if summary.get("completeness") in {"PARTIAL","TRUNCATED","UNKNOWN"} else 0
    return 2

if __name__=="__main__":
    raise SystemExit(main())
