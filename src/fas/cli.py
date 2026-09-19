"""First-class FAS CLI. API and CLI share the ProductService and never fabricate security conclusions."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
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
    a=sub.add_parser("analyze"); subcommands.append(a); a.add_argument("path"); a.add_argument("--project",default=None)
    for name,help_text in (
        ("status","show analysis status"),("findings","show findings"),("evidence","show evidence references"),
        ("graph","show persisted graph information"),("attack-paths","show persisted attack paths"),
        ("investigate","start an investigation"),("remediate","create a remediation"),
        ("verify-remediation","verify a remediation"),("verification","show verification"),
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
    if args.command=="analyze":
        root=Path(args.path).resolve()
        project=service.create_project(args.project or root.name,str(root))
        result=service.analyze_sync(project.id,root)
        dump(result,args.format); return 0
    if args.command=="status":
        dump(service.get_analysis(args.id).model_dump(mode="json"),args.format); return 0
    if args.command=="findings":
        dump({"items":service.findings(args.id)},args.format); return 0
    if args.command=="report":
        report=service.report(args.id)
        dump(report,args.format); return 0
    if args.command in {"evidence","graph","attack-paths","investigate","remediate","verify-remediation","verification"}:
        dump({"status":"UNSUPPORTED","code":"CAPABILITY_NOT_AVAILABLE","resource_id":args.id,
              "message":"The current repository does not expose a persisted product backend for this operation; FAS will not fabricate one."},args.format)
        return 3
    return 2

if __name__=="__main__":
    raise SystemExit(main())
