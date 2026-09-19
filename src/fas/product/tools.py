"""Installed tool capability discovery without executing repository content."""
from __future__ import annotations
import shutil, subprocess
TOOLS=("git","semgrep","trivy","gitleaks","osv-scanner")
def discover() -> list[dict[str,object]]:
    out=[]
    for name in TOOLS:
        path=shutil.which(name)
        version=None
        if path:
            try:
                p=subprocess.run([path,"--version"],capture_output=True,text=True,timeout=3,check=False)
                version=(p.stdout or p.stderr).splitlines()[0][:256] if (p.stdout or p.stderr) else None
            except (OSError,subprocess.SubprocessError):
                version=None
        out.append({"tool":name,"installed":bool(path),"path":path,"version":version,"supported":name in {"git","semgrep","trivy","gitleaks","osv-scanner"}})
    return out
