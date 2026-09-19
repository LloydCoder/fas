"""External security-tool output adapters."""
from .gitleaks import GitleaksAdapter
from .sarif import SarifAdapter
from .semgrep import SemgrepAdapter
from .trivy import TrivyAdapter
__all__=["GitleaksAdapter","SarifAdapter","SemgrepAdapter","TrivyAdapter"]
