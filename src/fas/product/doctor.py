"""Environment diagnostics exposed by the CLI."""
from .service import ProductService
def run(service: ProductService) -> dict[str,object]:
    return service.doctor()
