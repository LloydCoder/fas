from fas.adapters import AdapterRegistry

def test_registry_contains_initial_adapters():
    registry=AdapterRegistry()
    assert registry.names()==("gitleaks","sarif","semgrep","trivy")
