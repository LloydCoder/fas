from fas.analysis import AnalyzerRegistry

class A:
    name="test"; version="1"
    def analyze(self, context): raise AssertionError("not invoked")

def test_registry_is_deterministic_and_rejects_duplicates():
    r=AnalyzerRegistry(); r.register(A())
    assert r.names()==("test",)
    try: r.register(A())
    except ValueError: pass
    else: raise AssertionError("duplicate analyzer accepted")
