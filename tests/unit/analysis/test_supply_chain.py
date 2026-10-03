import pytest
from fas.analysis import CycloneDXInventoryParser

def test_cyclonedx_inventory_is_normalized_and_bounded():
    doc={"bomFormat":"CycloneDX","specVersion":"1.7",
         "components":[{"bom-ref":"pkg:a","name":"a","version":"1.0","purl":"pkg:pypi/a@1.0"}],
         "dependencies":[{"ref":"pkg:a","dependsOn":["pkg:b"]}]}
    inv=CycloneDXInventoryParser().parse(doc)
    assert inv.spec_version=="1.7"
    assert inv.components[0].bom_ref=="pkg:a"
    assert inv.dependencies[0].target=="pkg:b"

def test_cyclonedx_limits_are_enforced():
    with pytest.raises(ValueError):
        CycloneDXInventoryParser(max_components=1).parse({"bomFormat":"CycloneDX","specVersion":"1.7",
            "components":[{"bom-ref":"a","name":"a","version":"1"},{"bom-ref":"b","name":"b","version":"1"}]})
