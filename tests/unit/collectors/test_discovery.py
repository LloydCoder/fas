from fas.collectors import CollectionContext,DependencyDiscoveryCollector,RepositoryDiscoveryCollector

def test_repository_discovery_hashes_files_and_skips_git(tmp_path):
    (tmp_path/"app.py").write_text("print('ok')",encoding="utf-8")
    (tmp_path/"pyproject.toml").write_text("[project]\nname='demo'\ndependencies=['pydantic>=2']\n",encoding="utf-8")
    (tmp_path/".git").mkdir()
    (tmp_path/".git"/"secret.txt").write_text("ignored",encoding="utf-8")
    context=CollectionContext(analysis_id="analysis_01J00000000000000000000000",snapshot_id="snapshot_01J00000000000000000000000",root=tmp_path,repository="fixture")
    batch=RepositoryDiscoveryCollector().collect(context)
    assert {item.name for item in batch.artifacts}=={"app.py","pyproject.toml"}
    assert all(item.content_hash for item in batch.artifacts)

def test_dependency_discovery_is_data_only(tmp_path):
    (tmp_path/"package.json").write_text('{"dependencies":{"demo":"1.0.0"},"devDependencies":{"test":"2.0.0"}}',encoding="utf-8")
    context=CollectionContext(analysis_id="analysis_01J00000000000000000000000",snapshot_id="snapshot_01J00000000000000000000000",root=tmp_path,repository="fixture")
    batch=DependencyDiscoveryCollector().collect(context)
    assert batch.observations[0].observed_value["dependencies"]["demo"]=="1.0.0"
