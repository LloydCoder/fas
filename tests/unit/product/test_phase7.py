from __future__ import annotations
import hashlib
from fas.product.config import Settings
from fas.product.object_store import S3ObjectStore
from fas.product.tenancy import Role, TenantContext

class Body:
    def __init__(self,data:bytes): self.data=data
    def read(self): return self.data

class S3:
    def __init__(self): self.objects={}
    def put_object(self,**kwargs):
        key=(kwargs["Bucket"],kwargs["Key"])
        if key in self.objects and kwargs.get("IfNoneMatch")=="*":
            exc=type("Precondition",(Exception,),{})()
            exc.response={"Error":{"Code":"PreconditionFailed"}}
            raise exc
        self.objects[key]=kwargs["Body"]
    def get_object(self,**kwargs):
        return {"Body":Body(self.objects[(kwargs["Bucket"],kwargs["Key"])])}

def test_tenant_authorization_is_deny_by_default():
    reader=TenantContext("tenant-a","alice",Role.READER)
    try: reader.require(Role.ANALYST,Role.ADMIN)
    except PermissionError: pass
    else: raise AssertionError("reader was authorized to write")
    assert TenantContext("tenant-a","alice",Role.ADMIN).can_admin()

def test_s3_store_is_content_addressed_and_idempotent():
    client=S3()
    store=S3ObjectStore("s3://bucket/fas",client=client)
    data=b"evidence"
    first=store.put(data,media_type="application/octet-stream",snapshot_id="snapshot_test",source="fixture")
    second=store.put(data,media_type="application/octet-stream",snapshot_id="snapshot_test",source="fixture")
    expected="sha256:"+hashlib.sha256(data).hexdigest()
    assert first["content_hash"]==second["content_hash"]==expected
    assert store.get(expected)==data

def test_hosted_configuration_is_explicit():
    settings=Settings(database_url="postgresql://db/fas",object_store_path="s3://bucket/fas",tenant_id="tenant-a",subject_id="alice",role="analyst")
    assert settings.tenant_id=="tenant-a"
    assert settings.role=="analyst"
