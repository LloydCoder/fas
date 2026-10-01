"""Production S3-compatible content-addressed object store."""
from __future__ import annotations
import hashlib
from typing import Any
class S3ObjectStore:
    def __init__(self,uri:str,*,client:Any=None)->None:
        if not uri.startswith("s3://"): raise ValueError("S3 object store URI must use s3://")
        value=uri[5:]; bucket,_,prefix=value.partition("/")
        if not bucket: raise ValueError("S3 bucket is required")
        self.bucket,self.prefix=bucket,prefix.strip("/")
        if client is None:
            try: import boto3
            except ImportError as exc: raise RuntimeError("S3 support requires the production dependency set") from exc
            client=boto3.client("s3")
        self.client=client
    def _key(self,digest:str)->str:
        digest=digest.removeprefix("sha256:")
        if len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest.lower()): raise ValueError("invalid sha256 content hash")
        base=f"{digest[:2]}/{digest}"
        return f"{self.prefix}/{base}" if self.prefix else base
    def put(self,data:bytes,*,media_type:str,snapshot_id:str,source:str)->dict[str,Any]:
        digest=hashlib.sha256(data).hexdigest(); key=self._key(digest)
        try:
            self.client.put_object(Bucket=self.bucket,Key=key,Body=data,ContentType=media_type,Metadata={"snapshot-id":snapshot_id,"source":source[:1024]},IfNoneMatch="*")
        except Exception as exc:
            code=getattr(exc,"response",{}).get("Error",{}).get("Code")
            if str(code) not in {"PreconditionFailed","412"}: raise
        return {"artifact_id":f"sha256:{digest}","content_hash":f"sha256:{digest}","media_type":media_type,"size":len(data),"snapshot_id":snapshot_id,"source":source,"storage_reference":f"s3://{self.bucket}/{key}"}
    def get(self,content_hash:str)->bytes:
        key=self._key(content_hash); data=self.client.get_object(Bucket=self.bucket,Key=key)["Body"].read()
        digest=content_hash.removeprefix("sha256:")
        if hashlib.sha256(data).hexdigest()!=digest: raise OSError("content-addressed object integrity check failed")
        return data
