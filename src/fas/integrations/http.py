"""Secure outbound integration primitives and GitHub source connector."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
import json
import urllib.request
from urllib.error import HTTPError

@dataclass(frozen=True, slots=True)
class ConnectorResponse:
    status:int
    headers:dict[str,str]
    body:bytes
    next_cursor:str|None=None

class ConnectorError(RuntimeError): ...

class SecureHttpClient:
    def __init__(self,allowed_hosts:frozenset[str],timeout:float=15.0,max_response_bytes:int=2*1024*1024):
        if timeout<=0 or max_response_bytes<1: raise ValueError("invalid connector limits")
        self.allowed_hosts=allowed_hosts; self.timeout=timeout; self.max_response_bytes=max_response_bytes
    def request(self,url:str,*,token:str|None=None,accept:str="application/json")->ConnectorResponse:
        parsed=urlparse(url)
        if parsed.scheme!="https" or not parsed.hostname or parsed.hostname.lower() not in self.allowed_hosts:
            raise PermissionError("connector URL is outside the configured HTTPS host allowlist")
        if parsed.username or parsed.password: raise PermissionError("connector URL cannot contain credentials")
        headers={"Accept":accept,"User-Agent":"FAS-enterprise-connector/1"}
        if token: headers["Authorization"]=f"Bearer {token}"
        req=urllib.request.Request(url,headers=headers,method="GET")
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        try:
            opener=urllib.request.build_opener(NoRedirect)
            with opener.open(req,timeout=self.timeout) as response:
                location=response.headers.get("Location")
                if location: raise ConnectorError("connector redirects are not permitted")
                length=response.headers.get("Content-Length")
                if length and int(length)>self.max_response_bytes: raise ConnectorError("connector response exceeds limit")
                chunks=[]; total=0
                while True:
                    chunk=response.read(min(65536,self.max_response_bytes-total+1))
                    if not chunk: break
                    total+=len(chunk)
                    if total>self.max_response_bytes: raise ConnectorError("connector response exceeds limit")
                    chunks.append(chunk)
                return ConnectorResponse(response.status,{k:v for k,v in response.headers.items()},b"".join(chunks))
        except HTTPError as exc:
            if 300<=exc.code<400: raise ConnectorError("connector redirects are not permitted") from exc
            raise ConnectorError("connector request failed") from exc
        except ConnectorError:
            raise
        except Exception as exc:
            raise ConnectorError("connector request failed") from exc

class GitHubConnector:
    host="api.github.com"
    def __init__(self,client:SecureHttpClient,token:str):
        if not token: raise ValueError("GitHub token is required")
        self.client=client; self.token=token
    def repository(self,owner:str,name:str)->dict[str,Any]:
        if not owner or not name or "/" in owner or "/" in name: raise ValueError("invalid repository coordinates")
        response=self.client.request(f"https://api.github.com/repos/{owner}/{name}",token=self.token)
        if response.status!=200: raise ConnectorError(f"GitHub repository request returned {response.status}")
        return json.loads(response.body)
    def pull_request(self,owner:str,name:str,number:int)->dict[str,Any]:
        if number<1: raise ValueError("pull request number must be positive")
        response=self.client.request(f"https://api.github.com/repos/{owner}/{name}/pulls/{number}",token=self.token)
        if response.status!=200: raise ConnectorError(f"GitHub pull request request returned {response.status}")
        return json.loads(response.body)
