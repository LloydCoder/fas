"""Secure outbound integration primitives and GitHub source connector."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
import json
import urllib.request

@dataclass(frozen=True, slots=True)
class ConnectorResponse:
    status:int
    headers:dict[str,str]
    body:bytes
    next_cursor:str|None=None

class ConnectorError(RuntimeError): ...

class SecureHttpClient:
    def __init__(self,allowed_hosts:frozenset[str],timeout:float=15.0):
        if timeout<=0: raise ValueError("timeout must be positive")
        self.allowed_hosts=allowed_hosts; self.timeout=timeout
    def request(self,url:str,*,token:str|None=None,accept:str="application/json")->ConnectorResponse:
        parsed=urlparse(url)
        if parsed.scheme!="https" or not parsed.hostname or parsed.hostname.lower() not in self.allowed_hosts:
            raise PermissionError("connector URL is outside the configured HTTPS host allowlist")
        if parsed.username or parsed.password: raise PermissionError("connector URL cannot contain credentials")
        headers={"Accept":accept,"User-Agent":"FAS-enterprise-connector/1"}
        if token: headers["Authorization"]=f"Bearer {token}"
        req=urllib.request.Request(url,headers=headers,method="GET")
        try:
            with urllib.request.urlopen(req,timeout=self.timeout) as response:
                return ConnectorResponse(response.status,{k:v for k,v in response.headers.items()},response.read())
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
