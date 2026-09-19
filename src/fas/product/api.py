"""Bounded dependency-light HTTP API with stable /v1 contracts."""
from __future__ import annotations
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from .service import ProductService

MAX_BODY_BYTES=1_000_000
MAX_HEADER_BYTES=16_384
MAX_JSON_DEPTH=32
MAX_JSON_ITEMS=10_000

OPENAPI={"openapi":"3.1.0","info":{"title":"FAS API","version":"v1"},"paths":{
"/health/live":{"get":{"responses":{"200":{"description":"live"}}}},
"/health/ready":{"get":{"responses":{"200":{"description":"ready"}}}},
"/openapi.json":{"get":{"responses":{"200":{"description":"OpenAPI document"}}}},
"/v1/projects":{"post":{"responses":{"201":{"description":"created"}}}},
"/v1/projects/{id}":{"get":{"responses":{"200":{"description":"project"}}}},
"/v1/analyses":{"post":{"responses":{"201":{"description":"created"}}}},
"/v1/analyses/{id}":{"get":{"responses":{"200":{"description":"analysis"}}}},
"/v1/analyses/{id}/status":{"get":{"responses":{"200":{"description":"status"}}}},
"/v1/analyses/{id}/findings":{"get":{"responses":{"200":{"description":"findings"}}}},
"/v1/reports/{id}":{"get":{"responses":{"200":{"description":"report"}}}},
}}

def _validate_json_shape(value: object, depth: int=0) -> None:
    if depth>MAX_JSON_DEPTH: raise ValueError("JSON nesting exceeds limit")
    if isinstance(value,dict):
        if len(value)>MAX_JSON_ITEMS: raise ValueError("JSON object exceeds item limit")
        for key,item in value.items():
            if not isinstance(key,str) or len(key)>4096: raise ValueError("invalid JSON object key")
            _validate_json_shape(item,depth+1)
    elif isinstance(value,list):
        if len(value)>MAX_JSON_ITEMS: raise ValueError("JSON array exceeds item limit")
        for item in value: _validate_json_shape(item,depth+1)
    elif isinstance(value,str) and len(value)>MAX_BODY_BYTES: raise ValueError("JSON string exceeds limit")

class ApiServer:
    def __init__(self,service:ProductService): self.service=service
    def serve(self,host:str,port:int)->None:
        service=self.service
        if service.settings.auth_required and not service.settings.api_token:
            raise ValueError("FAS_AUTH_REQUIRED=true requires FAS_API_TOKEN")
        if host not in {"127.0.0.1","localhost","::1"} and not service.settings.auth_required:
            raise ValueError("refusing non-local API binding without FAS_AUTH_REQUIRED=true")
        class Handler(BaseHTTPRequestHandler):
            server_version="FAS/1"
            protocol_version="HTTP/1.1"
            def setup(self):
                super().setup()
                self.request.settimeout(15)
            def _send(self,status,payload):
                body=json.dumps(payload,sort_keys=True,separators=(",",":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.send_header("X-Request-ID",secrets.token_hex(12))
                self.end_headers()
                self.wfile.write(body)
            def _auth(self):
                if not service.settings.auth_required: return True
                auth_values=self.headers.get_all("Authorization") or []
                if len(auth_values) != 1: return False
                supplied=auth_values[0]
                expected=service.settings.api_token
                if not supplied or expected is None or len(supplied)>MAX_HEADER_BYTES: return False
                if any(len(str(k))+len(str(v)) > MAX_HEADER_BYTES for k,v in self.headers.items()): return False
                scheme,separator,token=supplied.partition(" ")
                if separator!=" " or scheme!="Bearer" or not token or token!=token.strip(): return False
                return secrets.compare_digest(token,expected)

            def _request_body(self):
                raw_length=self.headers.get("Content-Length")
                if raw_length is None: raise ValueError("Content-Length is required")
                try: length=int(raw_length)
                except ValueError as exc: raise ValueError("invalid Content-Length") from exc
                if length<0: raise ValueError("negative Content-Length")
                if length>MAX_BODY_BYTES: raise OverflowError("request body exceeds limit")
                raw=self.rfile.read(length)
                if len(raw)!=length: raise ValueError("incomplete request body")
                try: data=json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise ValueError("invalid UTF-8 JSON") from exc
                _validate_json_shape(data)
                return data
            def do_GET(self):
                if not self._auth(): return self._send(401,{"error":{"code":"UNAUTHORIZED","message":"authentication required"}})
                path=urlparse(self.path).path
                try:
                    if path=="/health/live": return self._send(200,{"status":"ok"})
                    if path=="/health/ready":
                        result=service.doctor(); return self._send(200 if result["ok"] else 503,result)
                    if path=="/openapi.json": return self._send(200,OPENAPI)
                    parts=path.strip("/").split("/")
                    if len(parts)==3 and parts[0]=="v1" and parts[1]=="projects":
                        return self._send(200,service.get_project(parts[2]).model_dump(mode="json"))
                    if parts[:2]==["v1","analyses"] and len(parts)>=3:
                        aid=parts[2]; analysis=service.get_analysis(aid)
                        if len(parts)==3: return self._send(200,analysis.model_dump(mode="json"))
                        if len(parts)==4 and parts[3]=="status": return self._send(200,{"analysis_id":aid,"status":analysis.status.value})
                        if len(parts)==4 and parts[3]=="findings": return self._send(200,{"items":service.findings(aid)})
                    if len(parts)==3 and parts[:2]==["v1","reports"]:
                        return self._send(200,service.store.get("reports",parts[2]))
                    return self._send(404,{"error":{"code":"NOT_FOUND","message":"resource not found"}})
                except KeyError: return self._send(404,{"error":{"code":"NOT_FOUND","message":"resource not found"}})
                except ValueError as exc: return self._send(400,{"error":{"code":"INVALID_REQUEST","message":str(exc)}})
                except (OSError,RuntimeError,TypeError,IndexError) as exc: return self._send(500,{"error":{"code":"INTERNAL_ERROR","message":type(exc).__name__}})
            def do_POST(self):
                if not self._auth(): return self._send(401,{"error":{"code":"UNAUTHORIZED","message":"authentication required"}})
                try:
                    data=self._request_body()
                    if not isinstance(data,dict): raise ValueError("request body must be a JSON object")
                    path=urlparse(self.path).path
                    if path=="/v1/projects":
                        if "name" not in data or "repository" not in data: raise ValueError("name and repository are required")
                        project=service.create_project(str(data["name"]),str(data["repository"]),str(data.get("owner","api")))
                        return self._send(201,project.model_dump(mode="json"))
                    if path=="/v1/analyses":
                        if "project_id" not in data or "source" not in data: raise ValueError("project_id and source are required")
                        analysis=service.create_analysis(str(data["project_id"]),str(data["source"]))
                        return self._send(201,analysis.model_dump(mode="json"))
                    return self._send(404,{"error":{"code":"NOT_FOUND","message":"resource not found"}})
                except OverflowError: return self._send(413,{"error":{"code":"PAYLOAD_TOO_LARGE","message":"request body exceeds limit"}})
                except (KeyError,TypeError,ValueError,UnicodeError): return self._send(400,{"error":{"code":"INVALID_REQUEST","message":"invalid request"}})
                except (OSError,RuntimeError) as exc: return self._send(500,{"error":{"code":"INTERNAL_ERROR","message":type(exc).__name__}})
            def log_message(self,fmt,*args): return
        server=ThreadingHTTPServer((host,port),Handler)
        server.daemon_threads=True
        server.serve_forever()
