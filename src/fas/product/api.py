"""Minimal dependency-light HTTP API with stable /v1 contracts and OpenAPI metadata."""
from __future__ import annotations
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from .service import ProductService

OPENAPI={"openapi":"3.1.0","info":{"title":"FAS API","version":"v1"},"paths":{
"/health/live":{"get":{"responses":{"200":{"description":"live"}}}},
"/health/ready":{"get":{"responses":{"200":{"description":"ready"}}}},
"/v1/projects":{"post":{"responses":{"201":{"description":"created"}}}},
"/v1/projects/{id}":{"get":{"responses":{"200":{"description":"project"}}}},
"/v1/analyses":{"post":{"responses":{"201":{"description":"created"}}}},
"/v1/analyses/{id}":{"get":{"responses":{"200":{"description":"analysis"}}}},
"/v1/analyses/{id}/status":{"get":{"responses":{"200":{"description":"status"}}}},
"/v1/analyses/{id}/findings":{"get":{"responses":{"200":{"description":"findings"}}}},
"/v1/reports/{id}":{"get":{"responses":{"200":{"description":"report"}}}},
}}

class ApiServer:
    def __init__(self, service: ProductService):
        self.service=service
    def serve(self, host: str, port: int) -> None:
        if host not in {"127.0.0.1","localhost","::1"} and not self.service.settings.auth_required:
            raise ValueError("refusing non-local API binding without FAS_AUTH_REQUIRED=true")
        service=self.service
        class Handler(BaseHTTPRequestHandler):
            server_version="FAS/0.1"
            def _send(self,status,payload):
                body=json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
                self.send_response(status)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.send_header("X-Request-ID",secrets.token_hex(12))
                self.end_headers()
                self.wfile.write(body)
            def _auth(self):
                if service.settings.auth_required:
                    supplied=self.headers.get("Authorization","")
                    expected=service.settings.api_token or ""
                    if not supplied.startswith("Bearer ") or not secrets.compare_digest(supplied[7:],expected):
                        return False
                return True
            def do_GET(self):
                if not self._auth():
                    return self._send(401,{"error":{"code":"UNAUTHORIZED","message":"authentication required"}})
                p=urlparse(self.path).path
                try:
                    if p=="/health/live":
                        return self._send(200,{"status":"ok"})
                    if p=="/health/ready":
                        d=service.doctor()
                        return self._send(200 if d["ok"] else 503,d)
                    if p=="/openapi.json":
                        return self._send(200,OPENAPI)
                    if p.startswith("/v1/projects/"):
                        return self._send(200,service.get_project(p.split("/")[3]).model_dump(mode="json"))
                    if p.startswith("/v1/analyses/"):
                        parts=p.strip("/").split("/")
                        aid=parts[2]
                        a=service.get_analysis(aid)
                        if len(parts)==3:
                            return self._send(200,a.model_dump(mode="json"))
                        if parts[3]=="status":
                            return self._send(200,{"analysis_id":aid,"status":a.status.value})
                        if parts[3]=="findings":
                            return self._send(200,{"items":service.findings(aid)})
                    if p.startswith("/v1/reports/"):
                        rid=p.split("/")[3]
                        return self._send(200,service.store.get("reports",rid))
                    return self._send(404,{"error":{"code":"NOT_FOUND","message":"resource not found"}})
                except KeyError:
                    return self._send(404,{"error":{"code":"NOT_FOUND","message":"resource not found"}})
                except ValueError as exc:
                    return self._send(400,{"error":{"code":"INVALID_REQUEST","message":str(exc)}})
                except (OSError, RuntimeError, TypeError) as exc:
                    return self._send(500,{"error":{"code":"INTERNAL_ERROR","message":type(exc).__name__}})
            def do_POST(self):
                if not self._auth():
                    return self._send(401,{"error":{"code":"UNAUTHORIZED","message":"authentication required"}})
                try:
                    length=int(self.headers.get("Content-Length","0"))
                    if length>1_000_000:
                        return self._send(413,{"error":{"code":"PAYLOAD_TOO_LARGE","message":"request body exceeds limit"}})
                    raw=self.rfile.read(length)
                    data=json.loads(raw or b"{}")
                    p=urlparse(self.path).path
                    if p=="/v1/projects":
                        project=service.create_project(str(data["name"]),str(data["repository"]),str(data.get("owner","api")))
                        return self._send(201,project.model_dump(mode="json"))
                    if p=="/v1/analyses":
                        analysis=service.create_analysis(str(data["project_id"]),str(data["source"]))
                        return self._send(201,analysis.model_dump(mode="json"))
                    return self._send(404,{"error":{"code":"NOT_FOUND","message":"resource not found"}})
                except (KeyError,TypeError,ValueError):
                    return self._send(400,{"error":{"code":"INVALID_REQUEST","message":"invalid request"}})
                except (OSError, RuntimeError, ValueError) as exc:
                    return self._send(500,{"error":{"code":"INTERNAL_ERROR","message":type(exc).__name__}})
            def log_message(self,fmt,*args): return
        ThreadingHTTPServer((host,port),Handler).serve_forever()
