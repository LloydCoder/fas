"""Bounded dependency-light HTTP API with explicit contracts and abuse controls."""
from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .service import ProductService

MAX_BODY_BYTES = 1_000_000
MAX_HEADER_BYTES = 16_384
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 10_000
RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_REQUESTS = 120
RATE_LIMIT_ANALYSIS_SUBMISSIONS = 10


OPENAPI = {
    "openapi": "3.1.0",
    "info": {"title": "FAS API", "version": "v1"},
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        },
        "schemas": {
            "Page": {
                "type": "object",
                "required": ["items", "limit", "offset", "count", "has_more"],
                "properties": {
                    "items": {"type": "array", "items": {}},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "offset": {"type": "integer", "minimum": 0},
                    "count": {"type": "integer", "minimum": 0},
                    "has_more": {"type": "boolean"},
                },
            },
            "Error": {
                "type": "object",
                "required": ["error"],
                "properties": {
                    "error": {
                        "type": "object",
                        "required": ["code", "message"],
                        "properties": {
                            "code": {"type": "string"},
                            "message": {"type": "string"},
                        },
                    }
                },
            },
        },
    },
    "paths": {
        "/health/live": {"get": {"responses": {"200": {"description": "live"}}}},
        "/health/ready": {"get": {"responses": {"200": {"description": "ready"}}}},
        "/openapi.json": {"get": {"responses": {"200": {"description": "OpenAPI document"}}}},
        "/v1/projects": {
            "post": {
                "security": [{"bearerAuth": []}],
                "requestBody": {"required": True},
                "responses": {"201": {"description": "created"}, "400": {"description": "invalid request"}},
            }
        },
        "/v1/projects/{id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "project"}, "404": {"description": "not found"}},
            }
        },
        "/v1/analyses": {
            "post": {
                "security": [{"bearerAuth": []}],
                "requestBody": {"required": True},
                "responses": {"201": {"description": "created"}, "400": {"description": "invalid request"}, "429": {"description": "rate limited"}},
            }
        },
        "/v1/analyses/{id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "analysis"}, "404": {"description": "not found"}},
            }
        },
        "/v1/analyses/{id}/status": {"get": {"security": [{"bearerAuth": []}], "responses": {"200": {"description": "status"}}}},
        "/v1/analyses/{id}/findings": {
            "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer", "minimum": 0}},
                ],
                "responses": {"200": {"description": "paginated findings"}},
            }
        },
        "/v1/reports/{id}": {"get": {"security": [{"bearerAuth": []}], "responses": {"200": {"description": "report"}}}},
    },
}


def _validate_json_shape(value: object, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting exceeds limit")
    if isinstance(value, dict):
        if len(value) > MAX_JSON_ITEMS:
            raise ValueError("JSON object exceeds item limit")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 4096:
                raise ValueError("invalid JSON object key")
            _validate_json_shape(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_JSON_ITEMS:
            raise ValueError("JSON array exceeds item limit")
        for item in value:
            _validate_json_shape(item, depth + 1)
    elif isinstance(value, str) and len(value) > MAX_BODY_BYTES:
        raise ValueError("JSON string exceeds limit")


class _RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[str, list[float]] = {}
        self._submissions: dict[str, list[float]] = {}

    def allow(self, key: str, *, analysis_submission: bool = False) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._submissions if analysis_submission else self._requests
            limit = RATE_LIMIT_ANALYSIS_SUBMISSIONS if analysis_submission else RATE_LIMIT_REQUESTS
            values = [stamp for stamp in bucket.get(key, []) if now - stamp < RATE_LIMIT_WINDOW_SECONDS]
            if len(values) >= limit:
                bucket[key] = values
                return False
            values.append(now)
            bucket[key] = values
            if len(self._requests) > 10_000:
                self._requests = {
                    item: stamps
                    for item, stamps in self._requests.items()
                    if stamps and now - stamps[-1] < RATE_LIMIT_WINDOW_SECONDS
                }
            return True


class ApiServer:
    def __init__(self, service: ProductService):
        self.service = service
        self._rate_limiter = _RateLimiter()

    def serve(self, host: str, port: int) -> None:
        service = self.service
        limiter = self._rate_limiter
        if service.settings.auth_required and not service.settings.api_token:
            raise ValueError("FAS_AUTH_REQUIRED=true requires FAS_API_TOKEN")
        if host not in {"127.0.0.1", "localhost", "::1"} and not service.settings.auth_required:
            raise ValueError("refusing non-local API binding without FAS_AUTH_REQUIRED=true")

        class Handler(BaseHTTPRequestHandler):
            server_version = "FAS/0.6.0"
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                self.request.settimeout(15)

            def _send(self, status, payload):
                body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Request-ID", secrets.token_hex(12))
                self.end_headers()
                self.wfile.write(body)

            def _auth(self):
                if not service.settings.auth_required:
                    return True
                auth_values = self.headers.get_all("Authorization") or []
                if len(auth_values) != 1:
                    return False
                supplied = auth_values[0]
                expected = service.settings.api_token
                if not supplied or expected is None or len(supplied) > MAX_HEADER_BYTES:
                    return False
                if any(len(str(k)) + len(str(v)) > MAX_HEADER_BYTES for k, v in self.headers.items()):
                    return False
                scheme, separator, token = supplied.partition(" ")
                if separator != " " or scheme != "Bearer" or not token or token != token.strip():
                    return False
                return secrets.compare_digest(token, expected)

            def _rate_key(self) -> str:
                auth = self.headers.get("Authorization")
                return f"token:{auth}" if auth else f"peer:{self.client_address[0]}"

            def _request_body(self):
                raw_length = self.headers.get("Content-Length")
                if raw_length is None:
                    raise ValueError("Content-Length is required")
                try:
                    length = int(raw_length)
                except ValueError as exc:
                    raise ValueError("invalid Content-Length") from exc
                if length < 0:
                    raise ValueError("negative Content-Length")
                if length > MAX_BODY_BYTES:
                    raise OverflowError("request body exceeds limit")
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("incomplete request body")
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError("invalid UTF-8 JSON") from exc
                _validate_json_shape(data)
                return data

            def _page(self):
                query = parse_qs(urlparse(self.path).query, keep_blank_values=False)
                try:
                    limit = int(query.get("limit", ["100"])[0])
                    offset = int(query.get("offset", ["0"])[0])
                except ValueError as exc:
                    raise ValueError("limit and offset must be integers") from exc
                if not 1 <= limit <= 100 or offset < 0:
                    raise ValueError("limit must be 1..100 and offset must be non-negative")
                return limit, offset

            def do_GET(self):
                if not limiter.allow(self._rate_key()):
                    return self._send(429, {"error": {"code": "RATE_LIMITED", "message": "request rate limit exceeded"}})
                if not self._auth():
                    return self._send(401, {"error": {"code": "UNAUTHORIZED", "message": "authentication required"}})
                path = urlparse(self.path).path
                try:
                    if path == "/health/live":
                        return self._send(200, {"status": "ok"})
                    if path == "/health/ready":
                        result = service.doctor()
                        return self._send(200 if result["ok"] else 503, result)
                    if path == "/openapi.json":
                        return self._send(200, OPENAPI)
                    parts = path.strip("/").split("/")
                    if len(parts) == 3 and parts[0] == "v1" and parts[1] == "projects":
                        return self._send(200, service.get_project(parts[2]).model_dump(mode="json"))
                    if parts[:2] == ["v1", "analyses"] and len(parts) >= 3:
                        aid = parts[2]
                        analysis = service.get_analysis(aid)
                        if len(parts) == 3:
                            return self._send(200, analysis.model_dump(mode="json"))
                        if len(parts) == 4 and parts[3] == "status":
                            return self._send(200, {"analysis_id": aid, "status": analysis.status.value})
                        if len(parts) == 4 and parts[3] == "findings":
                            limit, offset = self._page()
                            items = service.findings(aid, limit=limit, offset=offset)
                            return self._send(
                                200,
                                {"items": items, "limit": limit, "offset": offset, "count": len(items), "has_more": len(items) == limit},
                            )
                    if len(parts) == 3 and parts[:2] == ["v1", "reports"]:
                        return self._send(200, service.store.get("reports", parts[2]))
                    return self._send(404, {"error": {"code": "NOT_FOUND", "message": "resource not found"}})
                except KeyError:
                    return self._send(404, {"error": {"code": "NOT_FOUND", "message": "resource not found"}})
                except ValueError as exc:
                    return self._send(400, {"error": {"code": "INVALID_REQUEST", "message": str(exc)}})
                except (OSError, RuntimeError, TypeError, IndexError) as exc:
                    return self._send(500, {"error": {"code": "INTERNAL_ERROR", "message": type(exc).__name__}})

            def do_POST(self):
                key = self._rate_key()
                if not limiter.allow(key, analysis_submission=urlparse(self.path).path == "/v1/analyses"):
                    return self._send(429, {"error": {"code": "RATE_LIMITED", "message": "request rate limit exceeded"}})
                if not self._auth():
                    return self._send(401, {"error": {"code": "UNAUTHORIZED", "message": "authentication required"}})
                try:
                    data = self._request_body()
                    if not isinstance(data, dict):
                        raise TypeError("request body must be a JSON object")
                    path = urlparse(self.path).path
                    if path == "/v1/projects":
                        if "name" not in data or "repository" not in data:
                            raise ValueError("name and repository are required")
                        project = service.create_project(
                            str(data["name"]), str(data["repository"]), str(data.get("owner", "api"))
                        )
                        return self._send(201, project.model_dump(mode="json"))
                    if path == "/v1/analyses":
                        if "project_id" not in data or "source" not in data:
                            raise ValueError("project_id and source are required")
                        analysis = service.create_analysis(str(data["project_id"]), str(data["source"]))
                        return self._send(201, analysis.model_dump(mode="json"))
                    return self._send(404, {"error": {"code": "NOT_FOUND", "message": "resource not found"}})
                except OverflowError:
                    return self._send(413, {"error": {"code": "PAYLOAD_TOO_LARGE", "message": "request body exceeds limit"}})
                except (KeyError, TypeError, ValueError, UnicodeError):
                    return self._send(400, {"error": {"code": "INVALID_REQUEST", "message": "invalid request"}})
                except (OSError, RuntimeError) as exc:
                    return self._send(500, {"error": {"code": "INTERNAL_ERROR", "message": type(exc).__name__}})

            def log_message(self, fmt, *args):
                return

        server = ThreadingHTTPServer((host, port), Handler)
        server.daemon_threads = True
        server.serve_forever()
