"""Bounded webhook authentication and normalization."""
from __future__ import annotations
import hmac, json
from hashlib import sha256
from typing import Mapping
from .events import EventNormalizer, IntegrationEvent

MAX_WEBHOOK_BYTES=2*1024*1024

def verify_github_signature(body:bytes,signature:str,secret:bytes)->bool:
    if len(body)>MAX_WEBHOOK_BYTES or not secret or not signature.startswith("sha256="): return False
    expected="sha256="+hmac.new(secret,body,sha256).hexdigest()
    return hmac.compare_digest(expected,signature)

def normalize_github_webhook(headers:Mapping[str,str],body:bytes,normalizer:EventNormalizer)->IntegrationEvent:
    if len(body)>MAX_WEBHOOK_BYTES: raise ValueError("webhook payload exceeds limit")
    event=headers.get("X-GitHub-Event") or headers.get("x-github-event")
    delivery=headers.get("X-GitHub-Delivery") or headers.get("x-github-delivery")
    if not event or not delivery: raise ValueError("GitHub event headers are required")
    payload=json.loads(body)
    if not isinstance(payload,dict): raise ValueError("webhook payload must be an object")
    return normalizer.normalize("github",event,delivery,payload,delivery_id=delivery)
