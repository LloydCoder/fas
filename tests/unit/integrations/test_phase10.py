import hmac
from hashlib import sha256
from fas.integrations.events import EventNormalizer, IdempotencyLedger
from fas.integrations.http import SecureHttpClient
from fas.integrations.webhook import verify_github_signature, normalize_github_webhook

def test_event_fingerprint_is_idempotent_per_tenant():
    normalizer=EventNormalizer("tenant-a")
    event=normalizer.normalize("github","push","1",{"ref":"main"})
    ledger=IdempotencyLedger()
    assert ledger.accept(event)
    assert not ledger.accept(event)

def test_github_signature_verification():
    body=b'{"ok":true}'
    secret=b"secret"
    signature="sha256="+hmac.new(secret,body,sha256).hexdigest()
    assert verify_github_signature(body,signature,secret)
    assert not verify_github_signature(body,signature,b"wrong")

def test_webhook_normalization_requires_identity_headers():
    normalizer=EventNormalizer("tenant-a")
    event=normalize_github_webhook({"X-GitHub-Event":"push","X-GitHub-Delivery":"abc"},b'{"ref":"main"}',normalizer)
    assert event.provider=="github" and event.event_id=="abc"

def test_connector_host_allowlist_rejects_untrusted_hosts():
    client=SecureHttpClient(frozenset({"api.github.com"}))
    try:
        client.request("https://example.invalid/")
    except PermissionError:
        pass
    else:
        raise AssertionError("connector accepted an untrusted host")
