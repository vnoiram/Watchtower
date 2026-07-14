import hashlib
import hmac

from api.app.services.github import verify_webhook_signature


def test_verify_webhook_signature() -> None:
    body = b'{"zen":"ok"}'
    secret = "secret"
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(secret, body, signature)
    assert not verify_webhook_signature(secret, body, "sha256=bad")

