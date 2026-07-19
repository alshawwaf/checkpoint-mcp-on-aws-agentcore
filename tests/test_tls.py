"""The stdlib TLS context must ALWAYS verify: CERT_REQUIRED, hostname checks
on, and an actual CA store loaded (falling back to certifi/botocore bundles
when the interpreter's default store is empty -- never to no-verify)."""

import ssl

from chkpmcpaws.awsutil import tls_context


def test_context_always_verifies():
    ctx = tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_context_has_ca_certificates_loaded():
    # In any environment where boto3 is installed (a hard dependency),
    # botocore's bundled cacert.pem guarantees a non-empty fallback store.
    ctx = tls_context()
    assert ctx.cert_store_stats().get("x509_ca", 0) > 0
