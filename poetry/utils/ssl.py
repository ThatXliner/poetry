import os


def https_context():
    """Use patched roots by default and retain explicit OpenSSL CA overrides."""
    import ssl

    import certifi

    if tuple(int(part) for part in certifi.__version__.split(".")) < (2026, 10, 19):
        raise RuntimeError("Install certifi>=2026.10.19 before using HTTPS")
    return ssl.create_default_context(
        cafile=os.environ.get("SSL_CERT_FILE") or certifi.where(),
        capath=os.environ.get("SSL_CERT_DIR"),
    )
