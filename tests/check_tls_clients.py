"""Probe the real HTTP paths with no app credentials and a fixed host allowlist.

Only the official incident test hosts and example.com are contacted. A timeout
or DNS error is inconclusive. Run manually; this does not run an installer,
update an installation, publish a package, or use repository credentials.
"""
import json
import ssl
import sys

from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import HTTPSHandler
from urllib.request import ProxyHandler
from urllib.request import build_opener

import requests

from check_tls_contexts import load_installer
from poetry.config.config import Config
from poetry.console.commands.self.update import SelfUpdateCommand
from poetry.core.packages.package import Package
from poetry.installation.authenticator import Authenticator
from poetry.publishing.uploader import Uploader
from poetry.repositories.pypi_repository import PyPiRepository


HOSTS = (
    "dv-g3b-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-emudhra.we-have-a-problem.com",
    "example.com",
)


class HTTPSReached(Exception):
    pass


def probe(kind, host):
    url = "https://" + host + "/"
    try:
        if kind in ("get-poetry", "install-poetry", "self-update"):

            def open_probe(request, *, context):
                target = getattr(request, "full_url", request)
                assert urlparse(target).hostname in HOSTS
                opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
                # Stop as soon as verified HTTPS succeeds, before installer/update work.
                try:
                    with opener.open(request, timeout=8) as response:
                        response.read(1)
                except HTTPError as response:
                    # An HTTP error also proves that the TLS handshake succeeded.
                    response.close()
                raise HTTPSReached()

            if kind == "self-update":
                command = SelfUpdateCommand()
                command.BASE_URL = url.rstrip("/")
                with patch.object(
                    command, "_get_release_name", return_value="probe"
                ), patch(
                    "poetry.console.commands.self.update.urlopen",
                    side_effect=open_probe,
                ):
                    command._update("probe")
            else:
                module = load_installer(kind)
                with patch.object(module, "urlopen", side_effect=open_probe):
                    module.Installer._get(None, url)
        else:
            if kind == "authenticator":
                auth = Authenticator(Config())
                session = auth.session
                session.trust_env = False
                session.auth = None
                response = auth.request("GET", url, timeout=8)
            elif kind == "pypi-repository":
                session = PyPiRepository(disable_cache=True).session
                session.trust_env = False
                session.auth = None
                response = session.get(url, timeout=8)
            else:
                session = Uploader(
                    SimpleNamespace(package=Package("probe", "0.0.0")), None
                ).make_session()
                session.trust_env = False
                session.auth = None
                # Avoid the uploader's long retry loop; preserve its TLS adapter.
                session.adapters[
                    "https://"
                ].max_retries = requests.packages.urllib3.util.Retry(total=0)
                response = session.get(url, timeout=8)
            try:
                response.raise_for_status()
            finally:
                session.close()
            raise HTTPSReached()
    except HTTPSReached:
        verdict = "https_success" if host == "example.com" else "FAIL_accepted"
    except requests.exceptions.SSLError as error:
        verdict = (
            "certificate_rejected"
            if "CERTIFICATE_VERIFY_FAILED" in str(error)
            else "inconclusive_tls_error"
        )
    except URLError as error:
        verdict = (
            "certificate_rejected"
            if isinstance(error.reason, ssl.SSLCertVerificationError)
            else "inconclusive_" + type(error.reason).__name__
        )
    except ssl.SSLCertVerificationError:
        verdict = "certificate_rejected"
    except (requests.exceptions.RequestException, OSError) as error:
        verdict = "inconclusive_" + type(error).__name__
    return dict(client=kind, host=host, result=verdict)


if __name__ == "__main__":
    results = [
        probe(kind, host)
        for kind in (
            "get-poetry",
            "install-poetry",
            "self-update",
            "authenticator",
            "pypi-repository",
            "uploader",
        )
        for host in HOSTS
    ]
    print(json.dumps(results, indent=2))
    sys.exit(
        0
        if all(
            r["result"]
            == (
                "https_success"
                if r["host"] == "example.com"
                else "certificate_rejected"
            )
            for r in results
        )
        else 1
    )
