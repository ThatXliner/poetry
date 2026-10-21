"""Offline checks for the real installer and self-update TLS call sites."""
import importlib.util
import os
import ssl
import subprocess
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

import certifi

from poetry.console.commands.self.update import SelfUpdateCommand
from poetry.utils.ssl import https_context


ROOT = Path(__file__).resolve().parents[1]


def load_installer(name):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), ROOT / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_context(context):
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as bundle:
        for der in context.get_ca_certs(binary_form=True):
            bundle.write(ssl.DER_cert_to_PEM_cert(der))
        bundle.flush()
        for host in (
            "dv-g3b-emudhra.we-have-a-problem.com",
            "dv-g3b-aaa-emudhra.we-have-a-problem.com",
        ):
            chain = ROOT / "tests/chains" / (host + ".pem")
            result = subprocess.run(
                [
                    "openssl",
                    "verify",
                    "-no-CApath",
                    "-no-CAstore",
                    "-CAfile",
                    bundle.name,
                    "-untrusted",
                    str(chain),
                    "-verify_hostname",
                    host,
                    str(chain),
                ],
                capture_output=True,
                text=True,
            )
            assert result.returncode != 0, host + ": compromised chain accepted"
            assert (
                "unable to get local issuer certificate" in result.stderr
            ), result.stderr


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"PATH": os.environ["PATH"]}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_installer_downloads_use_patched_verified_context(self):
        for name in ("get-poetry", "install-poetry"):
            installer = load_installer(name)
            with patch.object(installer, "urlopen") as urlopen:
                urlopen.return_value.read.return_value = b"fixture"
                self.assertEqual(
                    installer.Installer._get(None, "https://example.com/"), b"fixture"
                )
                check_context(urlopen.call_args[1]["context"])

    def test_self_update_uses_patched_context_before_download(self):
        class StopDownload(Exception):
            pass

        command = SelfUpdateCommand()
        with patch.object(command, "_get_release_name", return_value="fixture"), patch(
            "poetry.console.commands.self.update.urlopen", side_effect=StopDownload
        ) as urlopen:
            with self.assertRaises(StopDownload):
                command._update("fixture")
            check_context(urlopen.call_args[1]["context"])

    def test_custom_ca_file_and_directory_are_preserved(self):
        for factory in (
            https_context,
            load_installer("get-poetry").https_context,
            load_installer("install-poetry").https_context,
        ):
            with tempfile.TemporaryDirectory() as directory, patch.dict(
                os.environ,
                {"SSL_CERT_FILE": certifi.where(), "SSL_CERT_DIR": directory},
            ), patch(
                "ssl.create_default_context", wraps=ssl.create_default_context
            ) as create:
                check_context(factory())
                self.assertEqual(
                    create.call_args[1],
                    {"cafile": certifi.where(), "capath": directory},
                )

    def test_standalone_bootstrap_rejects_old_certifi_and_preserves_pip_cert(self):
        installer = load_installer("install-poetry")
        with patch.object(certifi, "__version__", "2020.12.5"):
            with self.assertRaisesRegex(RuntimeError, "2026.10.19"):
                installer.pip_environment()
        self.assertEqual(installer.pip_environment()["PIP_CERT"], certifi.where())
        with patch.dict(os.environ, {"PIP_CERT": "/custom/roots.pem"}):
            self.assertEqual(
                installer.pip_environment()["PIP_CERT"], "/custom/roots.pem"
            )


if __name__ == "__main__":
    unittest.main()
