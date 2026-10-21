"""Reject the incident's archived test chains using certifi and OpenSSL 3+.

Run with ``python tests/check_ca_bundle.py``. This check is offline. Supply a
bundle path to demonstrate failure with a pre-update bundle.
"""

from pathlib import Path
import subprocess
import sys

import certifi


def main():
    bundle = sys.argv[1] if len(sys.argv) > 1 else certifi.where()
    for host in (
        "dv-g3b-emudhra.we-have-a-problem.com",
        "dv-g3b-aaa-emudhra.we-have-a-problem.com",
    ):
        chain = Path(__file__).parent / "chains" / (host + ".pem")
        result = subprocess.run(
            [
                "openssl", "verify", "-no-CApath", "-no-CAstore",
                "-CAfile", bundle, "-untrusted", str(chain),
                "-verify_hostname", host, str(chain),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            raise AssertionError(host + ": compromised chain accepted")
        if "unable to get local issuer certificate" not in result.stderr:
            raise RuntimeError(result.stderr)
        print(host + ": certificate rejected")


if __name__ == "__main__":
    main()
