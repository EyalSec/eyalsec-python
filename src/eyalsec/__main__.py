"""``python -m eyalsec``: print what this package is, or check a key.

python -m eyalsec            # what this package is, with links
python -m eyalsec --version
python -m eyalsec --check    # call the API once with EYALSEC_API_KEY
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import EyalSec, EyalSecError, __version__, about


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m eyalsec", description="The Python client for the EyalSec API.")
    parser.add_argument("--version", action="version", version=f"eyalsec {__version__}")
    parser.add_argument(
        "--check",
        action="store_true",
        help="call the API once with EYALSEC_API_KEY (and EYALSEC_URL) and print what it reached",
    )
    args = parser.parse_args(argv)
    if not args.check:
        print(about())
        return 0
    try:
        with EyalSec() as client:
            account = client.get_account()
            key = client.get_api_key_info()
            machines = client.list_machines()
    except EyalSecError as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    scope = key.scope or "unknown"
    expiry = f", expires {key.expires_at:%Y-%m-%d}" if key.expires_at else ""
    print(f"reached {client.base_url} as {account.username}")
    print(f"key scope: {scope}{expiry}")
    print(f"machines: {len(machines)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
