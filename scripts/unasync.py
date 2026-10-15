"""Generate the synchronous client from the asynchronous one.

python scripts/unasync.py          # rewrite src/eyalsec/_client.py
python scripts/unasync.py --check  # exit 1 if it is out of date (CI)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "eyalsec" / "_async_client.py"
DST = ROOT / "src" / "eyalsec" / "_client.py"

HEADER = '''"""The synchronous client, :class:`EyalSec`.

GENERATED from ``_async_client.py`` by ``scripts/unasync.py``. Do not edit
this file by hand: edit ``_async_client.py`` and run the script again.
"""
'''

# Order matters: longer, more specific patterns first.
SUBS = [
    (r"\bAsyncIterator\b", "Iterator"),
    (r"\bAsyncEyalSec\b", "EyalSec"),
    (r"\bhttpx\.AsyncClient\b", "httpx.Client"),
    (r"\bhttpx\.AsyncBaseTransport\b", "httpx.BaseTransport"),
    (r"\basync def\b", "def"),
    (r"\basync for\b", "for"),
    (r"\basync with\b", "with"),
    (r"\bawait ", ""),
    (r"\b__aenter__\b", "__enter__"),
    (r"\b__aexit__\b", "__exit__"),
    (r"\baclose\b", "close"),
    (r"\basyncio\.sleep\b", "time.sleep"),
    (r"^import asyncio$", "import time"),
    (r"Asynchronous client", "Client"),
]


def generate() -> str:
    text = SRC.read_text(encoding="utf-8")
    # Drop the async module docstring; the generated file gets its own.
    if text.startswith('"""'):
        end = text.index('"""', 3) + 3
        text = text[end:].lstrip("\n")
    for pattern, repl in SUBS:
        text = re.sub(pattern, repl, text, flags=re.MULTILINE)
    return HEADER + "\n" + text


def main() -> int:
    out = generate()
    if "--check" in sys.argv[1:]:
        current = DST.read_text(encoding="utf-8") if DST.exists() else ""
        if current != out:
            print(f"{DST.relative_to(ROOT)} is out of date: run python scripts/unasync.py", file=sys.stderr)
            return 1
        return 0
    DST.write_text(out, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
