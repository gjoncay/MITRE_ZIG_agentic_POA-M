"""Extracts every embedded file from PORTABLE_RECONSTRUCTION_BUNDLE.md.

Usage:  python3 extract_bundle.py [bundle.md]

Looks for blocks of the form:
    ## FILE: `relative/path` (sha256=<64 hex chars>)
    ````lang
    ...content...
    ````
Writes each file to its relative path and verifies its SHA-256 checksum.
Exits non-zero if any checksum fails. Pure stdlib; needs only Python 3.
"""
import sys
import os
import re
import hashlib

HEADER = re.compile(r"^## FILE: `([^`]+)` \(sha256=([0-9a-f]{64})\)\s*$")
FENCE = re.compile(r"^(`{4,})")

def main(bundle_path):
    pending = None   # (path, sha) seen, waiting for its opening fence
    fence = None     # exact backtick run that will close the current block
    path = sha = None
    buf = []
    written = failed = 0

    with open(bundle_path, encoding="utf-8") as f:
        for line in f:
            if fence is None:
                m = HEADER.match(line)
                if m:
                    pending = (m.group(1), m.group(2))
                    continue
                fm = FENCE.match(line)
                if pending and fm:
                    fence = fm.group(1)
                    path, sha = pending
                    pending = None
                    buf = []
            else:
                if line.rstrip("\n") == fence:
                    content = "".join(buf)
                    actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
                    if os.path.dirname(path):
                        os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8", newline="") as out:
                        out.write(content)
                    ok = actual == sha
                    print(("OK   " if ok else "FAIL ") + path)
                    written += 1
                    failed += (not ok)
                    fence = None
                else:
                    buf.append(line)

    print(f"\n{written} files written, {failed} checksum failures")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "PORTABLE_RECONSTRUCTION_BUNDLE.md")
