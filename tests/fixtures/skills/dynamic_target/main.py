"""Behavioral fixture for the sandbox integration test.

Writes a file to /tmp (allowed) and to $HOME/marker.txt (outside expected
scope — should surface as a filesystem finding). Also spawns ``/bin/sh``
via subprocess so the process-abuse detector fires.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def main() -> None:
    Path("/tmp/clean-skill-allowed.txt").write_text("allowed\n")
    home_marker = Path(os.path.expanduser("~")) / "clean-skill-marker.txt"
    try:
        home_marker.write_text("escaped\n")
    except OSError:
        pass
    subprocess.run(["/bin/sh", "-c", "echo hello"], check=False)


if __name__ == "__main__":
    main()
