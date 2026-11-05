"""Central config. Everything comes from env or scope.yaml — no hardcoded targets."""
import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCOPE_FILE = Path(os.environ.get("PENTEST_SCOPE_FILE", ROOT / "scope.yaml"))
EVIDENCE_DIR = Path(os.environ.get("PENTEST_EVIDENCE_DIR", ROOT / "evidence"))

# Transport is stdio only (the driver spawns the server over docker exec / ssh).
# No network listener, so no bind host / port / bearer token here.
HTTP_TIMEOUT = int(os.environ.get("PENTEST_HTTP_TIMEOUT", "20"))


def load_scope() -> dict:
    """Read scope.yaml fresh on each call so edits (and env overrides) take effect live."""
    path = Path(os.environ.get("PENTEST_SCOPE_FILE", ROOT / "scope.yaml"))
    if not path.exists():
        return {"targets": [], "notes": "scope.yaml missing — all targets refused"}
    with open(path) as f:
        return yaml.safe_load(f) or {"targets": []}


EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
