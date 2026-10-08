"""API entrypoint compatibility module."""
import sys
from pathlib import Path

# Ensure src is on sys.path
src_dir = Path(__file__).resolve().parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from cloudsec_rag.api.server import app

__all__ = ["app"]
