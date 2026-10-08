"""CLI entrypoint compatibility module."""
import sys
from pathlib import Path

# Ensure src is on sys.path
src_dir = Path(__file__).resolve().parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from cloudsec_rag.cli import cli

if __name__ == "__main__":
    cli()
