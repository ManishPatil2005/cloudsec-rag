#!/usr/bin/env python3
"""CloudSec-RAG: Main Entrypoint."""

import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from cloudsec_rag.cli import cli

if __name__ == "__main__":
    cli()
