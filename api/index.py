import sys
from pathlib import Path

# Add project root and src directory to Python path for Vercel Serverless Function
root_dir = Path(__file__).resolve().parent.parent
src_dir = root_dir / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from cloudsec_rag.api.server import app

# Vercel entrypoint
app = app
