"""FastAPI Server Entrypoint for CloudSec-RAG."""

import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .routes import router

app = FastAPI(
    title="CloudSec-RAG Enterprise API",
    description="Grounded Multi-Cloud LLM & RAG Security Platform with Anti-Hallucination Guardrails",
    version="2.0.0",
)

# Enterprise CORS Configuration
# W3C / RFC 6454: wildcard origin '*' CANNOT be used with allow_credentials=True
cors_env = os.getenv("CORS_ORIGINS", "").strip()
if cors_env:
    allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
    allow_creds = True
else:
    # Safe default: allow local dev and Vercel domains with credentials, or wildcard without credentials
    allowed_origins = [
        "http://localhost:8088",
        "http://127.0.0.1:8088",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://cloudsec-rag.vercel.app",
    ]
    allow_creds = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_creds,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

# Include API Router
app.include_router(router)


@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    """Serve the Cyber SOC Analyst Web Console."""
    candidates = [
        Path(__file__).resolve().parent.parent / "ui" / "templates" / "index.html",
        Path("src/cloudsec_rag/ui/templates/index.html"),
        Path("/var/task/src/cloudsec_rag/ui/templates/index.html"),
    ]
    for p in candidates:
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return f.read()
    return "<h1>CloudSec-RAG Server Running</h1><p><a href='/docs'>Swagger API Documentation</a></p>"
