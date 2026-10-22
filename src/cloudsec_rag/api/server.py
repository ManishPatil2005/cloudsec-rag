"""FastAPI Server Entrypoint for CloudSec-RAG."""

from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from .routes import router

app = FastAPI(
    title="CloudSec-RAG Enterprise API",
    description="Grounded Multi-Cloud LLM & RAG Security Platform with Anti-Hallucination Guardrails",
    version="1.0.0",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
