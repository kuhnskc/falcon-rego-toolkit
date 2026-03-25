import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.auth.router import router as auth_router
from backend.cspm.router import router as cspm_router
from backend.kac.router import router as kac_router

app = FastAPI(
    title="Falcon Rego Toolkit API",
    version="2.0.0",
    description="CrowdStrike Cloud Security Rego policy management — CSPM IOM and Kubernetes Admission Controller",
)

# CORS — configurable via env var, defaults to Vite dev server
cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers (registered BEFORE static files so /api/* always wins)
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(cspm_router, prefix="/api/cspm", tags=["CSPM IOM"])
app.include_router(kac_router, prefix="/api/kac", tags=["KAC"])


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "falcon-rego-toolkit"}


# Static file serving for production (container mode)
# In dev, Vite handles this; in production, FastAPI serves the built React app.
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if FRONTEND_DIR.is_dir():
    # Serve static assets (JS, CSS, images, etc.)
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="static-assets")

    # Catch-all: serve index.html for any non-API route (React Router client-side routing)
    @app.get("/{full_path:path}")
    async def serve_spa(request: Request, full_path: str):
        # If the exact file exists in dist/, serve it (e.g. favicon.ico, manifest.json)
        file_path = FRONTEND_DIR / full_path
        if full_path and file_path.is_file():
            return FileResponse(file_path)
        # Otherwise serve index.html for React Router
        return FileResponse(FRONTEND_DIR / "index.html")
