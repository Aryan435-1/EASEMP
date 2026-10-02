"""Main FastAPI entrypoint for the EEIP platform backend.

This module initializes the FastAPI application, configures CORS middleware for frontend clients,
and registers API routes.
"""

from typing import Dict
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router

app = FastAPI(
    title="EEIP Platform API",
    description="Main FastAPI backend service for the EEIP platform.",
    version="1.0.0",
)

# Configure CORS middleware
origins = [
    "http://localhost:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes router (routes already include /api prefix)
app.include_router(router)


@app.get("/")
def root() -> Dict[str, str]:
    """Root status endpoint.

    Returns:
        Dict[str, str]: Service status dictionary.
    """
    return {"status": "EEIP backend running"}
