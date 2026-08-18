from fastapi import FastAPI
from app.api import analyze


app = FastAPI(
    title="PhishLens",
    description="Defensive phishing email analysis platform",
    version="0.1.0"
)


app.include_router(analyze.router)


@app.get("/")
def root():
    return {
        "application": "PhishLens",
        "status": "online",
        "version": "0.1.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }
