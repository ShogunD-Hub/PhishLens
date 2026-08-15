from fastapi import FastAPI

app = FastAPI(
    title="PhishLens",
    description="Defensive phishing email analysis platform",
    version="0.1.0"
)


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
