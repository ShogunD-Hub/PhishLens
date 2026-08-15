from fastapi import APIRouter

router = APIRouter(
    prefix="/api",
    tags=["Analysis"]
)


@router.get("/analyze")
def analyze_email():
    return {
        "message": "PhishLens analysis endpoint"
    }
