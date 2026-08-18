from fastapi import APIRouter
from pydantic import BaseModel

from app.analyzers.content_analyzer import analyze_content
from app.analyzers.url_analyzer import analyze_urls
from app.scoring.risk_engine import calculate_risk


router = APIRouter(
    prefix="/api",
    tags=["Analysis"]
)


class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str


@router.post("/analyze")
def analyze_email(email: EmailRequest):

    # Combine subject and body for analysis
    email_content = f"{email.subject} {email.body}"

    # Content analysis
    content_result = analyze_content(email_content)

    # URL analysis
    url_result = analyze_urls(email_content)

    # Combine analyser scores
    risk_result = calculate_risk([
        content_result["score"],
        url_result["score"]
    ])

    return {
        "email": {
            "sender": email.sender,
            "subject": email.subject
        },

        "analysis": {
            "content": content_result,
            "urls": url_result
        },

        "risk_assessment": risk_result
    }
