from fastapi import APIRouter
from pydantic import BaseModel

from app.analyzers.content_analyzer import analyze_content
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

    # Analyse the email content
    content_result = analyze_content(
        f"{email.subject} {email.body}"
    )

    # Generate the final risk assessment
    risk_result = calculate_risk([
        content_result["score"]
    ])

    return {
        "email": {
            "sender": email.sender,
            "subject": email.subject
        },

        "analysis": {
            "content_score": content_result["score"],
            "indicators": content_result["indicators"]
        },

        "risk_assessment": risk_result
    }
