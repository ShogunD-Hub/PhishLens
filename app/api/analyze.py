from fastapi import APIRouter
from pydantic import BaseModel


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
    return {
        "sender": email.sender,
        "subject": email.subject,
        "message": "Email received successfully",
        "status": "ready_for_analysis"
    }
