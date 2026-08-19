from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from app.analyzers.content_analyzer import analyze_content
from app.analyzers.url_analyzer import analyze_urls
from app.analyzers.sender_analyzer import analyse_sender
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.email_parser import parse_eml
from app.scoring.risk_engine import calculate_risk


router = APIRouter(
    prefix="/api",
    tags=["Analysis"]
)


class EmailRequest(BaseModel):
    sender: str
    reply_to: str | None = None
    subject: str
    body: str


@router.post("/analyze")
def analyze_email(email: EmailRequest):

    # Combine subject and body for content analysis
    email_content = f"{email.subject} {email.body}"

    # Run individual security analysers
    content_result = analyze_content(email_content)

    url_result = analyze_urls(email_content)

    sender_result = analyse_sender(
        email.sender,
        email.reply_to
    )

    header_result = analyze_headers({
        "sender": email.sender,
        "reply_to": email.reply_to or "",
    })

    # Combine analyser scores
    risk_result = calculate_risk([
        content_result["score"],
        url_result["score"],
        sender_result["score"],
        header_result["risk_score"]
    ])

    return {
        "email": {
            "sender": email.sender,
            "reply_to": email.reply_to,
            "subject": email.subject
        },

        "analysis": {
            "content": content_result,
            "urls": url_result,
            "sender": sender_result,
            "header": header_result
        },

        "risk_assessment": risk_result

        @router.post("/analyze-eml")
async def analyze_eml(file: UploadFile = File(...)):

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    email_content = await file.read()

    try:
        parsed_email = parse_eml(email_content)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to parse email: {exc}"
        )

    sender = parsed_email.get("sender", "")
    reply_to = parsed_email.get("reply_to", "")
    subject = parsed_email.get("subject", "")
    body = parsed_email.get("body", "")

    combined_content = f"{subject} {body}"

    content_result = analyze_content(combined_content)

    url_result = analyze_urls(combined_content)

    sender_result = analyse_sender(
        sender,
        reply_to
    )

    header_result = analyze_headers(parsed_email)

    risk_result = calculate_risk([
        content_result["score"],
        url_result["score"],
        sender_result["score"],
        header_result["risk_score"]
    ])

    return {
        "email": {
            "sender": sender,
            "reply_to": reply_to,
            "subject": subject,
            "return_path": parsed_email.get("return_path", ""),
            "message_id": parsed_email.get("message_id", "")
        },

        "analysis": {
            "content": content_result,
            "urls": url_result,
            "sender": sender_result,
            "header": header_result
        },

        "risk_assessment": risk_result
    }
    }
