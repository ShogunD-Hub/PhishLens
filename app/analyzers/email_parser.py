from email import policy
from email.parser import BytesParser


def parse_eml(file_content: bytes) -> dict:
    """
    Parse an .eml file and extract useful email information.
    """

    message = BytesParser(
        policy=policy.default
    ).parsebytes(file_content)

    sender = message.get("From", "")
    reply_to = message.get("Reply-To")
    subject = message.get("Subject", "")
    return_path = message.get("Return-Path")
    message_id = message.get("Message-ID")

    body = extract_body(message)

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "return_path": return_path,
        "message_id": message_id,
        "body": body,
    }


def extract_body(message) -> str:
    """
    Extract readable text from an email message.
    """

    if message.is_multipart():

        plain_text = []

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":

                try:
                    content = part.get_content()

                    if content:
                        plain_text.append(content)

                except (LookupError, UnicodeDecodeError):
                    continue

        return "\n".join(plain_text)

    try:
        return message.get_content()
    except (LookupError, UnicodeDecodeError):
        return ""
