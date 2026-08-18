RISK_LEVELS = {
    "LOW": (0, 24),
    "MEDIUM": (25, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}


def calculate_risk_score(scores: list[int]) -> int:
    """
    Combine scores from multiple security analysers.

    The final score is capped at 100.
    """

    total_score = sum(scores)

    return min(total_score, 100)


def get_risk_level(score: int) -> str:
    """
    Convert a numerical risk score into a risk level.
    """

    for level, (minimum, maximum) in RISK_LEVELS.items():
        if minimum <= score <= maximum:
            return level

    return "CRITICAL"


def generate_recommendation(risk_level: str) -> str:
    """
    Generate a recommended action based on the final risk level.
    """

    recommendations = {
        "LOW": "No significant phishing indicators detected. Continue to exercise caution.",
        
        "MEDIUM": "Potential phishing indicators detected. Verify the sender before taking action.",
        
        "HIGH": "Multiple phishing indicators detected. Do not click links or provide credentials.",
        
        "CRITICAL": "Strong indicators of phishing detected. Do not interact with this email and report it to your security team.",
    }

    return recommendations[risk_level]


def calculate_risk(scores: list[int]) -> dict:
    """
    Generate the final PhishLens risk assessment.
    """

    score = calculate_risk_score(scores)
    risk_level = get_risk_level(score)
    recommendation = generate_recommendation(risk_level)

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "recommendation": recommendation,
    }
