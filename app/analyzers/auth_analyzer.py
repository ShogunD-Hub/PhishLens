import re


AUTH_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE
)


SCORES = {
    "pass": 0,
    "none": 5,
    "neutral": 5,
    "softfail": 10,
    "temperror": 5,
    "permerror": 15,
    "fail": 15,
}


def analyze_authentication(
    authentication_results: str | None
) -> dict:
    """
    Analyse SPF, DKIM and DMARC results from
    an Authentication-Results header.
    """

    results = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
    }

    if not authentication_results:
        return {
            "score": 0,
            "available": False,
            "results": results,
            "indicators": [],
        }

    matches = AUTH_PATTERN.findall(
        authentication_results
    )

    for method, result in matches:

        method = method.lower()
        result = result.lower()

        if method in results:
            results[method] = result

    indicators = []
    score = 0

    for method, result in results.items():

        if result is None:
            continue

        penalty = SCORES.get(result, 0)

        if penalty > 0:

            indicators.append({
                "type": f"{method}_{result}",
                "severity": (
                    "high"
                    if result == "fail"
                    else "medium"
                ),
                "score": penalty,
                "description": (
                    f"{method.upper()} authentication "
                    f"result: {result}."
                ),
            })

            score += penalty

    return {
        "score": min(score, 100),
        "available": True,
        "results": results,
        "indicators": indicators,
    }
