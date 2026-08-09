# PhishLens 🔍

> A rule-based phishing email analyzer that scores messages by risk and explains *why* — built to make phishing detection transparent instead of a black box.

<!-- Optional badges once you have CI/license set up:
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Build](https://img.shields.io/github/actions/workflow/status/YOUR_USERNAME/phishlens/tests.yml)
-->

## Overview

PhishLens analyzes raw email text and headers to detect phishing indicators using a set of explainable, weighted heuristics — no black-box ML required. Every flagged email comes with a breakdown of *which* rules triggered and *why*, making it useful both as a detection tool and as a learning aid for understanding phishing tactics.

<!-- TODO: 1-2 sentence "why I built this" line — recruiters like a bit of motivation/context -->

## Demo

<!-- TODO: Add a screenshot or GIF of the app in action once the frontend/API is working.
Example:
![PhishLens demo](docs/demo.gif)
-->

## Features

- 🎯 **Weighted risk scoring** — combines multiple heuristics into a single risk score and level (Low / Medium / High)
- 🔎 **Explainable results** — every triggered rule returns a human-readable reason, not just a score
- 🌐 **Sender & domain analysis** — flags lookalike domains, display-name spoofing, and free-mail impersonation of corporate brands
- 🔗 **URL inspection** — detects mismatched link text/href, shorteners, IP-based URLs, and suspicious TLDs
- ⚠️ **Urgency & pressure language detection** — flags common social-engineering phrasing
- 💳 **Credential/financial bait detection** — flags requests for passwords, payment info, gift cards, etc.
- 📎 **Attachment red flags** — detects suspicious extensions and double-extension tricks
- 🧪 **Tested against real phishing samples** — validated with a labeled dataset of phishing and legitimate emails

<!-- Trim/expand this list to match what you actually built -->

## Tech Stack

- **Backend:** Python, FastAPI
- **Validation:** Pydantic
- **Testing:** pytest
- <!-- TODO: add frontend stack if you build one (e.g. plain HTML/JS, or React) -->
- <!-- TODO: add deployment target if applicable (Render, Railway, Docker, etc.) -->

## How It Works

PhishLens runs each email through a set of independent heuristic rules. Each rule returns:

```json
{
  "rule_name": "domain_lookalike",
  "triggered": true,
  "weight": 25,
  "explanation": "Sender domain 'paypa1-secure.com' closely resembles trusted brand 'paypal.com'"
}
```

The scorer sums the weights of all triggered rules into an overall risk score (0–100), which maps to a risk level:

| Score Range | Risk Level |
|---|---|
| 0–29  | Low |
| 30–59 | Medium |
| 60–100 | High |

<!-- TODO: update this table once your actual scoring thresholds are finalized -->

## Getting Started

### Prerequisites

- Python 3.11+
- pip

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/phishlens.git
cd phishlens
pip install -r requirements.txt
```

### Running the API

```bash
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

## Usage

### Analyze an email

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "raw_text": "Dear Customer, your account has been suspended. Click here to verify: http://paypa1-secure.com/login"
  }'
```

### Example response

```json
{
  "risk_score": 68,
  "risk_level": "High",
  "triggered_rules": [
    {
      "rule_name": "domain_lookalike",
      "explanation": "Sender domain resembles trusted brand 'paypal.com'",
      "weight": 25
    },
    {
      "rule_name": "urgency_language",
      "explanation": "Contains urgency phrase: 'account has been suspended'",
      "weight": 20
    },
    {
      "rule_name": "generic_greeting",
      "explanation": "Uses generic greeting 'Dear Customer' instead of a name",
      "weight": 10
    }
  ]
}
```

<!-- TODO: replace with a real example output once your API is working -->

## Project Structure

```
phishlens/
├── app/
│   ├── main.py              # FastAPI app, routes
│   ├── analyzer/
│   │   ├── heuristics.py    # individual detection rules
│   │   ├── scorer.py        # combines rule outputs into risk score
│   │   └── url_utils.py     # URL parsing/validation helpers
│   ├── models.py            # Pydantic request/response schemas
├── tests/
│   └── test_heuristics.py
├── data/
│   └── sample_phishing_emails/
├── requirements.txt
└── README.md
```

## Testing

```bash
pytest
```

<!-- TODO: mention test coverage or notable test cases once you have them -->

## Roadmap

- [ ] Add attachment/extension analysis
- [ ] Add a minimal web frontend for live demoing
- [ ] Expand dataset and tune rule weights against real-world samples
- [ ] Deploy a live demo
- [ ] <!-- add your own next steps -->

## Limitations

PhishLens uses rule-based heuristics rather than machine learning, so it won't catch novel phishing techniques that don't match known patterns. It's built as a transparent, explainable detector rather than a state-of-the-art classifier — see the Roadmap for planned improvements.

## License

<!-- TODO: pick a license (MIT is common for portfolio projects) and add a LICENSE file -->
This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Author

<!-- TODO: your name, LinkedIn/portfolio link, contact -->
Built by [James A] as a portfolio project exploring phishing detection and explainable security tooling.
