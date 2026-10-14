
import re
from urllib.parse import urlparse
from ipaddress import ip_address


def get_risk(score):
    """Convert a score into a risk category."""
    if score >= 50:
        return "High"
    elif score >= 20:
        return "Medium"
    return "Low"


def check_url(url):
    """Check a URL for common suspicious indicators without opening it."""

    url = url.strip()
    reasons = []
    score = 0

    if not url:
        return {
            "risk": "Unknown",
            "score": 0,
            "reasons": ["Please enter a URL."]
        }

    # Add a scheme only to help parse the URL.
    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""

        # Reject malformed or incomplete addresses.
        if not host or "." not in host:
            reasons.append("The URL format looks unusual.")
            score += 20

        # Only allow HTTP and HTTPS for this prototype.
        if parsed.scheme.lower() not in ("http", "https"):
            reasons.append("The URL uses an unexpected protocol.")
            score += 25
        elif parsed.scheme.lower() == "http":
            reasons.append("The URL does not use HTTPS.")
            score += 10

        # Check for misleading user information in the URL.
        if "@" in parsed.netloc:
            reasons.append(
                "The URL contains an @ symbol in its address."
            )
            score += 25

        # Check whether the hostname is an IP address.
        if host:
            try:
                ip_address(host)
                reasons.append(
                    "The address uses an IP address instead of a domain name."
                )
                score += 25
            except ValueError:
                pass

        # Check unusual URL characteristics.
        if len(url) > 100:
            reasons.append("The URL is unusually long.")
            score += 10

        if host.count("-") >= 3:
            reasons.append("The domain contains many hyphens.")
            score += 10

        if host.startswith("xn--") or ".xn--" in host:
            reasons.append(
                "The domain uses encoded international characters; "
                "verify that it is the intended website."
            )
            score += 15

        # These words are warning indicators, not proof of a scam.
        suspicious_words = [
            "verify",
            "login",
            "urgent",
            "free",
            "prize",
            "wallet",
            "password",
            "update",
            "secure",
            "claim",
            "banking"
        ]

        matches = [
            word for word in suspicious_words
            if re.search(
                r"\b" + re.escape(word) + r"\b",
                url.lower()
            )
        ]

        if matches:
            reasons.append(
                "The URL contains potentially suspicious words: "
                + ", ".join(matches)
            )
            score += min(20, len(matches) * 5)

    except (ValueError, UnicodeError):
        reasons.append("The URL could not be parsed.")
        score += 30

    score = min(score, 100)

    if not reasons:
        reasons.append(
            "No warning signs from the current rules were detected."
        )

    return {
        "risk": get_risk(score),
        "score": score,
        "reasons": reasons
    }


def check_message(message):
    """Check a message for common scam warning signs."""

    message = message.strip()

    if not message:
        return {
            "risk": "Unknown",
            "score": 0,
            "reasons": ["Please enter a message."]
        }

    text = message.lower()
    score = 0
    reasons = []

    patterns = [
        (
            r"\b(otp|one[- ]time password)\b",
            "The message mentions an OTP or one-time password.",
            25
        ),
        (
            r"\b(send|pay|transfer|deposit)\b.{0,50}"
            r"\b(money|rupees|rs\.?|inr|upi|fee|payment)\b",
            "The message may be requesting a payment or money transfer.",
            25
        ),
        (
            r"\b(urgent|immediately|act now|limited time|expires today)\b",
            "The message uses urgency or pressure tactics.",
            15
        ),
        (
            r"\b(prize|lottery|winner|won a reward|cashback)\b",
            "The message mentions a prize or unexpected reward.",
            20
        ),
        (
            r"\b(password|bank details|card number|cvv|pin)\b",
            "The message mentions sensitive account information.",
            25
        ),
        (
            r"\b(job offer|registration fee|work from home|"
            r"guaranteed income)\b",
            "The message mentions a job or income offer that needs verification.",
            10
        ),
        (
            r"\b(account (will be|is) blocked|suspend(ed|ing)? account)\b",
            "The message may be threatening account suspension.",
            20
        ),
        (
            r"\b(click here|click the link|verify your account)\b",
            "The message urges you to click a link or verify an account.",
            15
        )
    ]

    for pattern, reason, points in patterns:
        if re.search(pattern, text):
            reasons.append(reason)
            score += points

    # A URL in a message is a reason to inspect it, not proof of fraud.
    if re.search(r"https?://|www\.", text):
        reasons.append(
            "The message contains a web link. Verify the destination "
            "independently before opening it."
        )
        score += 10

    score = min(score, 100)

    if not reasons:
        reasons.append(
            "No warning signs from the current rules were detected."
        )

    return {
        "risk": get_risk(score),
        "score": score,
        "reasons": reasons
    }
