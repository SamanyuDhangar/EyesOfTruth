

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from providers.domain_intel import check_brand_similarity, get_registration_info
from core.brand_intel import analyze_brand_domain

class EmailLinkParser(HTMLParser):
    """Extract clickable links from HTML without opening them."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.current_link = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            attributes = dict(attrs)
            href = attributes.get("href", "")

            self.current_link = {
                "destination": href,
                "visible_text": "",
            }
            self.links.append(self.current_link)

    def handle_data(self, data):
        if self.current_link is not None:
            self.current_link["visible_text"] += data

    def handle_endtag(self, tag):
        if tag.lower() == "a":
            self.current_link = None


def get_domain(value):
    """Extract a hostname from a URL or an email address."""

    value = value.strip()

    if not value:
        return None

    if "@" in value and "://" not in value:
        address = parseaddr(value)[1]
        if "@" not in address:
            return None
        domain = address.rsplit("@", 1)[1].lower()
    else:
        candidate = value if "://" in value else "https://" + value

        try:
            domain = urlparse(candidate).hostname
        except ValueError:
            return None

    if not domain:
        return None

    return domain.rstrip(".").lower()


def extract_text_urls(text):
    """Find URLs written directly in the email text."""

    pattern = r"""https?://[^\s<>"']+"""
    return re.findall(pattern, text, flags=re.IGNORECASE)


def get_email_parts(message):
    """Extract plain-text and HTML bodies from an email message."""

    plain_parts = []
    html_parts = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue

            if part.get_content_disposition() == "attachment":
                continue

            content_type = part.get_content_type()

            if content_type not in ("text/plain", "text/html"):
                continue

            try:
                content = part.get_content()
            except (LookupError, UnicodeDecodeError, ValueError):
                continue

            if not isinstance(content, str):
                continue

            if content_type == "text/plain":
                plain_parts.append(content)
            else:
                html_parts.append(content)
    else:
        try:
            content = message.get_content()
        except (LookupError, UnicodeDecodeError, ValueError):
            content = ""

        if isinstance(content, str):
            if message.get_content_type() == "text/html":
                html_parts.append(content)
            else:
                plain_parts.append(content)

    return "\n".join(plain_parts), "\n".join(html_parts)


def analyze_email(sender, subject, body, html_body=""):
    """Perform local email checks. No links are opened."""

    sender_name, sender_address = parseaddr(sender or "")
    sender_domain = get_domain(sender_address)

    full_text = "\n".join(
        [sender or "", subject or "", body or "", html_body or ""]
    )
    searchable_text = full_text.lower()

    warnings = []
    observations = []
    score = 0

    # Keep online results so main.py can reuse them.
    brand_result = None
    domain_info = {
    "available": False,
    "message": "Domain registration lookup did not complete.",
    }
    
    # Sender information
    if sender_address and sender_domain:
        observations.append(f"Sender domain: {sender_domain}")


        # Identify known brands and possible lookalike domains.
        try:
            brand_result = analyze_brand_domain(sender_domain)

            for warning in brand_result.get("warnings", []):
                if warning not in warnings:
                    warnings.append(warning)
                    score += 20

            for observation in brand_result.get("observations", []):
                if observation not in observations:
                    observations.append(observation)

        except Exception:
            observations.append(
                "Brand intelligence check could not be completed."
            )


        # Check public registration data for recently registered domains.
        # This is an online lookup; failure must not stop local analysis.
        try:
            domain_info = get_registration_info(sender_domain)

            if domain_info.get("available"):
                age_days = domain_info.get("age_days")

                if age_days is not None and age_days < 30:
                    warnings.append(
                        "Sender domain was registered less than 30 days ago."
                    )
                    score += 10
                    observations.append(
                        f"Domain age: {age_days} days."
                    )
                elif age_days is not None:
                    observations.append(
                        f"Domain age: {age_days} days."
                    )
            else:
                observations.append(
                    "Domain registration age could not be verified."
                )

        except Exception:
            observations.append(
                "Online domain lookup failed; local checks continued."
            )

    else:
        warnings.append(
            "A valid sender email address could not be identified."
        )
        score += 10


    # Basic suspicious-language checks
    rules = {
        "Urgent or pressuring language": [
            "urgent", "immediately", "act now", "account will be closed"
        ],
        "Password or account verification request": [
            "password", "verify your account", "login details",
            "confirm your credentials"
        ],
        "Suspicious clicking instructions": [
            "click here", "open attachment", "sign in now"
        ],
        "Unexpected prize or reward": [
            "won a prize", "claim your reward", "you are a winner"
        ],
        "Payment or financial pressure": [
            "payment failed", "send money", "update your billing"
        ],
    }

    for category, phrases in rules.items():
        if any(phrase in searchable_text for phrase in phrases):
            warnings.append(category)
            score += 15

    # Extract clickable links from HTML.
    html_parser = EmailLinkParser()

    if html_body:
        try:
            html_parser.feed(html_body)
        except (ValueError, AssertionError):
            warnings.append("Some HTML content could not be fully analyzed.")

    links = []
    seen = set()
    link_mismatch_found = False

    # Links embedded in HTML, including hidden destinations.
    for item in html_parser.links:
        destination = item["destination"].strip()
        visible_text = item["visible_text"].strip()

        if not destination:
            continue

        key = ("html", destination, visible_text)

        if key in seen:
            continue

        seen.add(key)

        link_info = {
            "destination": destination,
            "visible_text": visible_text or "(no visible link text)",
            "type": "HTML link",
        }

        links.append(link_info)

        visible_domain = get_domain(visible_text)
        destination_domain = get_domain(destination)

        if (
            visible_domain
            and destination_domain
            and visible_domain != destination_domain
        ):
            warning = (
                "A clickable link's displayed domain differs from its destination."
            )

            if warning not in warnings:
                warnings.append(warning)

            if not link_mismatch_found:
                score += 10
                link_mismatch_found = True

    # URLs written directly in the message body.
    for url in extract_text_urls(body or ""):
        key = ("text", url, url)

        if key in seen:
            continue

        seen.add(key)

        links.append({
            "destination": url,
            "visible_text": url,
            "type": "URL in text",
        })

    # Highlight unusual URL patterns.
    for link in links:
        destination = link["destination"]

        if destination.startswith("//"):
            warnings.append("A link uses a protocol-relative destination.")
            score += 10
            continue

        try:
            parsed = urlparse(destination)
            hostname = parsed.hostname
        except ValueError:
            hostname = None

        if not hostname:
            warnings.append("A link has an unusual or unrecognized destination.")
            score += 10
            continue

        if parsed.scheme not in ("http", "https"):
            warnings.append("A link uses a non-HTTP(S) scheme.")
            score += 20

        if "@" in parsed.netloc:
            warnings.append("A link contains @ before its hostname.")
            score += 20

    # Remove duplicate warning messages.
    warnings = list(dict.fromkeys(warnings))
    score = min(score, 100)

    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not warnings:
        observations.append("No warning patterns from the current rules were detected.")

    return {
        "sender_name": sender_name,
        "sender_address": sender_address,
        "sender_domain": sender_domain,
        "subject": subject or "(no subject)",
        "score": score,
        "level": level,
        "warnings": warnings,
        "observations": observations,
        "links": links,
        "brand_result": brand_result,
"domain_info": domain_info,
"checked_online": domain_info.get("available", False),
    }


def analyze_eml(file_path):
    """Read an .eml file locally and analyze its contents."""

    path = Path(file_path).expanduser()

    if not path.is_file():
        raise FileNotFoundError("The specified .eml file was not found.")

    if path.suffix.lower() != ".eml":
        raise ValueError("Please select a file with the .eml extension.")

    # Limit the initial prototype to reasonably sized email files.
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("The email file exceeds the 10 MB limit.")

    with path.open("rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    body, html_body = get_email_parts(message)

    result = analyze_email(
        sender=str(message.get("From", "")),
        subject=str(message.get("Subject", "")),
        body=body,
        html_body=html_body,
    )

    # Authentication headers are evidence to inspect, not proof by themselves.
    auth_headers = message.get_all("Authentication-Results", [])

    result["authentication_headers"] = [
        str(header) for header in auth_headers
    ]

    result["input_type"] = "EML file"

    return result


if __name__ == "__main__":
    print("=== EYES OF TRUTH: EMAIL ENGINE TEST ===")
    print("This test runs locally and does not open links.")

    sender = input("Sender email: ").strip()
    subject = input("Email subject: ").strip()

    print("Paste the email body. Type END on a separate line when finished.")

    lines = []

    while True:
        line = input()

        if line.strip().upper() == "END":
            break

        lines.append(line)

    result = analyze_email(sender, subject, "\n".join(lines))

    print("\n--- EMAIL ANALYSIS ---")
    print("Sender domain:", result["sender_domain"] or "Not identified")
    print("Risk estimate:", f'{result["score"]}/100')
    print("Risk level:", result["level"])

    print("\nWarnings:")
    for warning in result["warnings"]:
        print("-", warning)

    print("\nLinks:")
    for link in result["links"]:
        print("Displayed text:", link["visible_text"])
        print("Destination:", link["destination"])
        print()

    print("\nThis estimate is heuristic, not proof of maliciousness.")
