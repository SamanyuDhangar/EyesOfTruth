
import json
import re
from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path

DATABASE_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "trusted_brands.json"
)


def normalize_domain(domain):
    """Normalize a domain for comparison; do not trust it based on spelling alone."""
    if not isinstance(domain, str):
        return ""

    domain = domain.strip().lower().rstrip(".")

    if domain.startswith("http://") or domain.startswith("https://"):
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or ""

    if "@" in domain:
        domain = domain.rsplit("@", 1)[-1]

    if "/" in domain:
        domain = domain.split("/", 1)[0]

    if ":" in domain:
        domain = domain.split(":", 1)[0]

    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""

    if len(domain) > 253 or not domain:
        return ""

    labels = domain.split(".")
    if len(labels) < 2:
        return ""

    label_pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    if any(not label_pattern.fullmatch(label) for label in labels):
        return ""

    return domain


@lru_cache(maxsize=1)
def load_brands():
    """Load canonical domains from the local JSON database."""
    try:
        with DATABASE_PATH.open("r", encoding="utf-8") as file:
            database = json.load(file)
    except (OSError, json.JSONDecodeError):
        return []

    result = []

    for brand in database.get("brands", []):
        name = brand.get("name")
        domains = brand.get("domains", [])
        category = brand.get("category", "Other")

        if not isinstance(name, str) or not isinstance(domains, list):
            continue

        for domain in domains:
            normalized = normalize_domain(domain)
            if normalized:
                result.append({
                    "name": name,
                    "domain": normalized,
                    "category": category,
                })

    return result


def domain_matches_brand(sender_domain, brand_domain):
    """Match the canonical domain or a genuine subdomain of it."""
    return (
        sender_domain == brand_domain
        or sender_domain.endswith("." + brand_domain)
    )


def _similarity(left, right):
    return SequenceMatcher(None, left, right).ratio()


def analyze_brand_domain(sender_domain):
    """
    Identify a known brand or a possible lookalike.

    This result is a signal for the email scanner, not proof that an
    email is legitimate or malicious.
    """
    domain = normalize_domain(sender_domain)

    if not domain:
        return {
            "status": "invalid_domain",
            "brand": None,
            "matched_domain": None,
            "warnings": ["Sender domain could not be normalized."],
            "observations": [],
        }

    brands = load_brands()

    for entry in brands:
        if domain_matches_brand(domain, entry["domain"]):
            return {
                "status": "canonical_domain_match",
                "brand": entry["name"],
                "matched_domain": entry["domain"],
                "category": entry["category"],
                "warnings": [],
                "observations": [
                    f"Sender domain matches the listed domain for {entry['name']}."
                ],
            }

    sender_label = domain.split(".")[0]
    possible_matches = []

    for entry in brands:
        official_label = entry["domain"].split(".")[0]

        if len(sender_label) < 5 or len(official_label) < 5:
            continue

        similarity = _similarity(sender_label, official_label)

        # Similar spelling is only a warning signal. Keep the threshold
        # conservative to reduce false positives.
        if similarity >= 0.84 and sender_label != official_label:
            possible_matches.append((similarity, entry))

    if possible_matches:
        possible_matches.sort(key=lambda item: item[0], reverse=True)
        similarity, match = possible_matches[0]

        return {
            "status": "possible_lookalike",
            "brand": match["name"],
            "matched_domain": match["domain"],
            "category": match["category"],
            "similarity": round(similarity, 3),
            "warnings": [
                f"Sender domain may imitate {match['name']}."
            ],
            "observations": [
                f"Compare the sender domain carefully with {match['domain']}."
            ],
        }

    return {
        "status": "unknown_domain",
        "brand": None,
        "matched_domain": None,
        "warnings": [],
        "observations": [
            "Sender domain is not in the local brand database; legitimacy is unverified."
        ],
    }
