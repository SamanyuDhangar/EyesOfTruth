
import json
import re
from difflib import SequenceMatcher
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import tldextract


# Use bundled public-suffix data without downloading it.
extract_domain = tldextract.TLDExtract(suffix_list_urls=())

RDAP_ENDPOINT = "https://rdap.org/domain/"

TRUSTED_BRANDS = {
    "google": ["google.com"],
    "openai": ["openai.com"],
}

# Common character substitutions used in lookalike domains.
CONFUSABLES = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
})


def normalize_domain(value):
    """Extract a registered public domain from a hostname or email."""

    if not isinstance(value, str):
        return None

    value = value.strip().lower()

    if "@" in value:
        value = value.rsplit("@", 1)[1]

    value = value.rstrip(".")

    if "://" in value or "/" in value or " " in value:
        return None

    if not re.fullmatch(r"[a-z0-9.-]+", value):
        return None

    if ".." in value or value.startswith(".") or value.endswith("."):
        return None

    extracted = extract_domain(value)

    if not extracted.domain or not extracted.suffix:
        return None

    return f"{extracted.domain}.{extracted.suffix}"


def get_registration_info(domain):
    """Retrieve public domain registration information using RDAP."""

    registered_domain = normalize_domain(domain)

    if not registered_domain:
        return {
            "available": False,
            "domain": domain,
            "message": "Could not identify a valid registered domain.",
        }

    url = RDAP_ENDPOINT + quote(registered_domain, safe=".-")
    request = Request(
        url,
        headers={"User-Agent": "EyesOfTruth/0.1"},
    )

    try:
        with urlopen(request, timeout=12) as response:
            data = json.loads(response.read().decode("utf-8"))

        dates = {}

        for event in data.get("events", []):
            action = event.get("eventAction", "").lower()
            date = event.get("eventDate")

            if action in ("registration", "registered"):
                dates["created"] = date
            elif action in ("expiration", "expiry"):
                dates["expires"] = date
            elif action in (
                "last changed",
                "last update of rdap database",
            ):
                dates["updated"] = date

        creation_date = dates.get("created")
        age_days = None

        if creation_date:
            try:
                created = datetime.fromisoformat(
                    creation_date.replace("Z", "+00:00")
                )

                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                age_days = (
                    datetime.now(timezone.utc) - created
                ).days

                if age_days < 0:
                    age_days = None

            except ValueError:
                pass

        registrar = None

        for entity in data.get("entities", []):
            if "registrar" not in entity.get("roles", []):
                continue

            vcard = entity.get("vcardArray", [None, []])

            for item in vcard[1]:
                if len(item) >= 4 and item[0] == "fn":
                    registrar = item[3]
                    break

            if registrar:
                break

        return {
            "available": True,
            "domain": registered_domain,
            "created": creation_date,
            "age_days": age_days,
            "expires": dates.get("expires"),
            "updated": dates.get("updated"),
            "registrar": registrar,
            "message": "Registration information retrieved.",
        }

    except HTTPError as error:
        return {
            "available": False,
            "domain": registered_domain,
            "message": f"RDAP lookup returned HTTP {error.code}.",
        }

    except (URLError, TimeoutError, OSError):
        return {
            "available": False,
            "domain": registered_domain,
            "message": "RDAP lookup failed. Check your internet connection.",
        }

    except (json.JSONDecodeError, UnicodeDecodeError):
        return {
            "available": False,
            "domain": registered_domain,
            "message": "The RDAP service returned an unreadable response.",
        }


def check_brand_similarity(domain):
    """Flag configured brand names and common lookalike patterns."""

    registered_domain = normalize_domain(domain)

    if not registered_domain:
        return {
            "domain": domain,
            "warnings": [],
            "message": "Domain could not be normalized.",
        }

    extracted = extract_domain(registered_domain)
    label = extracted.domain.lower()
    warnings = []

    for brand, official_domains in TRUSTED_BRANDS.items():

        # Do not flag the configured official domain.
        if registered_domain in official_domains:
            continue

        # Normalize common number-for-letter substitutions.
        normalized_label = label.translate(CONFUSABLES)

        if brand in label:
            warnings.append(
                f"The domain contains the brand name '{brand}' "
                "but is not a configured official domain."
            )
            continue

        if brand in normalized_label:
            warnings.append(
                f"The domain resembles '{brand}' through possible "
                "character substitution."
            )
            continue

        # Detect small spelling changes, such as 'gogle'.
        # Compare the whole domain label, not its top-level suffix.
        similarity = SequenceMatcher(
            None, normalized_label, brand
        ).ratio()

        if (
            abs(len(normalized_label) - len(brand)) <= 2
            and similarity >= 0.75
        ):
            warnings.append(
                f"The domain spelling is similar to the brand "
                f"'{brand}' ({similarity:.0%} similarity)."
            )

    return {
        "domain": registered_domain,
        "warnings": list(dict.fromkeys(warnings)),
        "message": (
            "Potential brand impersonation indicators detected."
            if warnings
            else "No configured brand similarity detected."
        ),
    }


if __name__ == "__main__":
    domain = input(
        "Enter a domain or sender email address: "
    ).strip()

    registered_domain = normalize_domain(domain)

    print("\nRegistered domain:", registered_domain or "Not identified")

    if registered_domain:
        print("\n--- BRAND CHECK ---")
        brand_result = check_brand_similarity(registered_domain)
        print(brand_result["message"])

        for warning in brand_result["warnings"]:
            print("[!]", warning)

        print("\n--- RDAP REGISTRATION DATA ---")
        result = get_registration_info(registered_domain)
        print(result["message"])

        if result["available"]:
            print("Domain:", result["domain"])
            print("Registration date:", result["created"] or "Unavailable")
            print(
                "Age in days:",
                result["age_days"]
                if result["age_days"] is not None
                else "Unknown",
            )
            print("Expiration date:", result["expires"] or "Unavailable")
            print("Registrar:", result["registrar"] or "Unavailable")

            if result["age_days"] is not None and result["age_days"] < 30:
                print("[!] Recently registered domain: investigate further.")
