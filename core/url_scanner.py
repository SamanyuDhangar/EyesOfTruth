 
from urllib.parse import unquote, urlparse
import ipaddress
import re
from difflib import SequenceMatcher

TRUSTED_BRANDS = {
    "google": ["google.com"],
    "openai": ["openai.com"],
    "microsoft": ["microsoft.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
}


def get_brand_warnings(hostname):
    """Flag possible brand impersonation without claiming certainty."""
    warnings = []
    labels = hostname.lower().split(".")

    for brand, official_domains in TRUSTED_BRANDS.items():
        # Allow exact official domains and their subdomains.
        if any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in official_domains
        ):
            continue

        for label in labels:
            if label == brand:
                warnings.append(
                    f"Hostname contains '{brand}' but is not a configured "
                    "official domain. Check for impersonation."
                )
                break

                        # Only compare labels reasonably similar in length.
            if abs(len(label) - len(brand)) <= 2:
                normalized = label.translate(
                    str.maketrans({
                        "0": "o",
                        "1": "l",
                        "3": "e",
                        "4": "a",
                        "5": "s",
                        "7": "t",
                    })
                )

                if label != brand and (
                    SequenceMatcher(None, normalized, brand).ratio() >= 0.80
                ):
                    warnings.append(
                        f"Hostname label '{label}' resembles '{brand}'. "
                        "Possible lookalike domain."
                    )
                    break

    return warnings


def scan_url(url):
    """Analyze URL structure locally without contacting the destination."""

    url = url.strip()

    if not url:
        return {
            "score": 0,
            "level": "INVALID INPUT",
            "findings": ["Please enter a URL."],
            "observations": [],
            "checked_online": False,
        }

    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(candidate)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Unsupported URL scheme.")

        if not parsed.hostname:
            raise ValueError("Missing hostname.")

        # Accessing .port validates that the port is numeric and in range.
        port = parsed.port
        hostname = parsed.hostname.rstrip(".").lower()

        if any(char.isspace() for char in hostname):
            raise ValueError("Whitespace is not allowed in the hostname.")

                 # Validate hostname format while allowing IP addresses.
        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        if not is_ip_address:
            try:
                ascii_hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                raise ValueError("Hostname contains invalid international characters.")

            if len(ascii_hostname) > 253:
                raise ValueError("Hostname is too long.")

            labels = ascii_hostname.split(".")

            for label in labels:
                if (
                    not label
                    or len(label) > 63
                    or not re.fullmatch(
                        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
                        label,
                    )
                ):
                    raise ValueError(
                        f"Invalid hostname label: '{label}'."
                    )

        warnings = []
        observations = []
        score = 0

        # Check for encoded characters that may obscure a URL.
        decoded_url = unquote(url)

        if decoded_url != url:
            observations.append(
                "URL contains percent-encoded characters. "
                "Encoding is common, but inspect the decoded form."
            )

        if re.search(r"%0[ad]|%1[0-9a-f]|%7f", url, re.IGNORECASE):
            warnings.append(
                "URL contains encoded control characters that may obscure parsing."
            )
            score += 15

        if parsed.scheme == "http":
            warnings.append("Uses HTTP; the connection is not encrypted.")
            score += 15
        else:
            observations.append(
                "Uses HTTPS. Encryption does not guarantee that a site is safe."
            )

        if "@" in parsed.netloc:
            warnings.append(
                f"Contains '@' in the authority section. "
                f"The actual hostname is '{hostname}'. "
                "The URL may be disguising its destination."
             )
            score += 25

        if "xn--" in hostname:
            warnings.append(
                "Contains punycode. Inspect carefully for lookalike characters."
            )
            score += 20

        try:
            ipaddress.ip_address(hostname)
            warnings.append("Uses an IP address instead of a domain name.")
            score += 15
        except ValueError:
            pass

        if len(hostname) > 50:
            warnings.append("Hostname is unusually long.")
            score += 10

        if len(url) > 200:
            warnings.append("URL is unusually long.")
            score += 10

        if hostname.count(".") >= 4:
            warnings.append("Hostname has many subdomain levels.")
            score += 10

        if parsed.username is not None or parsed.password is not None:
            warnings.append(
                "Contains user-information fields before the hostname."
            )
            score += 25

        # Nonstandard ports are worth inspecting, but are not proof of danger.
        if port is not None and port not in (80, 443):
            warnings.append(
                f"Uses nonstandard web port {port}. Check whether it is expected."
            )
            score += 10

                # Brand lookalike checks.
        brand_warnings = get_brand_warnings(hostname)
        for warning in brand_warnings:
            warnings.append(warning)
            score += 25

        # Treat a possible brand lookalike as at least medium risk.
        if brand_warnings:
            score = max(score, 30)

        # Avoid duplicate messages and cap the score.
        warnings = list(dict.fromkeys(warnings))
        score = min(score, 100)

        if score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        if not warnings:
            observations.append(
                "No warning patterns from the current rules were detected."
            )

        return {
            "score": score,
            "level": level,
            "findings": warnings or ["No listed warning patterns detected."],
            "observations": observations,
            "checked_online": False,
            "hostname": hostname,
        }

    except ValueError as error:
        return {
            "score": 0,
            "level": "INVALID INPUT",
            "findings": [str(error)],
            "observations": [],
            "checked_online": False,
        }


if __name__ == "__main__":
    url = input("Enter a URL to analyze: ")
    result = scan_url(url)

    print("\n=== LOCAL URL ANALYSIS ===")
    print("Risk estimate:", f'{result["score"]}/100')
    print("Risk level:", result["level"])

    print("\nWarnings:")
    for item in result["findings"]:
        print("-", item)

    print("\nObservations:")
    for item in result["observations"]:
        print("-", item)
