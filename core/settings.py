import os
from dotenv import load_dotenv

load_dotenv()


def get_provider_keys():
    """Read optional provider keys from the local environment."""

    return {
        "urlhaus": os.getenv("URLHAUS_AUTH_KEY", "").strip(),
        "phishtank": os.getenv("PHISHTANK_API_KEY", "").strip(),
        "google_safe_browsing": os.getenv(
            "GOOGLE_SAFE_BROWSING_API_KEY", ""
        ).strip(),
    }


def get_provider_status():
    """Return configuration status without revealing secret values."""

    return {
        provider: bool(key)
        for provider, key in get_provider_keys().items()
    }


if __name__ == "__main__":
    print("=== EYES OF TRUTH: PROVIDER SETTINGS ===")

    for provider, configured in get_provider_status().items():
        status = "Configured" if configured else "Not configured"
        print(f"{provider}: {status}")
