import json
import os
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from dotenv import load_dotenv
from providers.base import ThreatProvider

load_dotenv()


class URLhausProvider(ThreatProvider):
    """Look up URLs using the user's URLhaus authentication key."""

    name = "URLhaus"
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, auth_key=None):
        self.auth_key = (
        auth_key if auth_key is not None
        else os.getenv("URLHAUS_AUTH_KEY", "")
    ).strip()

    def check_url(self, url):
        if not self.auth_key:
            return {
                "available": False,
                "malicious": None,
                "message": "URLhaus key is not configured.",
            }

        if not url or not url.strip():
            return {
                "available": False,
                "malicious": None,
                "message": "No URL was provided.",
            }

        data = urlencode({"url": url.strip()}).encode("utf-8")

        request = Request(
            self.endpoint,
            data=data,
            headers={
                "Auth-Key": self.auth_key,
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "EyesOfTruth/0.1",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))

            status = result.get("query_status")

            if status == "ok":
                return {
                    "available": True,
                    "malicious": True,
                    "message": "URLhaus has a record for this URL.",
                    "url_status": result.get("url_status", "unknown"),
                }

            if status == "no_results":
                return {
                    "available": True,
                    "malicious": False,
                    "message": "No matching URLhaus record was found.",
                }

            return {
                "available": False,
                "malicious": None,
                "message": f"URLhaus returned status: {status or 'unknown'}.",
            }

        except HTTPError as error:
            return {
                "available": False,
                "malicious": None,
                "message": f"URLhaus HTTP error: {error.code}.",
            }

        except (URLError, TimeoutError):
            return {
                "available": False,
                "malicious": None,
                "message": "Could not reach URLhaus. Check your connection.",
            }

        except (json.JSONDecodeError, UnicodeDecodeError):
            return {
                "available": False,
                "malicious": None,
                "message": "URLhaus returned an unreadable response.",
            }


if __name__ == "__main__":
    provider = URLhausProvider()

    print("Provider:", provider.name)
    print("API key configured:", bool(provider.auth_key))

    if not provider.auth_key:
        print("Check your .env file. No online request was made.")
    else:
        print("Key detected. No online request was made during this test.")
