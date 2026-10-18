
from core.url_scanner import scan_url
from core.terms_summarizer import run_terms_summarizer
from core.email_scanner import analyze_email, analyze_eml
from providers.urlhaus import URLhausProvider
from providers.domain_intel import (
    normalize_domain,
    get_registration_info,
    check_brand_similarity,
)
def display_domain_intelligence(
    sender_domain,
    domain_info=None,
    brand_result=None,
):
    """Display domain intelligence, reusing results when available."""

    print("\n--- ONLINE DOMAIN INTELLIGENCE ---")

    if not sender_domain:
        print("No valid sender domain was identified.")
        return False

    registered_domain = normalize_domain(sender_domain)

    if not registered_domain:
        print("Could not identify a registered public domain.")
        print("The sender's domain may be invalid or use a reserved suffix.")
        return False

    print("Registered domain:", registered_domain)

    if brand_result is None:
        try:
            brand_result = check_brand_similarity(registered_domain)
        except Exception:
            brand_result = None

    if brand_result is not None:
        print("\nBrand check:", brand_result.get("message", "Unavailable"))
        for warning in brand_result.get("warnings", []):
            print("[!] " + warning)
    else:
        print("\nBrand check could not be completed.")

    try:
        if domain_info is None:
            info = get_registration_info(registered_domain)
        else:
            info = domain_info

        if not info.get("available"):
            print("\nRegistration lookup unavailable:")
            print(info.get("message", "No details were returned."))
            print("Local email analysis is still available.")
            return False

        print("\nRegistration information:")
        print("Registration date:", info.get("created") or "Unavailable")

        age_days = info.get("age_days")
        if age_days is not None:
            print("Domain age:", f"{age_days} days")
            if age_days < 30:
                print("[!] Recently registered domain. Investigate further.")
        else:
            print("Domain age: Unknown")

        print("Registrar:", info.get("registrar") or "Unavailable")
        print("Expiration date:", info.get("expires") or "Unavailable")

        if info.get("updated"):
            print("Last update:", info["updated"])

        return True

    except Exception:
        print("\nRegistration lookup failed unexpectedly.")
        print("Continuing with local email analysis.")
        return False

def display_email_result(result):
    print("\n=== EMAIL ANALYSIS RESULTS ===")
    print("Sender:", result.get("sender_address") or "Not identified")
    print("Sender domain:", result.get("sender_domain") or "Not identified")
    print("Subject:", result.get("subject", "(no subject)"))
    print("Risk estimate:", f'{result["score"]}/100')
    print("Risk level:", result["level"])
    print("Online check: Checking domain registration...")

    print("\n--- WARNINGS ---")
    if result["warnings"]:
        for warning in result["warnings"]:
            print("[!] " + warning)
    else:
        print("No warning patterns detected by the current rules.")

    print("\n--- OBSERVATIONS ---")
    for item in result.get("observations", []):
        print("-", item)

    print("\n--- LINKS FOUND ---")
    if result["links"]:
        for index, link in enumerate(result["links"], start=1):
            print(f"\nLink {index}:")
            print("Type:", link["type"])
            print("Displayed text:", link["visible_text"])
            print("Destination:", link["destination"])
    else:
        print("No links found in the available email content.")

    if "authentication_headers" in result:
        print("\n--- EMAIL AUTHENTICATION HEADERS ---")
        headers = result["authentication_headers"]

        if headers:
            for header in headers:
                print(header)
        else:
            print("No Authentication-Results header found.")

        print("These headers are evidence to inspect, not independent proof.")

    # Additional online checks; failures do not stop the email report.
    online_success = display_domain_intelligence(
    result.get("sender_domain"),
    domain_info=result.get("domain_info"),
    brand_result=result.get("brand_result"),
    )
    print("\nOnline check:", "Yes" if online_success else "No")

    print("\nImportant:")

    print("\nImportant:")
    print("- This score is a heuristic, not a probability.")
    print("- A low score does not guarantee an email is safe.")
    print("- Links are analyzed as text and are never opened.")
    print("- Domain age and brand matches are indicators, not proof.")


def show_email_scanner():
    print("\n=== EMAIL PHISHING SCANNER ===")
    print("1. Paste email details")
    print("2. Analyze a saved .eml file")
    print("3. Return to main menu")

    choice = input("Choose an option (1-3): ").strip()

    if choice == "1":
        sender = input("Sender email address: ").strip()
        subject = input("Email subject: ").strip()

        print("Paste the email body.")
        print("Type END on a separate line when finished.")

        lines = []

        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)

        body = "\n".join(lines)

        result = analyze_email(
            sender=sender,
            subject=subject,
            body=body,
        )
        display_email_result(result)

        print(
            "\nNote: Pasting plain text cannot reliably reveal hidden HTML "
            "link destinations or original email authentication headers."
        )

    elif choice == "2":
        file_path = input(
            "Enter the path to your saved .eml file: "
        ).strip()

        file_path = file_path.strip("\"'")

        try:
            result = analyze_eml(file_path)
            display_email_result(result)
        except (OSError, ValueError) as error:
            print("\nCould not analyze the email file:", error)

    elif choice == "3":
        return

    else:
        print("Invalid choice. Please select 1, 2, or 3.")


def show_link_analyzer():
    print("\n=== LINK ANALYZER ===")
    print("Local analysis runs first. URLhaus lookup is optional.")

    url = input("Paste a URL: ").strip()
    local = scan_url(url)

    print("\n--- LOCAL ANALYSIS ---")

    if local["level"] == "INVALID INPUT":
        print("Validation status: INVALID URL")
        print("The URL could not be analyzed.")
    else:
        print("Validation status: Accepted for analysis")
        print("Risk estimate:", f'{local["score"]}/100')
        print("Risk level:", local["level"])
        print("Note: The score is heuristic, not a probability.")

    if local.get("hostname"):
        print("Hostname:", local["hostname"])

    print("\nWarnings:")
    for finding in local["findings"]:
        print("-", finding)

    observations = local.get("observations", [])
    if observations:
        print("\nObservations:")
        for observation in observations:
            print("-", observation)

    print("\n--- ONLINE THREAT LOOKUP ---")
    print("1. Local analysis only (no URLhaus lookup)")
    print("2. Local analysis + URLhaus lookup")

    lookup_choice = input("Choose an option (1-2): ").strip()

    if lookup_choice == "2":
        if local["level"] == "INVALID INPUT":
            print("Invalid URL. Online lookup skipped.")
        else:
            print("\n--- URLHAUS LOOKUP ---")
            result = URLhausProvider().check_url(url)

            print("Provider: URLhaus")
            print("Lookup available:", result["available"])
            print("Result:", result["message"])

            if result["available"] and result["malicious"] is True:
                print("[!] URLhaus has a record for this URL.")
            elif result["available"] and result["malicious"] is False:
                print("No matching URLhaus record was found.")
    elif lookup_choice == "1":
        print("Online lookup skipped. URL was not submitted to URLhaus.")
    else:
        print("Invalid choice. Online lookup skipped.")

    print("\nRemember:")
    print("- A local score is a heuristic, not a probability.")
    print("- No matching threat record does not prove a URL is safe.")
    print("- URLhaus is contacted only when you choose option 2.")



def main():
    print("=" * 42)
    print("             EYES OF TRUTH")
    print("           Security Analyzer")
    print("=" * 42)

    name = input("\nEnter your name: ").strip() or "User"
    print(f"\nWelcome to Eyes of Truth, {name}!")

    while True:
        print("\nMAIN MENU")
        print("1. Email Phishing Scanner")
        print("2. Link Analyzer (Local + URLhaus)")
        print("3. Terms Summarizer")
        print("4. Exit")

        choice = input("Select an option (1-4): ").strip()

        if choice == "1":
            show_email_scanner()
        elif choice == "2":
            show_link_analyzer()
        elif choice == "3":
            run_terms_summarizer()
        elif choice == "4":
            print("\nThank you for using Eyes of Truth!")
            break
        else:
            print("\nInvalid choice. Enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
