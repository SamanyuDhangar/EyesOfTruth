
import re
from pathlib import Path
from collections import Counter


TOPIC_KEYWORDS = {
    "Data collection": [
        "collect", "personal data", "information", "location",
        "device", "browsing history"
    ],
    "Data sharing": [
        "share", "third party", "third parties", "partner",
        "sell your data", "disclose"
    ],
    "Tracking and advertising": [
        "cookie", "tracking", "analytics", "advertising",
        "targeted ads"
    ],
    "Payments and subscriptions": [
        "subscription", "billing", "payment", "renewal",
        "fee", "charge", "automatically renew"
    ],
    "Cancellation and refunds": [
        "cancel", "cancellation", "terminate", "termination",
        "delete your account", "refund"
    ],
    "Liability and legal terms": [
        "liability", "liable", "warranty", "indemnify",
        "arbitration", "dispute"
    ],
    "Security and data retention": [
        "security", "encrypt", "retain", "retention",
        "breach", "store your data"
    ],
}


# Each rule contains a category, matching patterns, and an explanation.
# A match is a reason to review a clause, not proof of wrongdoing.
RISK_RULES = [
    {
        "category": "Automatic renewal",
        "patterns": [
            r"\bauto(?:matically)?[- ]renew(?:s|al|ed|ing)?\b",
            r"\bsubscription.{0,60}\brenew(?:s|al|ed|ing)?\b",
            r"\brenew(?:s|al|ed|ing)?.{0,60}\bsubscription\b",
        ],
        "explanation": (
            "Check when renewal happens, whether charges repeat, "
            "and how to stop future renewals."
        ),
    },
    {
        "category": "Cancellation restrictions",
        "patterns": [
            r"\bcancel(?:lation)?\b",
            r"\bterminate(?:d|s|tion)?\b",
        ],
        "explanation": (
            "Review the cancellation process, deadlines, and any "
            "conditions that could make ending the service difficult."
        ),
    },
    {
        "category": "Data sharing or sale",
        "patterns": [
            r"\bsell\b.{0,60}\b(?:data|information)\b",
            r"\b(?:data|information)\b.{0,60}\bsell\b",
            r"\bshare\b.{0,80}\b(?:third parties|partners|advertisers)\b",
            r"\b(?:third parties|partners|advertisers)\b.{0,80}\bshare\b",
            r"\bdisclose\b.{0,60}\b(?:data|information)\b",
        ],
        "explanation": (
            "Check who may receive your information, for what purpose, "
            "and whether you can opt out."
        ),
    },
    {
        "category": "Tracking and targeted advertising",
        "patterns": [
            r"\btargeted advertis(?:ing|ements)\b",
            r"\btargeted ads\b",
            r"\btrack(?:s|ing)?\b.{0,60}\b(?:activity|behavior|browsing)\b",
            r"\bcookies?\b",
        ],
        "explanation": (
            "Review what activity may be tracked and whether tracking "
            "is used for analytics or advertising."
        ),
    },
    {
        "category": "Broad data collection",
        "patterns": [
            r"\bcollect\b.{0,80}\b(?:personal data|personal information|"
            r"location|browsing history|contacts)\b",
            r"\b(?:location|browsing history|contacts)\b.{0,80}\bcollect\b",
        ],
        "explanation": (
            "Check which information is collected, why it is needed, "
            "and whether collection is optional."
        ),
    },
    {
        "category": "Liability limitations",
        "patterns": [
            r"\blimit(?:ed|ation|ations)?\b.{0,60}\bliability\b",
            r"\bdisclaim(?:s|er|ed)?\b.{0,60}\bwarrant(?:y|ies)\b",
            r"\bas is\b",
            r"\bnot liable\b",
        ],
        "explanation": (
            "Review which responsibilities or remedies the provider "
            "says are limited. The effect depends on applicable law."
        ),
    },
    {
        "category": "Arbitration and disputes",
        "patterns": [
            r"\bmandatory arbitration\b",
            r"\bbinding arbitration\b",
            r"\bclass action waiver\b",
        ],
        "explanation": (
            "Check how disputes must be handled and whether any "
            "rights or options are limited."
        ),
    },
    {
        "category": "Data retention",
        "patterns": [
            r"\bretain\b.{0,60}\b(?:data|information)\b",
            r"\b(?:data|information)\b.{0,60}\bretain\b",
            r"\bretain(?:ed|s)? indefinitely\b",
            r"\bstore\b.{0,60}\b(?:personal data|personal information)\b",
        ],
        "explanation": (
            "Look for how long information is kept and when it is "
            "deleted."
        ),
    },
]


def split_sentences(text):
    """Split text into sentences using basic punctuation rules."""
    text = re.sub(r"\s+", " ", text.strip())

    if not text:
        return []

    return re.split(r"(?<=[.!?])\s+", text)


def find_topics(text):
    """Find policy topics mentioned in the supplied text."""
    lower_text = text.lower()
    topics = []

    for topic, keywords in TOPIC_KEYWORDS.items():
        if any(keyword in lower_text for keyword in keywords):
            topics.append(topic)

    return topics


def detect_risks(text):
    """Return clauses that match review rules, with explanations."""
    findings = []
    seen = set()

    for sentence in split_sentences(text):
        for rule in RISK_RULES:
            matched = any(
                re.search(pattern, sentence, re.IGNORECASE)
                for pattern in rule["patterns"]
            )

            key = (rule["category"], sentence.casefold())

            if matched and key not in seen:
                seen.add(key)
                findings.append({
                    "category": rule["category"],
                    "clause": sentence,
                    "level": "Review",
                    "explanation": rule["explanation"],
                })

    return findings


def summarize_terms(text, max_sentences=5):
    """Create an extractive summary and identify topics and review flags."""
    if not text or not text.strip():
        return {
            "summary": [],
            "topics": [],
            "risks": [],
            "message": "No text was provided.",
        }

    if max_sentences < 1:
        max_sentences = 1

    sentences = split_sentences(text)

    # Remove exact duplicate sentences while preserving original order.
    unique_sentences = []
    seen_sentences = set()

    for sentence in sentences:
        key = sentence.casefold().strip()

        if key and key not in seen_sentences:
            seen_sentences.add(key)
            unique_sentences.append(sentence)

    # Common words are less useful for ranking than meaningful terms.
    stop_words = {
        "the", "and", "for", "that", "this", "with", "you", "your",
        "are", "was", "will", "may", "can", "not", "our", "their",
        "from", "have", "has", "shall", "into", "any", "all", "who",
        "what", "when", "where", "which", "its", "they", "them",
        "then", "than", "but", "use", "used", "using", "under"
    }

    words = re.findall(r"\b[a-z]{3,}\b", text.lower())
    word_counts = Counter(word for word in words if word not in stop_words)

    scored = []

    for index, sentence in enumerate(unique_sentences):
        lower_sentence = sentence.lower()
        sentence_words = re.findall(r"\b[a-z]{3,}\b", lower_sentence)

        score = sum(
            min(word_counts[word], 3)
            for word in sentence_words
            if word not in stop_words
        )

        # Give introductory sentences a modest preference.
        if index < 2:
            score += 2

        # Prioritize sentences discussing policy topics.
        for keywords in TOPIC_KEYWORDS.values():
            if any(keyword in lower_sentence for keyword in keywords):
                score += 3

        # Prefer informative sentences over very short ones.
        if len(sentence.split()) >= 8:
            score += 1

        scored.append((score, index, sentence))

    chosen = sorted(
        scored, key=lambda item: item[0], reverse=True
    )[:max_sentences]

    # Display selected sentences in their original order.
    chosen.sort(key=lambda item: item[1])

    return {
        "summary": [item[2] for item in chosen],
        "topics": find_topics(text),
        "risks": detect_risks(text),
        "message": "Analysis prepared.",
    }


def load_txt_file(file_path):
    """Read a local text file, with a basic size limit."""
    path = Path(file_path).expanduser()

    if path.suffix.lower() != ".txt":
        raise ValueError("Only .txt files are supported.")

    if not path.is_file():
        raise FileNotFoundError("That file was not found.")

    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("File is too large. Maximum size is 2 MB.")

    return path.read_text(encoding="utf-8")


def display_results(result):
    """Display the summary, detected topics, and review flags."""
    print("\n=== SUMMARY ===")

    if not result["summary"]:
        print(result["message"])
        return

    for sentence in result["summary"]:
        print(f"- {sentence}")

    print("\n=== TOPICS FOUND ===")

    if result["topics"]:
        for topic in result["topics"]:
            print(f"- {topic}")
    else:
        print("No recognised topics found.")

    print("\n=== CLAUSES TO REVIEW ===")

    if result["risks"]:
        for number, risk in enumerate(result["risks"], start=1):
            print(f"\n{number}. {risk['category']} [{risk['level']}]")
            print(f"   Clause: {risk['clause']}")
            print(f"   Why review it: {risk['explanation']}")
    else:
        print("No clauses matched the current review rules.")

    print("\nNote: This is a basic offline screening tool, not legal advice.")
    print("A flag is not proof of wrongdoing; read the full original clause.")
    print("No flag does not guarantee that a policy is safe.")


def run_terms_summarizer():
    """Run the summarizer from the Eyes of Truth terminal menu."""
    print("\n=== EYES OF TRUTH: TERMS SUMMARIZER v2 ===")
    print("1. Paste policy text")
    print("2. Read a local .txt file")
    print("3. Return to the main menu")

    choice = input("Choose an option: ").strip()

    if choice == "3":
        print("Returning to the menu.")
        return

    if choice == "1":
        print("\nPaste the terms or policy text below.")
        print("Enter END on its own line when finished.")
        print("Enter BACK on its own line to cancel.")

        lines = []

        while True:
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                print("\nReturning to the menu.")
                return

            if line.strip().upper() == "BACK":
                print("Returning to the menu.")
                return

            if line.strip().upper() == "END":
                break

            lines.append(line)

        text = "\n".join(lines)

    elif choice == "2":
        file_path = input("Enter the path to your .txt file: ").strip()

        try:
            text = load_txt_file(file_path)
        except (OSError, UnicodeError, ValueError) as error:
            print(f"Could not read file: {error}")
            return

    else:
        print("Invalid choice. Returning to the menu.")
        return

    try:
        result = summarize_terms(text)
        display_results(result)
    except (ValueError, TypeError) as error:
        print(f"Could not analyse the text: {error}")
