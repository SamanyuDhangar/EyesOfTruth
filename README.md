# Eyes of Truth

A Python-based cybersecurity tool for beginner-friendly security analysis.

## Features

- Email Phishing Scanner
- Link Analyzer with optional URLhaus lookup
- Terms Summarizer
- Domain Intelligence

## Installation on Kali Linux

Clone the repository:

    git clone https://github.com/SamanyuDhangar/EyesOfTruth.git
    cd EyesOfTruth

Create and activate a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    python -m pip install -r requirements.txt

Run the tool:

    python main.py

## Safety and limitations

This educational tool uses heuristic checks. Its results cannot guarantee
that an email or URL is safe. The Terms Summarizer is not legal advice.

Never publish API keys, passwords, or private emails. Optional online
lookups may send queried URLs or domains to external providers.

## License

No license has been selected yet.
