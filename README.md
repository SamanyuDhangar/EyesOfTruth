# Eyes of Truth

**A Python-based cybersecurity tool for email phishing analysis, suspicious URL checks, domain intelligence, and terms-of-service summarization.**

Eyes of Truth is an educational project designed to help users investigate suspicious emails and links and review lengthy policy documents through a simple terminal interface.

## Features

### 1. Email Phishing Scanner
Analyze pasted email content or a saved `.eml` email file for suspicious patterns and potential phishing indicators.

### 2. Link Analyzer
Examine URLs using local heuristic checks and, when configured, an optional URLhaus threat-intelligence lookup.

### 3. Terms Summarizer
Summarize text from terms of service and privacy policies, identify relevant topics, and flag clauses that may deserve closer review.

### 4. Domain Intelligence
Review available domain-registration information and possible brand-name similarities.

## Requirements

- Python 3.10 or newer
- Git, if installing by cloning the repository
- Internet connection for optional online lookups
- API keys only for online providers that require them

## Installation

### Option A: Kali Linux or Ubuntu

**Step 1 — Install system prerequisites**

Open a terminal and run:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

**Step 2 — Download the project**

```bash
git clone https://github.com/SamanyuDhangar/EyesOfTruth.git
cd EyesOfTruth
```

**Step 3 — Create a virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

When activated, your terminal should display `(.venv)` or a similar environment indicator.

**Step 4 — Install Python dependencies**

```bash
python -m pip install -r requirements.txt
```

Wait for the installation to finish before continuing.

### Option B: Windows

Install Python 3.10 or newer and Git first.

Open PowerShell and run:

```powershell
git clone https://github.com/SamanyuDhangar/EyesOfTruth.git
cd EyesOfTruth
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks environment activation, use Command Prompt and activate with:

```bat
.venv\Scripts\activate.bat
```

Then continue to the configuration section.

## Configuration

### Optional API keys

Some online intelligence providers may require API keys.

Copy the example configuration file:

**Kali Linux / Ubuntu:**

```bash
cp .env.example .env
nano .env
```

**Windows PowerShell:**

```powershell
Copy-Item .env.example .env
notepad .env
```

Add the relevant API keys only if you intend to use their associated providers:

- `URLHAUS_AUTH_KEY`
- `PHISHTANK_API_KEY`
- `GOOGLE_SAFE_BROWSING_API_KEY`

Use the exact variable names already provided in `.env.example`. Follow each provider's current instructions for obtaining and using a key. Leave unused settings blank if supported by the provider implementation.

Save the file and close the editor.

**Security warning:** Never commit `.env`, API keys, passwords, or private email content to GitHub. The repository's `.gitignore` is intended to exclude sensitive local files.

## Running Eyes of Truth

Activate your virtual environment if it is not already active.

On Kali Linux or Ubuntu:

```bash
cd EyesOfTruth
source .venv/bin/activate
python main.py
```

On Windows, activate the environment using the appropriate command above, then run:

```powershell
python main.py
```

Follow the numbered menu displayed in the terminal:

1. **Email Phishing Scanner** — inspect email content or an email file.
2. **Link Analyzer** — examine a URL using available local checks and optional online intelligence.
3. **Terms Summarizer** — summarize policy text and review flagged clauses.
4. **Exit** — close the program.

Follow any additional prompts shown by the selected feature.

## Running the tests

From the project directory, with your virtual environment activated, run:

```bash
python -m unittest discover -s tests -v
```

The test suite currently includes URL-scanner checks. A successful run ends with `OK`.

You can also check Python syntax with:

```bash
python -m py_compile main.py core/*.py providers/*.py
```

No output usually means the syntax check succeeded.

## Troubleshooting

- **`ModuleNotFoundError`:** Activate `.venv` and run `python -m pip install -r requirements.txt` again.
- **Virtual environment creation fails:** On Debian-based Linux, install `python3-venv` using `apt`.
- **Online lookup fails:** Check your internet connection, provider requirements, API-key configuration, and any rate limits.
- **Command not found:** Confirm that Python and Git are installed and available in your terminal.
- **Permission or package-installation errors:** Install dependencies inside the virtual environment rather than modifying system Python packages.

## Limitations

Eyes of Truth is an educational security-screening tool, not a guarantee of safety.

- Heuristic scores are estimates, not statistically validated probabilities.
- A low risk score or absence of a threat-intelligence match does not prove that a URL or email is safe.
- Domain information may be incomplete or unavailable.
- The Terms Summarizer uses rule-based processing and sentence selection; it is not a semantic AI model or a substitute for legal advice.
- Online providers may be unavailable, impose rate limits, or change their requirements.
- Review findings independently before making security decisions.

## Privacy and responsible use

Use Eyes of Truth only for lawful, authorized defensive analysis.

Local analysis functions process their input on your device. Optional online lookups may transmit queried URLs or domain names to external providers. Review the relevant provider's privacy policy and the project's implementation before submitting sensitive information.

Do not open suspicious links merely to test them, and never enter passwords or confidential information into untrusted websites.

## Contributing

Bug reports, reproducible test cases, documentation improvements, and defensive security enhancements are welcome.

## License

No license has been selected yet. Until a license is added, do not assume that others have permission to redistribute or modify this project.
