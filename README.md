# 👁️ EyesOfTruth

**EyesOfTruth** is a beginner-friendly cybersecurity tool designed to help users identify potential phishing threats, analyze suspicious URLs, and understand complex terms and conditions through simplified summaries.

Built with Python, this project combines practical security checks with accessible, terminal-based workflows to make cybersecurity analysis easier to understand and use.

### ✨ What It Does

- **Email Phishing Scanner:** Examines email content for suspicious indicators that may suggest phishing.
- **URL Analyzer:** Checks URLs for potential warning signs and supports threat-intelligence lookups where configured.
- **Terms Summarizer:** Simplifies lengthy terms and conditions to help users identify important clauses and potential concerns.

### 🎯 Project Goal

The goal of EyesOfTruth is to make basic cybersecurity analysis more accessible while providing a practical learning project for exploring Python, security automation, and threat detection.

### ⚠️ Disclaimer

EyesOfTruth is an educational security tool, not a guarantee of safety. Its findings may be incomplete or inaccurate. Always verify important results independently and use it only for lawful, authorized purposes.

---

## Installation and Setup

EyesOfTruth runs locally using Python. Follow the instructions for your operating system.

### Requirements

- Python 3.10 or newer
- Git
- An internet connection for optional online threat-intelligence lookups
- API keys only for providers you choose to configure

### 1. Kali Linux / Debian / Ubuntu

**Step 1 — Open Terminal**

**Step 2 — Install the required packages**

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

**Step 3 — Download EyesOfTruth**

```bash
git clone https://github.com/SamanyuDhangar/EyesOfTruth.git
cd EyesOfTruth
```

**Step 4 — Create a virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Step 5 — Install dependencies**

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Step 6 — Start EyesOfTruth**

```bash
python main.py
```

### 2. Windows — PowerShell

**Step 1 — Install prerequisites**

Install Python 3.10 or newer and Git for Windows. During Python installation, enable the option to add Python to PATH if available.

Open PowerShell and verify the installations:

```powershell
py --version
git --version
```

**Step 2 — Download the project**

```powershell
git clone https://github.com/SamanyuDhangar/EyesOfTruth.git
cd EyesOfTruth
```

**Step 3 — Create a virtual environment**

```powershell
py -m venv .venv
```

**Step 4 — Install dependencies**

These commands use the virtual environment directly, so activating it is not required.

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**Step 5 — Start EyesOfTruth**

```powershell
.\.venv\Scripts\python.exe main.py
```

**Optional — Activate the environment**

If you prefer to activate it first:

```powershell
.\.venv\Scripts\Activate.ps1
python main.py
```

If PowerShell blocks script activation, use the direct Python commands above instead. Alternatively, use Command Prompt as described below.

### 3. Windows — Command Prompt (CMD)

**Step 1 — Open Command Prompt**

Verify Python and Git:

```bat
py --version
git --version
```

**Step 2 — Download the project**

```bat
git clone https://github.com/SamanyuDhangar/EyesOfTruth.git
cd EyesOfTruth
```

**Step 3 — Create a virtual environment**

```bat
py -m venv .venv
```

**Step 4 — Install dependencies**

```bat
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**Step 5 — Start EyesOfTruth**

```bat
.venv\Scripts\python.exe main.py
```

### 4. macOS

**Step 1 — Install prerequisites**

Install Python 3.10 or newer and Git. You can obtain Python from [python.org](https://www.python.org/downloads/macos/). If Git is not installed, macOS may offer to install its command-line developer tools when you run `git`.

Open Terminal and verify:

```bash
python3 --version
git --version
```

**Step 2 — Download the project**

```bash
git clone https://github.com/SamanyuDhangar/EyesOfTruth.git
cd EyesOfTruth
```

**Step 3 — Create and activate a virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Step 4 — Install dependencies**

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Step 5 — Start EyesOfTruth**

```bash
python main.py
```

## How to Use EyesOfTruth

After installation, run the appropriate startup command for your operating system. The application opens an interactive menu in the terminal.

### Feature 1 — Email Phishing Scanner

1. Select the email phishing scanner from the displayed menu.
2. Follow the on-screen prompts to provide email content or the path to a saved `.eml` file.
3. Review the suspicious indicators and analysis returned by the tool.
4. Use the findings as a starting point for further investigation.

**Safety tip:** Use sample emails or authorized test messages. Do not share confidential email contents or credentials.

### Feature 2 — Link Analyzer

1. Select the link analyzer from the menu.
2. Enter the URL when prompted.
3. Review the local heuristic checks and any available online threat-intelligence results.
4. Treat the result as an initial assessment, not a guarantee that the URL is safe.

Do not open a suspicious URL simply to test it.

### Feature 3 — Terms Summarizer

1. Select the terms summarizer from the menu.
2. Follow the prompts to provide the policy or terms text.
3. Review the summary, identified topics, and clauses flagged for closer inspection.

The summarizer uses rule-based processing. It does not replace legal advice or a complete review of the original document.

### Exit the application

Choose the exit option shown in the menu. If you need to stop the application immediately, press `Ctrl+C` in the terminal.

## Configuration — Optional API Keys

Some online threat-intelligence providers may require API keys. Local analysis features may work without them, depending on the provider configuration.

### Kali Linux / Ubuntu / macOS

From the project directory:

```bash
cp .env.example .env
nano .env
```

Save your changes in Nano with `Ctrl+O`, press Enter, and exit with `Ctrl+X`.

### Windows PowerShell

```powershell
Copy-Item .env.example .env
notepad .env
```

### Windows Command Prompt

```bat
copy .env.example .env
notepad .env
```

Use the exact environment variable names provided in `.env.example`. Configure only the providers you intend to use.

**Never upload your `.env` file, API keys, passwords, or private email content to GitHub.** Keep credentials private.

## Running EyesOfTruth Again

You do not need to clone the repository or reinstall dependencies every time.

### Kali Linux / Ubuntu / macOS

```bash
cd EyesOfTruth
source .venv/bin/activate
python main.py
```

### Windows PowerShell

```powershell
cd EyesOfTruth
.\.venv\Scripts\python.exe main.py
```

### Windows Command Prompt

```bat
cd EyesOfTruth
.venv\Scripts\python.exe main.py
```

If you open a new terminal, make sure you navigate to the project directory first. If your project is stored elsewhere, use its actual directory path.

## Running Tests

Run these commands from the project directory.

### Kali Linux / Ubuntu / macOS

```bash
python -m unittest discover -s tests -v
```

If the virtual environment is not active, activate it first:

```bash
source .venv/bin/activate
```

### Windows PowerShell

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Windows Command Prompt

```bat
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

A successful test run normally ends with `OK`. If a test fails, read the error output to identify the issue.

## Troubleshooting

- **`git` is not recognized:** Install Git and reopen your terminal.
- **`python` or `python3` is not found:** Install Python 3.10 or newer and check that it is available in your terminal.
- **`No module named ...`:** Install the dependencies inside the project's virtual environment using the commands above.
- **PowerShell blocks activation:** Use the direct `.venv\Scripts\python.exe` commands instead.
- **`python3-venv` is missing on Linux:** Run `sudo apt install python3-venv`.
- **Online lookups fail:** Check your connection, API-key configuration, provider availability, and rate limits.
- **The application cannot find a file:** Check the path you entered and ensure the file exists.
- **A command fails:** Confirm that you are in the `EyesOfTruth` project directory and that the installation completed successfully.

## Limitations

EyesOfTruth is an educational cybersecurity project.

- Risk scores are estimates, not statistically validated probabilities.
- A low-risk result does not prove an email or URL is safe.
- Domain intelligence may be incomplete or unavailable.
- The terms summarizer uses rule-based processing and is not a substitute for legal advice.
- External providers may impose rate limits or change their requirements.

Use the tool for lawful, authorized defensive analysis. Review important findings independently.
