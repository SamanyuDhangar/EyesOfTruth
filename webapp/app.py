
from dotenv import load_dotenv
from providers.urlhaus import URLhausProvider
from pathlib import Path
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.email_scanner import analyze_email, analyze_eml
from core.url_scanner import scan_url
from core.terms_summarizer import summarize_terms

app = FastAPI(
    title="Eyes of Truth",
    description="Local cybersecurity analysis dashboard",
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
STATIC_DIR = BASE_DIR / "static"
ENV_FILE = PROJECT_DIR / ".env"

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


class EmailInput(BaseModel):
    sender: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1000)
    body: str = Field(default="", max_length=200000)
    html_body: str = Field(default="", max_length=200000)


class URLInput(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class TermsInput(BaseModel):
    text: str = Field(min_length=1, max_length=200000)
    max_sentences: int = Field(default=5, ge=1, le=15)


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {
        "status": "online",
        "application": "EyesOfTruth",
    }

@app.get("/api/settings/urlhaus")
def urlhaus_settings():
    provider = URLhausProvider()

    return {
        "provider": "URLhaus",
        "configured": bool(provider.auth_key),
    }




@app.post("/api/scan/email")
def scan_email(data: EmailInput):
    if not any(
        value.strip()
        for value in (data.sender, data.subject, data.body, data.html_body)
    ):
        raise HTTPException(
            status_code=400,
            detail="Enter email details before scanning.",
        )

    try:
        return analyze_email(
            sender=data.sender,
            subject=data.subject,
            body=data.body,
            html_body=data.html_body,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Email analysis failed. Check the local application logs.",
        )


@app.post("/api/scan/email-file")
async def scan_email_file(file: UploadFile = File(...)):
    if not file.filename or Path(file.filename).suffix.lower() != ".eml":
        raise HTTPException(
            status_code=400,
            detail="Upload an .eml email file.",
        )

    temp_path = None

    try:
        content = await file.read(10 * 1024 * 1024 + 1)

        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail="The email file exceeds the 10 MB limit.",
            )

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".eml",
            delete=False,
        ) as temp_file:
            temp_file.write(content)
            temp_path = Path(temp_file.name)

        return analyze_eml(str(temp_path))

    except HTTPException:
        raise
    except (ValueError, OSError) as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Email file analysis failed.",
        )
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        await file.close()



@app.post("/api/scan/url")
def scan_link(data: URLInput):
    # Run the existing local analysis first.
    result = scan_url(data.url)

    # Do not send invalid input to the online provider.
    if result.get("level") == "INVALID INPUT":
        result["urlhaus"] = {
            "available": False,
            "malicious": None,
            "message": "URLhaus was not queried because the URL is invalid.",
        }
        return result

    # URLhaus expects a URL with a scheme.
    url_to_check = data.url.strip()
    if "://" not in url_to_check:
        url_to_check = "https://" + url_to_check

    # Check online reputation using the locally configured key.
    try:
        provider = URLhausProvider()
        online_result = provider.check_url(url_to_check)
    except Exception:
        online_result = {
            "available": False,
            "malicious": None,
            "message": "URLhaus could not be checked.",
        }

    result["urlhaus"] = online_result
    result["checked_online"] = online_result.get("available", False)

    # A URLhaus match is a strong warning.
    if online_result.get("malicious") is True:
        result["score"] = max(result.get("score", 0), 80)
        result["level"] = "HIGH"
        result["findings"].append(
            "URLhaus reports a matching malicious URL."
        )

    elif online_result.get("available") and online_result.get("malicious") is False:
        result["observations"].append(
            "URLhaus found no matching record. This does not prove the URL is safe."
        )

    return result


@app.post("/api/scan/terms")
def scan_terms(data: TermsInput):
    return summarize_terms(
        data.text,
        max_sentences=data.max_sentences,
    )
