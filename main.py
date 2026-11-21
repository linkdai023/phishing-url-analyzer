from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl

from analyzer import analyze

app = FastAPI()
BASE_DIR = Path(__file__).parent


class UrlRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def home():
    return FileResponse(BASE_DIR / "index.html")


@app.post("/analyze")
def analyze_url(request: UrlRequest):
    result = analyze(str(request.url))
    result["submitted_url"] = str(request.url)
    result["score_note"] = "Rule points only; a score of 0 does not mean safe."
    return result