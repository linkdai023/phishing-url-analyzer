from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
app = FastAPI()

@app.get("/")
def home():
    return {"message": "Phishing URL Risk Analyzer"}

class UrlRequest(BaseModel):
    url: HttpUrl
@app.post("/analyze")
def analyze_url(request: UrlRequest):
    signals = []
    if request.url.scheme == "http":
        signals.append("The submitted URL uses HTTP: the connection may be unencrypted.")

    return {"submitted_url": str(request.url), "risk_signals": signals,}