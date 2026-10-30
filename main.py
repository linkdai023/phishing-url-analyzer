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
    score = 0
    if request.url.scheme == "http":
        signals.append("The submitted URL uses HTTP: the connection may be unencrypted.")
        score += 15
    if request.url.username is not None:
        score += 40
        signals.append("This URL contains text before @; check the actual destination host.")
    return {"submitted_url": str(request.url), "risk_signals": signals,"destination_host": request.url.host, "risk_score": score,"score_note": "Rule points only; a score of 0 does not mean safe."}