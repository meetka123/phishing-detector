import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# CORS fix (frontend ko backend se connect hone dene ke liye)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Apna API key daalna (Google Safe Browsing ka)
API_KEY = "🔑 Yaha apna Google Safe Browsing API Key daal"
API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

class URLItem(BaseModel):
    url: str

@app.post("/check")
def check_url(item: URLItem):
    body = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": item.url}]
        }
    }

    response = requests.post(API_URL, json=body)
    result = response.json()

    if "matches" in result:
        return {"result": "🚨 Danger (Phishing/Malware detected)"}
    else:
        return {"result": "✅ Safe"}
