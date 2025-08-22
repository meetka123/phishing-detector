from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import requests, os

app = FastAPI()

# ✅ CORS enable (frontend se call karne ke liye)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Google Safe Browsing API key (Render env var se read karega)
API_KEY = os.getenv("GOOGLE_API_KEY")
API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

class URLItem(BaseModel):
    url: str

@app.post("/check")
def check_url(item: URLItem):
    body = {
        "client": {"clientId": "meet-hacker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": item.url}],
        },
    }

    response = requests.post(API_URL, json=body)
    result = response.json()

    if "matches" in result:
        return {"result": "🚨 Danger"}
    else:
        return {"result": "✅ Safe"}

# ✅ Serve index.html from root
@app.get("/")
def home():
    return FileResponse("index.html")

