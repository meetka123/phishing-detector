from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import os

app = FastAPI()

# Serve static files (CSS/JS/images if any)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Root -> show index.html
@app.get("/", response_class=HTMLResponse)
async def read_index():
    return FileResponse("index.html")


# API endpoint for checking phishing
from pydantic import BaseModel

class URLItem(BaseModel):
    url: str

@app.post("/check")
async def check_url(item: URLItem):
    url = item.url.lower()
    # Dummy rules for now
    if "login" in url or "verify" in url or "bank" in url:
        return {"result": "🚨 Danger! This looks like a phishing site."}
    elif "google" in url or "youtube" in url or "github" in url:
        return {"result": "✅ Safe site."}
    else:
        return {"result": "⚠️ Suspicious, proceed with caution."}


