"""Serve the demo and API behind a shared password on hosted deployments."""
import base64
import binascii
import os
from pathlib import Path
from secrets import compare_digest

from fastapi import Request
from fastapi.responses import FileResponse, PlainTextResponse
from starlette.staticfiles import StaticFiles

from app.main import app

WEB_ROOT = Path(os.environ.get("CUSTOS_WEB_ROOT", "/app/web")).resolve()
USERNAME = os.environ.get("DEMO_USERNAME", "")
PASSWORD = os.environ.get("DEMO_PASSWORD", "")
if not USERNAME or not PASSWORD or ":" in USERNAME:
    raise RuntimeError("Set DEMO_USERNAME and DEMO_PASSWORD before starting the hosted demo")


@app.middleware("http")
async def protect_demo(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    scheme, _, encoded = request.headers.get("authorization", "").partition(" ")
    try:
        credentials = base64.b64decode(encoded, validate=True).decode("utf-8")
        username, separator, password = credentials.partition(":")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        username, separator, password = "", "", ""
    valid = (scheme.lower() == "basic" and separator and
             compare_digest(username.encode(), USERNAME.encode()) and
             compare_digest(password.encode(), PASSWORD.encode()))
    if not valid:
        return PlainTextResponse("Authentication required", status_code=401,
                                 headers={"WWW-Authenticate": 'Basic realm="Custos demo"'})
    return await call_next(request)


app.mount("/assets", StaticFiles(directory=WEB_ROOT / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
async def frontend(path: str):
    candidate = (WEB_ROOT / path).resolve()
    if candidate.is_relative_to(WEB_ROOT) and candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(WEB_ROOT / "index.html")
