from functools import lru_cache
from pathlib import Path
import json
import os
import re
from pydantic_settings import BaseSettings, SettingsConfigDict

RUNTIME_DIR = Path(os.environ.get("CUSTOS_RUNTIME_DIR", str(Path(__file__).resolve().parent.parent / ".runtime"))).resolve()
SESSION_FILE = RUNTIME_DIR / "demo-session.json"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file="../.env", extra="ignore")
    app_env: str = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173"
    hydradb_uri: str = "bolt://127.0.0.1:7687"
    hydradb_username: str = "neo4j"
    hydradb_password: str = ""
    demo_seed: int = 42
    graph_namespace: str = "custos"
    reviewer_token: str = ""
    passwordless_demo_enabled: bool = False
    hosted_demo_reset_enabled: bool = False
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""

@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.app_env == "development" and SESSION_FILE.exists():
        data = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        namespace = data.get("namespace", "")
        if re.fullmatch(r"custos_demo_[0-9a-f]{32}", namespace):
            settings.graph_namespace = namespace
    return settings
