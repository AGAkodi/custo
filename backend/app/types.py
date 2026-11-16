from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class SecurityEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    event_type: Literal["login_failed", "login_succeeded"]
    source_ip: str
    account_id: str = Field(min_length=1, max_length=128)
    user_agent: str = Field(max_length=256)
    result: Literal["failure", "success"]
    scenario_id: str = Field(min_length=1, max_length=128)

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value))

    @model_validator(mode="after")
    def result_matches_type(self):
        if (self.event_type == "login_failed") != (self.result == "failure"):
            raise ValueError("event_type and result disagree")
        return self


class Features(BaseModel):
    total_events: int
    failures: int
    max_failures_per_ip: int
    distinct_accounts: int
    distinct_ips: int
    max_accounts_per_ip: int
    max_ips_per_account: int
    success_after_failures: bool
    window_seconds: int


class Assessment(BaseModel):
    decision_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scenario_id: str
    classification: Literal["benign", "single_source_brute_force", "distributed_credential_stuffing", "password_spray", "suspicious_login"]
    confidence: float = Field(ge=0, le=1)
    action: Literal["allow", "monitor", "flag", "escalate"]
    matched_rules: list[str]
    evidence_event_ids: list[str]
    features: Features
    memory_context: str
    memory_influences: list[str] = Field(default_factory=list)
    memory_retrieval: dict = Field(default_factory=dict)
    explanation: str
