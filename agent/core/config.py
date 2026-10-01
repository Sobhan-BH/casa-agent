"""Central configuration (12-factor style, env-driven, .env supported)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CASA_", env_file=".env", extra="ignore")

    env: str = "development"
    database_url: str = "sqlite+aiosqlite:///./casa.db"
    redis_url: str = "redis://localhost:6379/0"

    # LLM layer (provider-agnostic)
    llm_provider: str = "heuristic"
    llm_model: str = ""
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_timeout_seconds: float = 45.0
    llm_max_output_tokens: int = 2000

    # HTTP API
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Safety / engine limits
    log_level: str = "INFO"
    audit_log_path: Path = Path("./data/audit.log")
    require_signed_authorizations: bool = False
    signing_key_path: Path = Path("./data/signing_key.pem")
    job_max_steps: int = 40
    job_step_timeout_seconds: float = 120.0
    job_total_timeout_seconds: float = 900.0
    job_module_retries: int = 1
    http_max_concurrency: int = 4
    http_timeout_seconds: float = 10.0  # per-request; real-internet targets benefit from 25-30s
    http_max_bytes: int = 2_000_000
    user_agent: str = "CASA-Agent/0.1 (+authorized-security-assessment)"

    # Queue (simple in-process queue for the MVP; Celery/Redis is an extension point)
    queue_backend: str = "inline"
    worker_poll_interval_seconds: float = 1.0

    lab_base_url: str = "http://127.0.0.1:8001"

    # OSV.dev CVE enrichment
    osv_enabled: bool = True
    osv_max_technologies: int = 12

    # External security tools (Tool Integration layer)
    tools_enabled: bool = True
    tools_allowed: str = ""  # comma-separated allowlist; empty = all known tools
    tool_timeout_seconds: float = 300.0
    tool_max_concurrency: int = 2
    tool_rate_limit: float = 50.0        # max requests/second to the target
    tool_max_requests: int = 5000        # hard cap per tool invocation
    tool_max_runtime_seconds: float = 900.0  # global tool-phase budget

    # Nuclei policy
    nuclei_allowed_tags: str = "cve,idor,misconfig,exposure,tech,token,cookie,redirect,default-login"
    nuclei_excluded_tags: str = "fuzz,pdo,bruteforce,destructive"
    nuclei_severity_filter: str = "info,low,medium,high,critical"
    nuclei_rate_limit: int = 50
    nuclei_max_concurrency: int = 5

    # Pipeline toggles (kept on Settings so env can override; FeatureFlags
    # in agent.core.features documents the full flag surface incl. extension points)
    ai_analysis_enabled: bool = True

    # API security
    api_key: str = ""                  # empty = auth disabled (lab posture)
    rate_limit_rpm: int = 0            # 0 = rate limiting disabled

    # Webhook notifications (Slack/Discord/generic)
    webhook_url: str = ""
    webhook_format: str = "generic"    # generic | slack | discord
    webhook_events: str = "JOB_COMPLETED,JOB_FAILED,JOB_BLOCKED"

    # Continuous monitoring (0 disables the scheduler)
    reassess_interval_hours: float = 0.0

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def data_dir(self) -> Path:
        d = self.audit_log_path.parent
        d.mkdir(parents=True, exist_ok=True)
        return d


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
