"""Read-only config view (names only, never values, except flags)."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from ..auth import require_role
from ..config import get_settings

router = APIRouter()


@router.get("")
async def read(_=Depends(require_role("admin"))):
    s = get_settings()
    # Expose non-secret knobs as-is; for anything that looks like a key,
    # only report presence, never the value.
    def present(name: str) -> bool:
        return bool(getattr(s, name, "") or "")
    public_flags = {
        "APP_ENV": s.APP_ENV, "LOG_LEVEL": s.LOG_LEVEL,
        "JWT_EXPIRE_MINUTES": s.JWT_EXPIRE_MINUTES,
        "MAX_CONCURRENT_COLLECTORS": s.MAX_CONCURRENT_COLLECTORS,
        "RATE_LIMIT_PER_MINUTE": s.RATE_LIMIT_PER_MINUTE,
        "HTTP_TIMEOUT_SECONDS": s.HTTP_TIMEOUT_SECONDS,
        "UPLOAD_DIR": s.UPLOAD_DIR,
        "DATABASE_URL_scheme": s.DATABASE_URL.split("://", 1)[0] if "://" in s.DATABASE_URL else "",
        "REDIS_URL_scheme": s.REDIS_URL.split("://", 1)[0] if "://" in s.REDIS_URL else "",
    }
    secret_presence = {
        name: present(name) for name in [
            "JWT_SECRET", "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
            "VIRUSTOTAL_API_KEY", "SECURITYTRAILS_API_KEY", "GREYNOISE_API_KEY",
            "ABUSEIPDB_API_KEY", "IPINFO_TOKEN", "URLSCAN_API_KEY", "HIBP_API_KEY",
            "OTX_API_KEY", "OPENCORPORATES_API_KEY", "INTELX_API_KEY",
            "TINEYE_API_KEY", "TINEYE_API_USER", "BING_VISUAL_API_KEY",
            "FOFA_API_KEY", "FOFA_API_EMAIL", "ZOOMEYE_API_KEY",
            "COMPANIESHOUSE_API_KEY", "GITHUB_TOKEN", "NUMVERIFY_API_KEY",
            "OPENCTI_URL", "OPENCTI_TOKEN", "EMAILREP_API_KEY", "WEBHOOK_URL",
            "ELASTICSEARCH_URL", "ELASTICSEARCH_API_KEY",
        ]
    }
    return {"flags": public_flags, "secrets_present": secret_presence}
