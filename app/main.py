from fastapi import FastAPI

from app.core.config import get_settings
from app.core.database import init_db
from app.core.logging import configure_logging
from app.core.rate_limit import RateLimitMiddleware
from app.routes import explain, gmail, health, logs, scan


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.debug)
    init_db()

    application = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="Backend for CyberShield AI phishing and risk analysis.",
    )

    application.add_middleware(
        RateLimitMiddleware,
        requests_limit=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )

    application.include_router(health.router)
    application.include_router(scan.router)
    application.include_router(explain.router)
    application.include_router(gmail.router)
    application.include_router(logs.router)
    return application


app = create_app()
