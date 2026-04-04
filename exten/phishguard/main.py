from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

try:
    from .config import configure_logging, get_client_ip_from_request, get_settings
    from .models.database import init_db
    from .routers import history, scan, stats
    from .services.yara_engine import initialize_yara_rules
except ImportError:  # pragma: no cover - supports running from project root or package root
    from config import configure_logging, get_client_ip_from_request, get_settings
    from models.database import init_db
    from routers import history, scan, stats
    from services.yara_engine import initialize_yara_rules


settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_client_ip_from_request, default_limits=[settings.rate_limit_per_minute])


async def verify_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    if not x_api_key or x_api_key != settings.api_secret_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    await initialize_yara_rules()
    logger.info("application_startup_complete", extra={"app": settings.app_name})
    yield


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def enforce_json_content_type(request: Request, call_next):
    if request.url.path.startswith(settings.api_v1_prefix) and request.method in {"POST", "PUT", "PATCH"}:
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return JSONResponse(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                content={"detail": "Content-Type must be application/json"},
            )
    response = await call_next(request)
    return response


@app.get("/", tags=["system"])
async def root() -> dict[str, str]:
    return {"message": f"{settings.app_name} is running"}


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(
    scan.router,
    prefix=settings.api_v1_prefix,
    dependencies=[Depends(verify_api_key)],
)
app.include_router(
    history.router,
    prefix=settings.api_v1_prefix,
    dependencies=[Depends(verify_api_key)],
)
app.include_router(
    stats.router,
    prefix=settings.api_v1_prefix,
    dependencies=[Depends(verify_api_key)],
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
