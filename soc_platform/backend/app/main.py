from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.init_db import init_db

settings = get_settings()

configure_logging()

app = FastAPI(
    title=settings.app_name,
    debug=settings.app_debug,
    version="0.1.0",
)


@app.on_event("startup")
def on_startup():
    if settings.app_env == "dev":
        init_db()


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": settings.app_name,
        "env": settings.app_env,
    }


app.include_router(api_router, prefix=settings.api_v1_prefix)