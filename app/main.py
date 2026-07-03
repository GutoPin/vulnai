# -*- coding: utf-8 -*-
"""Aplicación FastAPI: sirve el dashboard estático y monta la API."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import config
from app.api import api_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    config.ensure_dirs()
    yield


def create_app() -> FastAPI:
    application = FastAPI(title="VulnAI Dashboard", lifespan=lifespan)
    application.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
    application.include_router(api_router)

    @application.get("/")
    def read_root():
        return FileResponse(config.STATIC_DIR / "index.html")

    return application


app = create_app()
