# -*- coding: utf-8 -*-
"""Router agregado de la API."""

from fastapi import APIRouter

from app.api import inventory, results, scan

api_router = APIRouter(prefix="/api")
api_router.include_router(inventory.router)
api_router.include_router(scan.router)
api_router.include_router(results.router)
