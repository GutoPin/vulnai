# -*- coding: utf-8 -*-
"""Endpoints de escaneo: lanzamiento async del pipeline + reporte de progreso."""

import os
import subprocess
import sys

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app import config
from app.infrastructure import progress, storage

router = APIRouter(tags=["scan"])


@router.post("/scan")
def run_scan():
    """Lanza el scanner como subproceso no bloqueante. Devuelve inmediatamente."""
    inventario = storage.ruta_inventario_actual()
    if not inventario:
        raise HTTPException(
            status_code=400,
            detail="Primero debes subir un inventario (POST /api/upload-inventario).",
        )

    progress.limpiar_progreso()

    # Popen no bloqueante: el scanner corre en segundo plano y reporta vía progress.json.
    # cwd=BASE_DIR para que `python -m app...` resuelva el paquete sin importar
    # desde dónde se lanzó el server.
    env = os.environ.copy()
    env["INVENTARIO_PATH"] = str(inventario)
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.pipeline.scanner"],
        env=env,
        cwd=config.BASE_DIR,
    )
    return {"started": True, "pid": proc.pid, "inventario": str(inventario)}


@router.get("/scan-progress")
def scan_progress():
    """Devuelve el estado actual del pipeline (leído de progress.json)."""
    try:
        return progress.leer_progreso()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
