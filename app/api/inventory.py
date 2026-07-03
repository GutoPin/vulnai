# -*- coding: utf-8 -*-
"""Endpoints de inventario: upload + validación + estado actual."""

import os

from fastapi import APIRouter, File, HTTPException, UploadFile

from app import config
from app.domain.inventory import cargar_activos_desde_inventario
from app.infrastructure import storage

router = APIRouter(tags=["inventario"])


@router.post("/upload-inventario")
async def upload_inventario(file: UploadFile = File(...)):
    """Recibe el archivo de inventario (.xlsx/.xls/.csv), lo guarda en uploads/
    y valida que tenga las columnas esperadas leyendo los activos."""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in config.EXTENSIONES_VALIDAS:
        raise HTTPException(
            status_code=400,
            detail=f"Extensión {ext!r} no soportada. Usa: {', '.join(sorted(config.EXTENSIONES_VALIDAS))}",
        )

    dst = storage.guardar_inventario(file.file, ext)

    try:
        activos = cargar_activos_desde_inventario(str(dst))
    except Exception as e:
        # El archivo se guardó, pero no es válido: lo borramos para no tener basura.
        storage.borrar_inventario(dst)
        raise HTTPException(status_code=400, detail=str(e))

    if not activos:
        storage.borrar_inventario(dst)
        raise HTTPException(
            status_code=400,
            detail="El archivo no contiene activos válidos (todos descartados por filtros).",
        )

    ejemplos = [a["name"] or a["nombre"] for a in activos[:3]]
    return {
        "ok": True,
        "filename": file.filename,
        "saved_as": str(dst),
        "n_activos": len(activos),
        "ejemplos": ejemplos,
    }


@router.get("/inventario-actual")
def inventario_actual():
    """Devuelve metadatos del inventario subido (si existe), para hidratar la UI tras un reload."""
    path = storage.ruta_inventario_actual()
    if not path:
        return {"ok": False}
    try:
        activos = cargar_activos_desde_inventario(str(path))
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {
        "ok": True,
        "saved_as": str(path),
        "n_activos": len(activos),
        "ejemplos": [a["name"] or a["nombre"] for a in activos[:3]],
    }
