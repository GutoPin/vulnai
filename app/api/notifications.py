# -*- coding: utf-8 -*-
"""Endpoints de configuración de notificaciones (destinatarios del reporte).

La lista se persiste en data/config_notificaciones.json. Es la única fuente
de verdad: el dashboard la edita y el workflow de n8n la consulta antes de
enviar el correo (tanto en scans manuales como en el cron semanal).
"""

import json
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app import config

router = APIRouter(tags=["notificaciones"])

# Validación pragmática de email (no RFC completo): algo@dominio.tld
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MAX_DESTINATARIOS = 20


class ConfigNotificaciones(BaseModel):
    destinatarios: list[str]


def _leer_config() -> dict:
    """Lee la config persistida; si no existe o está corrupta, devuelve defaults."""
    if not config.CONFIG_NOTIFICACIONES_PATH.exists():
        return {"destinatarios": list(config.DESTINATARIOS_DEFAULT), "custom": False}
    try:
        with open(config.CONFIG_NOTIFICACIONES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        destinatarios = data.get("destinatarios") or []
        if not destinatarios:
            return {"destinatarios": list(config.DESTINATARIOS_DEFAULT), "custom": False}
        return {"destinatarios": destinatarios, "custom": True}
    except (OSError, json.JSONDecodeError):
        return {"destinatarios": list(config.DESTINATARIOS_DEFAULT), "custom": False}


@router.get("/config-notificaciones")
def get_config_notificaciones():
    """Devuelve la lista de destinatarios vigente (custom o default)."""
    return _leer_config()


@router.post("/config-notificaciones")
def set_config_notificaciones(body: ConfigNotificaciones):
    """Guarda la lista de destinatarios. Lista vacía = volver a los defaults."""
    limpios = []
    for correo in body.destinatarios:
        correo = correo.strip().lower()
        if not correo:
            continue
        if not _EMAIL_RE.match(correo):
            raise HTTPException(status_code=400, detail=f"Correo inválido: {correo!r}")
        if correo not in limpios:
            limpios.append(correo)

    if len(limpios) > MAX_DESTINATARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Máximo {MAX_DESTINATARIOS} destinatarios (recibidos: {len(limpios)}).",
        )

    config.ensure_dirs()
    if not limpios:
        # Sin destinatarios custom: borramos el archivo para volver al default.
        config.CONFIG_NOTIFICACIONES_PATH.unlink(missing_ok=True)
        return {"ok": True, "destinatarios": list(config.DESTINATARIOS_DEFAULT), "custom": False}

    with open(config.CONFIG_NOTIFICACIONES_PATH, "w", encoding="utf-8") as f:
        json.dump({"destinatarios": limpios}, f, ensure_ascii=False, indent=2)
    return {"ok": True, "destinatarios": limpios, "custom": True}
