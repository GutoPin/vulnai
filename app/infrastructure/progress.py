# -*- coding: utf-8 -*-
"""Reporte de progreso del pipeline, consumido por el frontend vía /api/scan-progress."""

import json
from datetime import datetime, timezone

from app import config

PROGRESO_INICIAL = {
    "stage_idx": 0,
    "total": config.TOTAL_ETAPAS,
    "label": "Sin escaneo en curso",
    "detail": "",
    "finished": False,
    "error": None,
}


def actualizar_progreso(stage_idx: int, label: str, detail: str = "",
                        finished: bool = False, error: str | None = None):
    """Escribe el estado actual del pipeline a progress.json.

    El frontend hace polling de este archivo para mostrar el timeline en vivo.
    """
    payload = {
        "stage_idx": stage_idx,
        "total": config.TOTAL_ETAPAS,
        "label": label,
        "detail": detail,
        "finished": finished,
        "error": error,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    try:
        config.ensure_dirs()
        with open(config.PROGRESS_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
    except Exception as e:
        # No queremos que un fallo de IO en el progreso tumbe el escaneo.
        print(f"WARN: no se pudo escribir progress.json: {e}")


def leer_progreso() -> dict:
    """Lee progress.json; si no existe devuelve el estado inicial."""
    if not config.PROGRESS_PATH.exists():
        return dict(PROGRESO_INICIAL)
    with open(config.PROGRESS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def limpiar_progreso() -> None:
    """Borra el progress.json viejo para que el frontend no lea estado obsoleto."""
    try:
        config.PROGRESS_PATH.unlink(missing_ok=True)
    except OSError:
        pass
