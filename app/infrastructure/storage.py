# -*- coding: utf-8 -*-
"""Persistencia del inventario subido por el usuario (uploads/)."""

import shutil
from pathlib import Path

from app import config


def guardar_inventario(fileobj, ext: str) -> Path:
    """Guarda el archivo subido como uploads/inventario<ext>, eliminando
    cualquier inventario previo con otra extensión para evitar ambigüedad."""
    config.ensure_dirs()
    dst = config.UPLOADS_DIR / f"inventario{ext}"

    # En Windows el archivo puede estar bloqueado por otro proceso (Excel abierto,
    # scanner en curso, etc.); si falla, lo dejamos pasar — el nuevo upload sobrescribirá.
    for old_ext in config.EXTENSIONES_VALIDAS:
        old_path = config.UPLOADS_DIR / f"inventario{old_ext}"
        if old_path != dst and old_path.exists():
            try:
                old_path.unlink()
            except OSError as e:
                print(f"WARN: no se pudo borrar inventario previo {old_path}: {e}")

    with open(dst, "wb") as out:
        shutil.copyfileobj(fileobj, out)
    return dst


def borrar_inventario(path: Path) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


def ruta_inventario_actual() -> Path | None:
    """Devuelve la ruta del inventario subido más reciente, o None si no hay."""
    if not config.UPLOADS_DIR.is_dir():
        return None
    for ext in config.EXTENSIONES_VALIDAS:
        p = config.UPLOADS_DIR / f"inventario{ext}"
        if p.exists():
            return p
    return None
