# -*- coding: utf-8 -*-
"""Etapas 1-2 del pipeline: recepción y normalización del inventario de activos."""

import os
import re

import pandas as pd

# Keywords genéricos del inventario que solo generan ruido en NVD.
KEYWORDS_INUTILES = {
    "other",
    "other 3.x or later linux",
    "2019 stnd",
    "win 10 ent",
}

# Aliases (case-insensitive) para detectar columnas del inventario.
ALIASES_SO = ["guest os", "os", "sistema operativo", "sistema_operativo"]
ALIASES_NOMBRE = ["name", "nombre", "activo", "hostname"]
ALIASES_CRITICIDAD = ["criticidad", "criticality", "business criticality",
                      "importance", "criticidad activo", "criticidad_activo"]

# Mapeo de criticidad a forma canonical (acepta ES e EN).
_CRITICIDAD_MAP = {
    "alta": "Alta", "alto": "Alta", "high": "Alta", "h": "Alta", "1": "Alta",
    "media": "Media", "medio": "Media", "medium": "Media", "med": "Media", "m": "Media", "2": "Media",
    "baja": "Baja", "bajo": "Baja", "low": "Baja", "l": "Baja", "3": "Baja",
}
CRITICIDAD_DEFAULT = "Media"


def normalizar_criticidad(valor) -> str:
    """Normaliza el valor de criticidad a 'Alta'/'Media'/'Baja'. Default: Media."""
    if valor is None:
        return CRITICIDAD_DEFAULT
    s = str(valor).strip().lower()
    if not s or s in ("nan", "none", "-", "n/a"):
        return CRITICIDAD_DEFAULT
    return _CRITICIDAD_MAP.get(s, CRITICIDAD_DEFAULT)


def limpiar_guest_os(guest_os: str) -> str:
    """Normaliza el string Guest OS: quita 'Microsoft' y sufijos '(64|32-bit)'."""
    s = re.sub(r"\s*\((?:32|64)-bit\)\s*$", "", guest_os, flags=re.IGNORECASE)
    s = re.sub(r"^\s*Microsoft\s+", "", s, flags=re.IGNORECASE)
    return s.strip()


def resolver_columna(df_columns, aliases: list[str]) -> str | None:
    """Encuentra la primera columna del DataFrame cuyo nombre (case-insensitive,
    sin espacios extra) coincida con alguno de los aliases."""
    norm = {c.strip().lower(): c for c in df_columns}
    for a in aliases:
        if a in norm:
            return norm[a]
    return None


def _leer_inventario(path: str) -> pd.DataFrame:
    """Lee el inventario sea Excel o CSV. Para Excel usa hoja 'Master List' si
    existe, sino la primera. Para CSV detecta separador entre ',' y ';'."""
    ext = os.path.splitext(str(path))[1].lower()
    if ext in (".xlsx", ".xls"):
        xl = pd.ExcelFile(path)
        sheet = "Master List" if "Master List" in xl.sheet_names else xl.sheet_names[0]
        return pd.read_excel(xl, sheet_name=sheet)
    if ext == ".csv":
        # sep=None + engine='python' deja que pandas detecte el separador.
        return pd.read_csv(path, sep=None, engine="python")
    raise ValueError(f"Extensión no soportada: {ext!r}. Usa .xlsx, .xls o .csv.")


def cargar_activos_desde_inventario(path: str) -> list:
    """Lee el inventario (Excel o CSV) y devuelve dicts {name, nombre, version, criticidad}.

    Acepta los aliases definidos en ALIASES_SO / ALIASES_NOMBRE / ALIASES_CRITICIDAD.
    Filtra filas sin SO y descarta keywords genéricos (KEYWORDS_INUTILES).
    Si no existe columna de criticidad, todos los activos quedan como 'Media'.
    """
    df = _leer_inventario(path)

    col_so = resolver_columna(df.columns, ALIASES_SO)
    if col_so is None:
        raise ValueError(
            f"No se encontró ninguna columna de SO. Esperado uno de: {ALIASES_SO}. "
            f"Columnas encontradas: {list(df.columns)}"
        )
    col_nombre = resolver_columna(df.columns, ALIASES_NOMBRE)             # opcional
    col_crit = resolver_columna(df.columns, ALIASES_CRITICIDAD)           # opcional

    df = df[df[col_so].notna()].copy()

    activos = []
    for _, r in df.iterrows():
        nombre_so = limpiar_guest_os(str(r[col_so]))
        if not nombre_so:
            continue
        if nombre_so.lower() in KEYWORDS_INUTILES:
            display = str(r[col_nombre]).strip() if col_nombre else ""
            print(f"  Saltando activo con keyword genérico: {nombre_so!r} (name={display!r})")
            continue
        criticidad = normalizar_criticidad(r[col_crit]) if col_crit else CRITICIDAD_DEFAULT
        activos.append({
            "name": str(r[col_nombre]).strip() if col_nombre else "",
            "nombre": nombre_so,
            "version": "",
            "criticidad": criticidad,
        })
    return activos
