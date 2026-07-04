# -*- coding: utf-8 -*-
"""Configuración central del proyecto.

Todas las rutas son absolutas (relativas a la raíz del repo), de modo que
el comportamiento no dependa del directorio desde el que se lance el proceso.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Raíz del proyecto (carpeta que contiene app/, static/, tests/...).
BASE_DIR = Path(__file__).resolve().parent.parent

# --- Directorios de trabajo ---
# uploads/ vive DENTRO de data/ para que un único volumen (ej. Railway permite
# uno por servicio, montado en /vulnai/data) persista inventario + resultados.
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"            # salidas generadas por el scanner
UPLOADS_DIR = DATA_DIR / "uploads"      # inventarios subidos por el usuario

# --- Archivos generados por el pipeline ---
CSV_CRUDO = DATA_DIR / "vulnerabilidades_completas.csv"
CSV_RESUMEN = DATA_DIR / "gemini_resumen_vulnerabilidades.csv"
XLSX_RESUMEN = DATA_DIR / "gemini_resumen_vulnerabilidades.xlsx"
RESUMEN_EJECUTIVO_TXT = DATA_DIR / "resumen_ejecutivo.txt"
PROGRESS_PATH = DATA_DIR / "progress.json"

# --- Notificaciones ---
# Config editable desde el dashboard; n8n la consulta antes de enviar el correo.
CONFIG_NOTIFICACIONES_PATH = DATA_DIR / "config_notificaciones.json"
DESTINATARIOS_DEFAULT = [
    "augustopm607@gmail.com",
    "avalenzuela2903@gmail.com",
    "fbr.latino4@gmail.com",
]

# --- Inventario ---
EXTENSIONES_VALIDAS = {".xlsx", ".xls", ".csv"}

# --- APIs externas ---
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MODELO_GEMINI = "gemini-2.5-flash"

# Rango global de fechas a consultar en NVD.
FECHA_INICIO = "2014-01-01"
FECHA_FIN = "2026-01-01"

# Severidades que pedimos a NVD. NVD acepta solo una severidad por request,
# así que iteramos. CRITICAL+HIGH es el sweet spot entre cobertura y volumen.
SEVERIDADES_NVD = ("CRITICAL", "HIGH")

# Total de etapas reportadas al frontend (debe coincidir con las llamadas a
# actualizar_progreso en el pipeline).
TOTAL_ETAPAS = 8


def gemini_api_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY")


def nvd_api_key() -> str | None:
    return os.environ.get("NVD_API_KEY")


def ensure_dirs() -> None:
    """Crea los directorios de trabajo si no existen."""
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
