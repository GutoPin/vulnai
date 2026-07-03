# -*- coding: utf-8 -*-
"""Punto de entrada retrocompatible: permite seguir usando `uvicorn main:app`.

La aplicación real vive en app/main.py (`uvicorn app.main:app`).
"""

from app.main import app  # noqa: F401
