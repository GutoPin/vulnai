# -*- coding: utf-8 -*-
"""Fixtures compartidas.

`paths_temporales` redirige los directorios de trabajo (uploads/, data/) a un
tmp_path para que los tests de API no toquen los archivos reales del proyecto.
"""

import pytest
from fastapi.testclient import TestClient

from app import config
from app.main import create_app


@pytest.fixture
def paths_temporales(tmp_path, monkeypatch):
    uploads = tmp_path / "uploads"
    data = tmp_path / "data"
    uploads.mkdir()
    data.mkdir()
    monkeypatch.setattr(config, "UPLOADS_DIR", uploads)
    monkeypatch.setattr(config, "DATA_DIR", data)
    monkeypatch.setattr(config, "CSV_CRUDO", data / "vulnerabilidades_completas.csv")
    monkeypatch.setattr(config, "CSV_RESUMEN", data / "gemini_resumen_vulnerabilidades.csv")
    monkeypatch.setattr(config, "XLSX_RESUMEN", data / "gemini_resumen_vulnerabilidades.xlsx")
    monkeypatch.setattr(config, "RESUMEN_EJECUTIVO_TXT", data / "resumen_ejecutivo.txt")
    monkeypatch.setattr(config, "PROGRESS_PATH", data / "progress.json")
    return tmp_path


@pytest.fixture
def client(paths_temporales):
    return TestClient(create_app())
