# -*- coding: utf-8 -*-
"""Tests de app.domain.prioritization: matriz CVSS x criticidad del activo."""

import pandas as pd
import pytest

from app.domain.prioritization import aplicar_prioridad, calcular_prioridad


class TestCalcularPrioridad:
    # Matriz completa documentada en calcular_prioridad.
    @pytest.mark.parametrize("cvss,criticidad,esperado", [
        (9.8, "Alta", "Prioritaria"),
        (7.0, "Alta", "Prioritaria"),      # borde inferior CVSS Alto
        (9.8, "Media", "Por validar"),
        (9.8, "Baja", "Por validar"),
        (6.9, "Alta", "Por validar"),      # borde superior CVSS Medio
        (5.0, "Media", "Planificada"),
        (5.0, "Baja", "Planificada"),
        (3.9, "Alta", "Por validar"),
        (1.0, "Media", "Planificada"),
        (1.0, "Baja", "Planificada"),
    ])
    def test_matriz(self, cvss, criticidad, esperado):
        assert calcular_prioridad(cvss, criticidad) == esperado

    @pytest.mark.parametrize("cvss", [None, float("nan"), "no-numerico"])
    def test_sin_score_fuerza_revision_humana(self, cvss):
        assert calcular_prioridad(cvss, "Alta") == "Por validar"

    def test_criticidad_desconocida_usa_default_media(self):
        # Criticidad inválida -> Media; CVSS alto + Media = Por validar.
        assert calcular_prioridad(9.0, "urgentisima") == "Por validar"

    def test_criticidad_none_usa_default(self):
        assert calcular_prioridad(5.0, None) == "Planificada"

    def test_score_como_string_numerico(self):
        assert calcular_prioridad("8.5", "Alta") == "Prioritaria"


class TestAplicarPrioridad:
    def test_agrega_columnas(self):
        df = pd.DataFrame([
            {"so": "Windows 10", "cve_id": "CVE-2024-0001", "cvss_score": 9.0},
            {"so": "Ubuntu", "cve_id": "CVE-2024-0002", "cvss_score": 5.0},
        ])
        out = aplicar_prioridad(df, {"Windows 10": "Alta"})
        assert list(out["criticidad"]) == ["Alta", "Media"]  # Ubuntu sin mapa -> default
        assert list(out["prioridad"]) == ["Prioritaria", "Planificada"]

    def test_df_vacio_no_falla(self):
        df = pd.DataFrame()
        assert aplicar_prioridad(df, {}).empty

    def test_no_muta_el_original(self):
        df = pd.DataFrame([{"so": "X", "cve_id": "CVE-1", "cvss_score": 9.0}])
        aplicar_prioridad(df, {"X": "Alta"})
        assert "prioridad" not in df.columns
