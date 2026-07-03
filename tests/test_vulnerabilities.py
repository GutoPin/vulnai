# -*- coding: utf-8 -*-
"""Tests de app.domain.vulnerabilities: filtrado, TSV y chunking."""

import pandas as pd

from app.domain.vulnerabilities import (
    chunk_text_by_size,
    df_to_tsv_rows,
    filtrar_y_organizar,
)


def _df(rows):
    return pd.DataFrame(rows)


class TestFiltrarYOrganizar:
    def test_quita_cves_sin_descripcion(self):
        df = _df([
            {"so": "W", "cve_id": "CVE-1", "severity": "HIGH", "description": "algo"},
            {"so": "W", "cve_id": "CVE-2", "severity": "HIGH", "description": "   "},
        ])
        out = filtrar_y_organizar(df)
        assert list(out["cve_id"]) == ["CVE-1"]

    def test_deduplica_por_so_y_cve(self):
        df = _df([
            {"so": "W", "cve_id": "CVE-1", "severity": "HIGH", "description": "a"},
            {"so": "W", "cve_id": "CVE-1", "severity": "HIGH", "description": "b"},
            {"so": "U", "cve_id": "CVE-1", "severity": "HIGH", "description": "c"},
        ])
        out = filtrar_y_organizar(df)
        # Mismo CVE en otro SO no es duplicado.
        assert len(out) == 2

    def test_ordena_por_severidad(self):
        df = _df([
            {"so": "W", "cve_id": "CVE-1", "severity": "LOW", "description": "a"},
            {"so": "W", "cve_id": "CVE-2", "severity": "CRITICAL", "description": "b"},
            {"so": "W", "cve_id": "CVE-3", "severity": "HIGH", "description": "c"},
        ])
        out = filtrar_y_organizar(df)
        assert list(out["severity"]) == ["CRITICAL", "HIGH", "LOW"]

    def test_df_vacio_no_falla(self):
        assert filtrar_y_organizar(pd.DataFrame()).empty


class TestDfToTsvRows:
    def test_serializa_8_columnas(self):
        df = _df([{
            "so": "Windows 10", "version": "", "cve_id": "CVE-2024-1",
            "published": "2024-01-01", "lastModified": "2024-02-01",
            "vulnStatus": "Analyzed", "severity": "HIGH", "description": "desc",
        }])
        linea = df_to_tsv_rows(df)
        assert linea.count("\t") == 7
        assert linea.startswith("Windows 10\t")

    def test_limpia_tabs_y_saltos_en_descripcion(self):
        df = _df([{
            "so": "W", "version": "", "cve_id": "CVE-1", "published": "",
            "lastModified": "", "vulnStatus": "", "severity": "",
            "description": "linea1\nlinea2\tcon tab",
        }])
        linea = df_to_tsv_rows(df)
        # La descripción no debe introducir tabs ni saltos extra.
        assert linea.count("\t") == 7
        assert "\n" not in linea


class TestChunkTextBySize:
    def test_texto_corto_un_solo_chunk(self):
        assert chunk_text_by_size("abc", max_chars=100) == ["abc"]

    def test_no_corta_lineas(self):
        lineas = [f"registro-{i:03d}" for i in range(20)]
        texto = "\n".join(lineas)
        chunks = chunk_text_by_size(texto, max_chars=50)
        assert len(chunks) > 1
        # Reconstruir los chunks devuelve exactamente las líneas originales.
        reconstruido = "\n".join(chunks).splitlines()
        assert reconstruido == lineas

    def test_respeta_max_chars(self):
        texto = "\n".join(["x" * 10] * 100)
        for chunk in chunk_text_by_size(texto, max_chars=50):
            assert len(chunk) <= 50
