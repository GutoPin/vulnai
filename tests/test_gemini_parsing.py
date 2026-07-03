# -*- coding: utf-8 -*-
"""Tests del parseo de respuestas Markdown de Gemini (app.infrastructure.gemini).

Solo se testea la lógica pura (prompt y parseo); las llamadas de red no.
"""

from app.infrastructure.gemini import build_instruction_header, parsear_filas_markdown

FILA_VALIDA = (
    "| Windows 10 |  | CVE-2024-0001 | 2024-01-01 | 2024-02-01 "
    "| Analyzed | HIGH | Descripción corta | Riesgo simple | Aplicar parche |"
)


class TestParsearFilasMarkdown:
    def test_fila_valida(self):
        filas = parsear_filas_markdown(FILA_VALIDA)
        assert len(filas) == 1
        f = filas[0]
        assert f["so"] == "Windows 10"
        assert f["cve_id"] == "CVE-2024-0001"
        assert f["severity"] == "HIGH"
        assert f["explicacion_simple"] == "Riesgo simple"
        assert f["remediacion"] == "Aplicar parche"

    def test_ignora_cabecera_y_separadores(self):
        md = "\n".join([
            "| SO | Version | CVE | Publicado | Modificado | Estado | Severidad | Descripcion | Explicacion Simple | Remediacion |",
            "|---|---|---|---|---|---|---|---|---|---|",
            FILA_VALIDA,
        ])
        filas = parsear_filas_markdown(md)
        assert len(filas) == 1

    def test_descarta_filas_sin_cve_valido(self):
        md = "| a | b | NO-ES-CVE | c | d | e | f | g | h | i |"
        assert parsear_filas_markdown(md) == []

    def test_descarta_filas_con_menos_de_10_columnas(self):
        md = "| Windows | CVE-2024-1 | HIGH |"
        assert parsear_filas_markdown(md) == []

    def test_ignora_bloques_de_codigo_y_lineas_vacias(self):
        md = "\n".join(["```markdown", "", FILA_VALIDA, "```"])
        assert len(parsear_filas_markdown(md)) == 1


class TestBuildInstructionHeader:
    def test_incluye_limite_de_palabras(self):
        assert "40 palabras" in build_instruction_header(max_words=40)

    def test_modo_sin_cabecera(self):
        prompt = build_instruction_header(no_header_rows=True)
        assert "NO incluyas la cabecera" in prompt

    def test_modo_con_cabecera(self):
        prompt = build_instruction_header(no_header_rows=False)
        assert "Incluye cabecera" in prompt
