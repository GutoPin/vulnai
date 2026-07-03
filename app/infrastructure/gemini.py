# -*- coding: utf-8 -*-
"""Etapa 7 del pipeline: envío de información a la IA generativa (Gemini).

Contiene el cliente, los prompts y el parseo de las respuestas — todo lo que
constituye el "contrato" con Gemini vive en este módulo.
"""

import time

import pandas as pd
from google import genai
from google.genai import types

from app import config


def get_gemini_client():
    api_key = config.gemini_api_key()
    if not api_key:
        raise RuntimeError("Falta la variable de entorno GEMINI_API_KEY.")
    return genai.Client(api_key=api_key)


def build_instruction_header(no_header_rows=True, max_words=40) -> str:
    """Prompt para Gemini: produce 10 columnas (las 8 originales + Explicación Simple + Remediación)."""
    parts = [
        "Eres un experto analista de ciberseguridad.",
        "Recibirás datos (separados por tabulaciones) con 8 campos originales: so, version, cve_id, published, lastModified, vulnStatus, severity, description.",
        "Tarea: Devuelve una tabla en formato Markdown con EXACTAMENTE 10 columnas.",
        "",
        "REGLAS ESTRICTAS:",
        "1. COPIA EXACTAMENTE los valores originales para las columnas: SO, Version, CVE, Publicado, Modificado, Estado y Severidad. PROHIBIDO poner 'N/A', debes mantener las fechas exactas.",
        f"2. RESUME la Descripcion original en máximo {max_words} palabras, traduciéndola al español si es necesario.",
        "3. GENERA una nueva columna 'Explicacion Simple': describe el riesgo en lenguaje no técnico, en UNA sola oración (máximo 25 palabras), apta para un usuario sin conocimientos de seguridad.",
        "4. GENERA una nueva columna 'Remediacion' con 1 o 2 pasos técnicos claros para mitigar la vulnerabilidad.",
        "",
        "El encabezado de tu tabla Markdown DEBE SER EXACTAMENTE ESTE:",
        "SO | Version | CVE | Publicado | Modificado | Estado | Severidad | Descripcion | Explicacion Simple | Remediacion",
        "|---|---|---|---|---|---|---|---|---|---|",
        "",
    ]
    if no_header_rows:
        parts.append("- IMPORTANTE: NO incluyas la cabecera de la tabla, SOLO las filas.")
    else:
        parts.append("- Incluye cabecera de tabla en Markdown.")
    parts.extend(["- No agregues textos antes o despues de la tabla.", "", "Datos (TSV):"])
    return "\n".join(parts)


def _extraer_retry_delay(err) -> int:
    """Extrae el retryDelay sugerido por Gemini en errores 429. Default 60s."""
    try:
        details = err.details if hasattr(err, "details") else {}
        if isinstance(details, dict):
            for d in details.get("error", {}).get("details", []):
                if d.get("@type", "").endswith("RetryInfo"):
                    delay = d.get("retryDelay", "60s")
                    return int(float(delay.rstrip("s"))) + 1
    except Exception:
        pass
    return 60


def call_gemini_on_chunk(client, model_name: str, instructions: str, tsv_chunk: str,
                         max_retries: int = 5) -> str:
    """Llama a Gemini en streaming. Reintenta automáticamente en 429."""
    contents = [
        types.Content(
            role="user",
            parts=[types.Part.from_text(text=instructions + "\n" + tsv_chunk)],
        ),
    ]
    gen_config = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_budget=-1),
    )

    for attempt in range(1, max_retries + 1):
        try:
            out = []
            for piece in client.models.generate_content_stream(
                model=model_name, contents=contents, config=gen_config,
            ):
                if hasattr(piece, "text") and piece.text:
                    out.append(piece.text)
            return "".join(out)
        except Exception as e:
            msg = str(e)
            is_429 = "429" in msg or "RESOURCE_EXHAUSTED" in msg
            if is_429 and attempt < max_retries:
                wait = _extraer_retry_delay(e)
                print(f"     Gemini rate limit. Esperando {wait}s (intento {attempt}/{max_retries})...")
                time.sleep(wait)
                continue
            raise


def parsear_filas_markdown(rows_md: str) -> list:
    """Parsea la respuesta Markdown de Gemini a dicts (10 columnas esperadas).

    Filtra:
      - Líneas vacías, separadores Markdown ('---'), bloques de código.
      - Cabeceras repetidas (heurística: empieza con '|' y contiene 'SO'/'Version').
      - **Filas cuyo CVE no empieza con 'CVE-'** — Gemini a veces incluye la
        cabecera completa como una fila más; este check la elimina sin importar
        cómo venga formateada.
    """
    filas = []
    for linea in rows_md.strip().split("\n"):
        linea = linea.strip()
        if not linea or "---" in linea or "```" in linea:
            continue
        if linea.startswith("|") and ("SO " in linea[:10] or "Version " in linea):
            continue
        partes = [p.strip() for p in linea.strip("|").split("|")]
        if len(partes) < 10:
            continue
        cve_id = partes[2].strip()
        # Validación dura: si la 3ra celda no es un CVE real, descartamos la fila.
        if not cve_id.upper().startswith("CVE-"):
            continue
        filas.append({
            "so": partes[0],
            "version": partes[1],
            "cve_id": cve_id,
            "published": partes[3],
            "lastModified": partes[4],
            "vulnStatus": partes[5],
            "severity": partes[6],
            "description": partes[7],
            "explicacion_simple": partes[8],
            "remediacion": partes[9],
        })
    return filas


def generar_resumen_ejecutivo(client, df_resumen: pd.DataFrame) -> str:
    """Genera un resumen ejecutivo para alta dirección a partir del DataFrame consolidado."""
    if df_resumen.empty:
        return "No se detectaron vulnerabilidades en el escaneo."

    total = len(df_resumen)
    por_sev = df_resumen["severity"].value_counts().to_dict()
    por_so = df_resumen["so"].value_counts().to_dict()

    criticos = df_resumen[df_resumen["severity"].str.upper() == "CRITICAL"].head(5)
    top_lista = []
    for _, r in criticos.iterrows():
        desc_corta = str(r["description"])[:120]
        top_lista.append(f"- {r['cve_id']} ({r['so']}): {desc_corta}")
    top_str = "\n".join(top_lista) if top_lista else "Ninguno"

    prompt = (
        "Eres un consultor senior de ciberseguridad. Redacta un resumen ejecutivo breve "
        "(máximo 250 palabras) en español dirigido a la alta dirección de una organización, "
        "sobre el siguiente escaneo de vulnerabilidades. Evita tecnicismos innecesarios.\n\n"
        f"Estadísticas:\n"
        f"- Total de vulnerabilidades únicas detectadas: {total}\n"
        f"- Distribución por severidad: {por_sev}\n"
        f"- Distribución por activo (SO): {por_so}\n\n"
        f"Top 5 CVEs CRÍTICOS:\n{top_str}\n\n"
        "Estructura el resumen en 3 párrafos cortos:\n"
        "1. Panorama general (qué tan grave es la situación).\n"
        "2. Activos más comprometidos (a qué prestar atención primero).\n"
        "3. Recomendación de acción (1-2 líneas accionables).\n\n"
        "NO incluyas títulos en Markdown. Solo texto plano con párrafos."
    )

    gen_config = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_budget=-1),
    )
    contents = [types.Content(role="user", parts=[types.Part.from_text(text=prompt)])]

    for attempt in range(1, 6):
        try:
            out = []
            for piece in client.models.generate_content_stream(
                model=config.MODELO_GEMINI, contents=contents, config=gen_config,
            ):
                if hasattr(piece, "text") and piece.text:
                    out.append(piece.text)
            return "".join(out).strip()
        except Exception as e:
            if ("429" in str(e) or "RESOURCE_EXHAUSTED" in str(e)) and attempt < 5:
                wait = _extraer_retry_delay(e)
                print(f"  Resumen ejecutivo: rate limit, esperando {wait}s (intento {attempt}/5)...")
                time.sleep(wait)
                continue
            raise
