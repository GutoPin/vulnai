# -*- coding: utf-8 -*-
"""Etapas 5-6 del pipeline: filtrado, organización y troceado (chunks) de CVEs."""

import pandas as pd


def filtrar_y_organizar(df: pd.DataFrame) -> pd.DataFrame:
    """Quita CVEs sin descripción, deduplica por (so, cve_id) y ordena por severidad."""
    if df.empty:
        return df

    df = df.copy()
    df = df[df["description"].astype(str).str.strip() != ""]
    df = df.drop_duplicates(subset=["so", "cve_id"], keep="first")

    orden_sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    df["_orden"] = df["severity"].map(orden_sev).fillna(99)
    df = df.sort_values(["_orden", "so", "cve_id"]).drop(columns=["_orden"])

    return df.reset_index(drop=True)


def df_to_tsv_rows(df: pd.DataFrame) -> str:
    """Serializa el DataFrame a TSV (8 columnas) para enviar a Gemini."""
    rows = []
    for _, r in df.iterrows():
        cid = str(r.get("cve_id", "")).strip()
        sev = str(r.get("severity", "")).strip()
        desc = str(r.get("description", "")).replace("\n", " ").replace("\t", " ").strip()
        so = str(r.get("so", "")).strip()
        ver = str(r.get("version", "")).strip()
        pub = str(r.get("published", "")).strip()
        mod = str(r.get("lastModified", "")).strip()
        status = str(r.get("vulnStatus", "")).strip()
        rows.append(f"{so}\t{ver}\t{cid}\t{pub}\t{mod}\t{status}\t{sev}\t{desc}")
    return "\n".join(rows)


def chunk_text_by_size(text: str, max_chars: int = 60000) -> list:
    """Parte el texto en bloques respetando saltos de línea, sin cortar registros."""
    if len(text) <= max_chars:
        return [text]
    lines = text.splitlines()
    chunks, current, size = [], [], 0
    for ln in lines:
        length = len(ln) + 1
        if size + length > max_chars and current:
            chunks.append("\n".join(current))
            current, size = [], 0
        current.append(ln)
        size += length
    if current:
        chunks.append("\n".join(current))
    return chunks
