# -*- coding: utf-8 -*-
"""Etapa 5b: priorización contextualizada (matriz CVSS x criticidad del activo)."""

import pandas as pd

from app.domain.inventory import CRITICIDAD_DEFAULT


def calcular_prioridad(cvss_score, criticidad: str) -> str:
    """Aplica la matriz de priorización combinando CVSS técnico + criticidad de negocio.

    Matriz:
                 | Activo Alta  | Activo Media | Activo Baja
        --------+--------------+--------------+--------------
        CVSS Alto (>=7.0)        Prioritaria    Por validar    Por validar
        CVSS Medio (4.0-6.9)     Por validar    Planificada    Planificada
        CVSS Bajo (<4.0)         Por validar    Planificada    Planificada

    Si no hay cvss_score (CVE sin métrica CVSS publicada o NaN), retorna
    'Por validar' — sin score no podemos posicionarlo en la matriz, así que
    forzamos revisión humana.
    """
    crit = (criticidad or CRITICIDAD_DEFAULT).strip().capitalize()
    if crit not in ("Alta", "Media", "Baja"):
        crit = CRITICIDAD_DEFAULT

    if cvss_score is None:
        return "Por validar"
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return "Por validar"
    if score != score:  # NaN check
        return "Por validar"

    if score >= 7.0:
        nivel = "Alto"
    elif score >= 4.0:
        nivel = "Medio"
    else:
        nivel = "Bajo"

    if nivel == "Alto" and crit == "Alta":
        return "Prioritaria"
    if nivel == "Alto":  # Activo Media o Baja
        return "Por validar"
    # CVSS Medio o Bajo
    if crit == "Alta":
        return "Por validar"
    return "Planificada"


def aplicar_prioridad(df: pd.DataFrame, criticidad_por_so: dict) -> pd.DataFrame:
    """Agrega columnas 'criticidad' y 'prioridad' al DataFrame."""
    if df.empty:
        return df
    df = df.copy()
    df["criticidad"] = df["so"].map(criticidad_por_so).fillna(CRITICIDAD_DEFAULT)
    df["prioridad"] = df.apply(
        lambda r: calcular_prioridad(r.get("cvss_score"), r["criticidad"]), axis=1,
    )
    return df
