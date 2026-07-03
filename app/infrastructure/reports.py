# -*- coding: utf-8 -*-
"""Etapa 9 del pipeline: generación del Excel de resultados (el HTML lo sirve FastAPI)."""

import pandas as pd


def generar_excel(df_resumen: pd.DataFrame, resumen_ejecutivo: str, path):
    """Genera el .xlsx con hojas: Vulnerabilidades, Por Prioridad, Por Severidad,
    Por Activo y Resumen Ejecutivo."""
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        df_resumen.to_excel(writer, sheet_name="Vulnerabilidades", index=False)

        if not df_resumen.empty:
            if "prioridad" in df_resumen.columns:
                # Orden personalizado (Prioritaria > Por validar > Planificada).
                orden_prio = {"Prioritaria": 0, "Por validar": 1, "Planificada": 2}
                por_prio = df_resumen["prioridad"].value_counts().reset_index()
                por_prio.columns = ["Prioridad", "Conteo"]
                por_prio["_o"] = por_prio["Prioridad"].map(orden_prio).fillna(99)
                por_prio = por_prio.sort_values("_o").drop(columns=["_o"])
                por_prio.to_excel(writer, sheet_name="Por Prioridad", index=False)

            por_sev = df_resumen["severity"].value_counts().reset_index()
            por_sev.columns = ["Severidad", "Conteo"]
            por_sev.to_excel(writer, sheet_name="Por Severidad", index=False)

            por_so = df_resumen["so"].value_counts().reset_index()
            por_so.columns = ["Activo (SO)", "Conteo"]
            por_so.to_excel(writer, sheet_name="Por Activo", index=False)

        df_re = pd.DataFrame({"Resumen Ejecutivo": [resumen_ejecutivo]})
        df_re.to_excel(writer, sheet_name="Resumen Ejecutivo", index=False)
