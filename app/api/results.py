# -*- coding: utf-8 -*-
"""Endpoints de resultados: tabla, resumen ejecutivo y descargas."""

import pandas as pd
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from app import config

router = APIRouter(tags=["resultados"])


@router.get("/vulnerabilidades")
def get_vulnerabilities():
    if not config.CSV_RESUMEN.exists():
        return []
    try:
        df = pd.read_csv(config.CSV_RESUMEN, sep=';').fillna("")
        return df.to_dict(orient="records")
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/resumen-ejecutivo")
def get_resumen_ejecutivo():
    if not config.RESUMEN_EJECUTIVO_TXT.exists():
        return {"resumen": ""}
    try:
        with open(config.RESUMEN_EJECUTIVO_TXT, "r", encoding="utf-8") as f:
            return {"resumen": f.read()}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/csv")
def descargar_csv():
    if not config.CSV_RESUMEN.exists():
        raise HTTPException(status_code=404, detail="Aún no hay CSV generado.")
    return FileResponse(config.CSV_RESUMEN, media_type="text/csv",
                        filename=config.CSV_RESUMEN.name)


@router.get("/excel")
def descargar_excel():
    if not config.XLSX_RESUMEN.exists():
        raise HTTPException(status_code=404, detail="Aún no hay Excel generado.")
    return FileResponse(
        config.XLSX_RESUMEN,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=config.XLSX_RESUMEN.name,
    )
