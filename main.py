import os
import sys
import subprocess

import pandas as pd
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

CSV_RESUMEN = "gemini_resumen_vulnerabilidades.csv"
XLSX_RESUMEN = "gemini_resumen_vulnerabilidades.xlsx"
RESUMEN_EJECUTIVO_TXT = "resumen_ejecutivo.txt"
SCANNER_SCRIPT = "vulnerability_management.py"

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def read_root():
    return FileResponse("static/index.html")


# --- VULNERABILIDADES (tabla del dashboard) ---
@app.get("/api/vulnerabilidades")
def get_vulnerabilities():
    if not os.path.exists(CSV_RESUMEN):
        return []
    try:
        df = pd.read_csv(CSV_RESUMEN, sep=';').fillna("")
        return df.to_dict(orient="records")
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# --- RESUMEN EJECUTIVO (texto plano para mostrar en dashboard) ---
@app.get("/api/resumen-ejecutivo")
def get_resumen_ejecutivo():
    if not os.path.exists(RESUMEN_EJECUTIVO_TXT):
        return {"resumen": ""}
    try:
        with open(RESUMEN_EJECUTIVO_TXT, "r", encoding="utf-8") as f:
            return {"resumen": f.read()}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# --- DESCARGA DEL EXCEL CONSOLIDADO ---
@app.get("/api/excel")
def descargar_excel():
    if not os.path.exists(XLSX_RESUMEN):
        return JSONResponse(
            status_code=404,
            content={"error": "Aún no hay Excel generado. Ejecuta un escaneo primero."},
        )
    return FileResponse(
        XLSX_RESUMEN,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=XLSX_RESUMEN,
    )


# --- SCAN: lanza el pipeline completo ---
@app.post("/api/scan")
def run_scan():
    try:
        # sys.executable apunta al intérprete actual (venv en Windows o python3 en WSL/Linux).
        subprocess.run([sys.executable, SCANNER_SCRIPT], check=True)
        return {"status": "success", "message": "Escaneo finalizado"}
    except subprocess.CalledProcessError as e:
        return JSONResponse(status_code=500, content={"error": f"Error en el script: {e}"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
