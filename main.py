import os
import sys
import json
import shutil
import subprocess

import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# --- Constantes (sincronizadas con vulnerability_management.py) ---
CSV_RESUMEN = "gemini_resumen_vulnerabilidades.csv"
XLSX_RESUMEN = "gemini_resumen_vulnerabilidades.xlsx"
RESUMEN_EJECUTIVO_TXT = "resumen_ejecutivo.txt"
PROGRESS_PATH = "progress.json"
SCANNER_SCRIPT = "vulnerability_management.py"

UPLOADS_DIR = "uploads"
EXTENSIONES_VALIDAS = {".xlsx", ".xls", ".csv"}

app = FastAPI(title="VulnAI Dashboard")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
def _ensure_uploads_dir():
    os.makedirs(UPLOADS_DIR, exist_ok=True)


@app.get("/")
def read_root():
    return FileResponse("static/index.html")


# =========================================================================
# Inventario: upload + validación
# =========================================================================
@app.post("/api/upload-inventario")
async def upload_inventario(file: UploadFile = File(...)):
    """Recibe el archivo de inventario (.xlsx/.xls/.csv), lo guarda en uploads/
    y valida que tenga las columnas esperadas leyendo los activos."""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in EXTENSIONES_VALIDAS:
        raise HTTPException(
            status_code=400,
            detail=f"Extensión {ext!r} no soportada. Usa: {', '.join(sorted(EXTENSIONES_VALIDAS))}",
        )

    os.makedirs(UPLOADS_DIR, exist_ok=True)
    dst = os.path.join(UPLOADS_DIR, f"inventario{ext}")
    # Borra cualquier inventario previo (con extensión distinta) para evitar ambigüedad.
    for old_ext in EXTENSIONES_VALIDAS:
        old_path = os.path.join(UPLOADS_DIR, f"inventario{old_ext}")
        if old_path != dst and os.path.exists(old_path):
            os.remove(old_path)

    with open(dst, "wb") as out:
        shutil.copyfileobj(file.file, out)

    # Validar leyendo activos. Importamos aquí para no acoplar al startup.
    try:
        from vulnerability_management import cargar_activos_desde_inventario
        activos = cargar_activos_desde_inventario(dst)
    except Exception as e:
        # El archivo se guardó, pero no es válido: lo borramos para no tener basura.
        try:
            os.remove(dst)
        except OSError:
            pass
        raise HTTPException(status_code=400, detail=str(e))

    if not activos:
        try:
            os.remove(dst)
        except OSError:
            pass
        raise HTTPException(
            status_code=400,
            detail="El archivo no contiene activos válidos (todos descartados por filtros).",
        )

    ejemplos = [a["name"] or a["nombre"] for a in activos[:3]]
    return {
        "ok": True,
        "filename": file.filename,
        "saved_as": dst,
        "n_activos": len(activos),
        "ejemplos": ejemplos,
    }


def _ruta_inventario_actual() -> str | None:
    """Devuelve la ruta del inventario subido más reciente, o None si no hay."""
    if not os.path.isdir(UPLOADS_DIR):
        return None
    for ext in EXTENSIONES_VALIDAS:
        p = os.path.join(UPLOADS_DIR, f"inventario{ext}")
        if os.path.exists(p):
            return p
    return None


@app.get("/api/inventario-actual")
def inventario_actual():
    """Devuelve metadatos del inventario subido (si existe), para hidratar la UI tras un reload."""
    path = _ruta_inventario_actual()
    if not path:
        return {"ok": False}
    try:
        from vulnerability_management import cargar_activos_desde_inventario
        activos = cargar_activos_desde_inventario(path)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {
        "ok": True,
        "saved_as": path,
        "n_activos": len(activos),
        "ejemplos": [a["name"] or a["nombre"] for a in activos[:3]],
    }


# =========================================================================
# Scan: lanzamiento async + reporte de progreso
# =========================================================================
@app.post("/api/scan")
def run_scan():
    """Lanza el scanner como subproceso no bloqueante. Devuelve inmediatamente."""
    inventario = _ruta_inventario_actual()
    if not inventario:
        raise HTTPException(
            status_code=400,
            detail="Primero debes subir un inventario (POST /api/upload-inventario).",
        )

    # Limpiamos el progress.json viejo para que el frontend no lea estado obsoleto.
    if os.path.exists(PROGRESS_PATH):
        try:
            os.remove(PROGRESS_PATH)
        except OSError:
            pass

    env = os.environ.copy()
    env["INVENTARIO_PATH"] = inventario

    # Popen no bloqueante: el scanner corre en segundo plano y reporta vía progress.json.
    proc = subprocess.Popen([sys.executable, SCANNER_SCRIPT], env=env)
    return {"started": True, "pid": proc.pid, "inventario": inventario}


@app.get("/api/scan-progress")
def scan_progress():
    """Lee progress.json y devuelve el estado actual del pipeline."""
    if not os.path.exists(PROGRESS_PATH):
        return {
            "stage_idx": 0,
            "total": 8,
            "label": "Sin escaneo en curso",
            "detail": "",
            "finished": False,
            "error": None,
        }
    try:
        with open(PROGRESS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# =========================================================================
# Resultados: tabla, resumen ejecutivo, descargas
# =========================================================================
@app.get("/api/vulnerabilidades")
def get_vulnerabilities():
    if not os.path.exists(CSV_RESUMEN):
        return []
    try:
        df = pd.read_csv(CSV_RESUMEN, sep=';').fillna("")
        return df.to_dict(orient="records")
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/resumen-ejecutivo")
def get_resumen_ejecutivo():
    if not os.path.exists(RESUMEN_EJECUTIVO_TXT):
        return {"resumen": ""}
    try:
        with open(RESUMEN_EJECUTIVO_TXT, "r", encoding="utf-8") as f:
            return {"resumen": f.read()}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/csv")
def descargar_csv():
    if not os.path.exists(CSV_RESUMEN):
        raise HTTPException(status_code=404, detail="Aún no hay CSV generado.")
    return FileResponse(CSV_RESUMEN, media_type="text/csv", filename=CSV_RESUMEN)


@app.get("/api/excel")
def descargar_excel():
    if not os.path.exists(XLSX_RESUMEN):
        raise HTTPException(status_code=404, detail="Aún no hay Excel generado.")
    return FileResponse(
        XLSX_RESUMEN,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=XLSX_RESUMEN,
    )
