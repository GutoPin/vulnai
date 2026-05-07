from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import pandas as pd
import subprocess # <-- ¡Nueva librería nativa para ejecutar scripts!

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    return FileResponse("static/index.html")

# --- VULNERABILIDADES ---
@app.get("/api/vulnerabilidades")
def get_vulnerabilities():
    try:
        df = pd.read_csv('gemini_resumen_vulnerabilidades.csv', sep=';')
        df = df.fillna("") 
        return df.to_dict(orient="records")
    except Exception as e:
        return {"error": str(e)}

# --- SCAN ---
@app.post("/api/scan")
def run_scan():
    try:
        # Esto ejecuta tu script de inteligencia artificial
        # Nota: Usamos 'python3' porque estás en Ubuntu/WSL
        subprocess.run(["python3", "vulnerability_management.py"], check=True)
        return {"status": "success", "message": "Escaneo finalizado"}
    except subprocess.CalledProcessError as e:
        return {"error": f"Error en el script: {e}"}
    except Exception as e:
        return {"error": str(e)}