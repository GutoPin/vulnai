# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Visión general

Dashboard web (FastAPI + Vue 3 vía CDN) que envuelve un script de IA implementando un pipeline de 10 etapas:

1. **Recepción del inventario de activos** — Excel con hoja `Master List`, columna `Guest OS`.
2. **Normalización** — limpia el string de OS (quita `Microsoft`, `(64-bit)`) y descarta keywords genéricos.
3. **Consulta a NVD/NIST** — API v2.0, sub-rangos de 120 días, retry con `Retry-After`.
4. **Obtención de CVEs relacionadas** — aplanado a DataFrame, severidad CVSS v3.1 > v3.0 > v2.
5. **Filtrado y organización** — dedup por `(so, cve_id)`, ordenado por severidad descendente.
6. **Procesamiento por chunks** — bloques de hasta 60 000 caracteres respetando saltos de línea.
7. **Envío a IA generativa (Gemini `gemini-2.5-flash`)**:
   - **Explicación simple** (por CVE) — lenguaje no técnico, una oración.
   - **Remediación sugerida** (por CVE) — 1-2 pasos técnicos.
   - **Resumen ejecutivo** (global) — llamada agregada al final con stats por severidad/SO + top 5 críticos.
8. **Consolidación** — ensambla DataFrame final + texto del resumen ejecutivo.
9. **Generación de Excel** — 4 hojas: Vulnerabilidades, Por Severidad, Por Activo, Resumen Ejecutivo. El dashboard HTML lo provee FastAPI.
10. **Entrega** — archivos en disco listos para servir vía endpoints.

El backend FastAPI (`main.py`) sirve `static/index.html` y expone 4 endpoints; el escaneo real lo hace `vulnerability_management.py`, lanzado como subproceso por `POST /api/scan`.

Existe además `script-basico/` — variante CLI standalone con un subset del flujo (sin resumen ejecutivo ni Excel). Ya no es la fuente "buena": ahora es la versión de raíz la que tiene todas las mejoras.

## Comandos

```powershell
# Crear / activar venv
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Servidor web (FastAPI + frontend en http://127.0.0.1:8000)
uvicorn main:app --reload

# Ejecutar el scanner directamente (sin pasar por la web)
python vulnerability_management.py
```

No hay tests, lint, ni build configurados. Para acotar pruebas: edita `INVENTARIO_PATH` en `vulnerability_management.py` (o exporta la env var del mismo nombre) y/o reduce `FECHA_INICIO` / `FECHA_FIN`.

## Endpoints HTTP

| Método | Ruta | Devuelve |
|---|---|---|
| GET | `/` | `static/index.html` (dashboard) |
| GET | `/api/vulnerabilidades` | JSON con la tabla del CSV resumen |
| GET | `/api/resumen-ejecutivo` | `{"resumen": "..."}` con el texto plano del resumen ejecutivo |
| GET | `/api/excel` | Descarga el `.xlsx` consolidado |
| POST | `/api/scan` | Lanza `vulnerability_management.py` como subproceso (bloquea hasta que termina) |

## Variables de entorno (`.env`)

| Variable | Obligatoria | Default |
|---|---|---|
| `GEMINI_API_KEY` | Sí | — (sin ella el scanner falla con `RuntimeError`) |
| `NVD_API_KEY` | No | sin clave: 5 req/30s; con clave: ~50 req/30s |
| `INVENTARIO_PATH` | No | `script-basico/Inventario de Activos POC - prueba.xlsx` |

`load_dotenv()` se llama al importar `vulnerability_management.py`, por lo que el `.env` se carga tanto para corridas CLI como cuando lo lanza FastAPI.

## Archivos generados por el scanner

| Archivo | Origen | Consumido por |
|---|---|---|
| `vulnerabilidades_completas.csv` | NVD crudo | (referencia / debugging) |
| `gemini_resumen_vulnerabilidades.csv` | Tabla post-Gemini, **10 columnas** | `GET /api/vulnerabilidades` y el frontend Vue |
| `resumen_ejecutivo.txt` | Llamada agregada a Gemini | `GET /api/resumen-ejecutivo` |
| `gemini_resumen_vulnerabilidades.xlsx` | Consolidado de los anteriores | `GET /api/excel` |

## Consideraciones críticas al editar

- **Contrato prompt ↔ parser**: `build_instruction_header` exige una tabla Markdown de **exactamente 10 columnas** sin cabecera (`so, version, cve_id, published, lastModified, vulnStatus, severity, description, explicacion_simple, remediacion`). `parsear_filas_markdown` espera ese orden por índice. Cualquier cambio en uno debe replicarse en el otro o se producen datos cruzados sin error visible.

- **Frontend lee 6 columnas** (`so, version, cve_id, severity, description, remediacion`) en `static/index.html:38-62`. El CSV escribe 10. Si añades columnas al prompt, recuerda actualizar también el `<thead>`/`<tbody>` del Vue. La columna `explicacion_simple` ya viaja en el JSON pero todavía no se renderiza.

- **Resumen ejecutivo es una llamada Gemini extra** después de procesar todos los chunks. No es per-CVE — toma estadísticas agregadas + top 5 críticos y genera un texto de ~250 palabras. Si Gemini falla aquí, se propaga la excepción y NO se genera el `.txt` ni el Excel.

- **Guardado parcial por chunk**: tras cada llamada a Gemini, el CSV se reescribe con todas las filas acumuladas. Si el subproceso muere a mitad, se conserva todo lo procesado hasta ahí (a diferencia del comportamiento original). El Excel y el resumen ejecutivo, en cambio, **solo se generan al final** — si crashea durante el último chunk, esos dos no existirán.

- **`INVENTARIO_PATH` por defecto apunta a `script-basico/`** porque ahí están los `.xlsx` con datos reales. Si refactoreas la organización de archivos, actualiza el default. La envvar `INVENTARIO_PATH` siempre tiene prioridad.

- **`coincide_version(cve, version_objetivo)`** — filtro local post-API por substring. **No se invoca actualmente**; el filtrado real lo hace `cvssV3Severity="CRITICAL"` en la llamada a NVD.

- **Rangos NVD ≤ 120 días**: la API limita `pubStartDate`/`pubEndDate` a ~120 días. `dividir_rango_fechas` parte el rango global; si tocas `dias=120`, mantenlo bajo o NVD devolverá error 400.

- **Rate limits**: 
  - NVD: `time.sleep(1.5)` entre páginas + manejo de `Retry-After` en 429 (default 30s, 3 reintentos máximos antes de error claro).
  - Gemini: respeta el `retryDelay` que la API sugiere en 429, hasta 5 reintentos por chunk.

- **CSVs separados con `;` y UTF-8** — tanto el crudo como el resumen. `main.py` también usa ese separador al leer.

- **Subproceso**: `main.py` invoca `subprocess.run([sys.executable, "vulnerability_management.py"])`. `sys.executable` apunta al intérprete actual (el del venv), por lo que funciona tanto en Windows nativo como en WSL/Linux. **No** uses `python3` literal — fallaría con `FileNotFoundError` en Windows.
