# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Visión general

Dashboard web (FastAPI + Vue 3 vía CDN) que envuelve un script de IA que:
1. Consulta vulnerabilidades a la **NVD** (National Vulnerability Database) para una lista hardcodeada de activos (`activos` en `vulnerability_management.py:main`).
2. Resume y traduce los CVEs con **Gemini** (`gemini-2.5-flash`) y añade una columna `Remediacion`.
3. Persiste el resultado en `gemini_resumen_vulnerabilidades.csv`, que el frontend lee y renderiza.

El backend FastAPI (`main.py`) sirve `static/index.html` y expone dos endpoints; el escaneo real lo hace `vulnerability_management.py`, lanzado como subproceso por el endpoint `/api/scan`.

Existe además `script-basico/` — variante CLI standalone del mismo pipeline (con inventario en Excel y mejor manejo de 429); tiene su propio `CLAUDE.md` con el detalle de esa versión. Los dos directorios comparten ~80 % del código pero **no se importan entre sí**.

## Comandos

```powershell
# Crear / activar venv (ya existe carpeta venv/ en la raíz)
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Servidor de desarrollo (FastAPI + frontend en http://127.0.0.1:8000)
uvicorn main:app --reload

# Ejecutar el scanner directamente (sin pasar por la web)
python vulnerability_management.py
```

No hay tests, lint, ni build configurados. El scanner sólo se puede ejecutar completo: para acotar pruebas hay que editar la lista `activos` o el rango `inicio`/`fin` dentro de `vulnerability_management.py:main` (aprox. líneas 345–369).

## Arquitectura

**Flujo end-to-end del botón "Nuevo Escaneo":**

`static/index.html` (Vue) → `POST /api/scan` → `subprocess.run(["python3", "vulnerability_management.py"])` → genera `gemini_resumen_vulnerabilidades.csv` → frontend hace `GET /api/vulnerabilidades` → `pd.read_csv(...).to_dict("records")` → render en tabla.

La comunicación entre la app web y el scanner es **únicamente vía archivo CSV en disco**; no hay cola, ni IPC, ni progreso en streaming. El frontend queda con `isScanning=true` durante varios minutos hasta que el subproceso termina.

### Pipeline del scanner (`vulnerability_management.py`)

Organizado en 5 secciones numeradas (`# === N) ... ===`). Para cambios no triviales:

- **`obtener_vulnerabilidades(...)`** — wrapper completo de la API NVD que expone TODOS los filtros (CPE, CVSS v2/v3/v4, KEV, fechas, versiones, etc.) con validación cruzada de parámetros mutuamente obligatorios. Pagina por `startIndex`/`resultsPerPage=2000`, reintenta con backoff lineal y maneja 429 con `time.sleep(10)`. Aplana `metrics` priorizando CVSS v3.1 > v3.0 > v2 y prefiere descripciones en `es` sobre `en`.

- **`dividir_rango_fechas(inicio, fin, dias=120)`** — la NVD limita rangos `pubStartDate`/`pubEndDate` a ~120 días. `main()` parte el rango global (2014–2026) en sub-rangos y llama a la API por cada uno. Si tocas el tamaño, **mantenlo ≤ 120 días** o la API devolverá error.

- **`coincide_version(cve, version_objetivo)`** — filtro local post-API por substring sobre `cpeMatch[].criteria`. **Está desactivado** (líneas 192–194 comentadas); el filtrado real lo hace `cvssV3Severity="CRITICAL"` en la llamada.

- **Pipeline Gemini (`df_to_tsv_rows` → `chunk_text_by_size` → `build_instruction_header` → `call_gemini_on_chunk`)** — el DataFrame se serializa a TSV de 8 columnas, se trocea por tamaño (en `main()` se usan `max_chars=15000`) y cada chunk se envía como llamada en streaming. El prompt exige una tabla Markdown de **exactamente 9 columnas SIN cabecera** (la cabecera se omite porque se concatenan múltiples chunks). El parser en `main()` (~líneas 442–467) descarta líneas con `---`, ` ``` ` o que parezcan cabecera, y solo acepta filas con ≥ 9 columnas tras `split("|")`.

## Consideraciones críticas al editar

- **`subprocess.run(["python3", ...])` en `main.py:31`** — el código asume Linux/WSL. En Windows nativo el ejecutable suele ser `python` (o `python.exe`), por lo que `/api/scan` fallará con `FileNotFoundError`. Si trabajas en Windows, cambia a `sys.executable` para usar el intérprete del venv actual.

- **NVD_API_KEY hardcodeada** — `vulnerability_management.py:139` contiene una API key de NVD literal en el código. La versión de `script-basico/proyecto-agile.py` la lee desde `os.environ`. Al refactorar, mueve la clave a `.env` y lee con `os.environ.get("NVD_API_KEY")`. **No la dupliques en commits ni la pongas en archivos rastreados.**

- **Credenciales por variables de entorno**: `vulnerability_management.py` llama a `load_dotenv()` (línea 14), por lo que SÍ carga `.env` automáticamente — distinto de la versión en `script-basico/`. `GEMINI_API_KEY` es obligatoria (`RuntimeError` si falta). Hay un `.env.example` como plantilla; el `.env` real está en `.gitignore`.

- **Contrato prompt ↔ parser**: cualquier cambio en `build_instruction_header` (orden/nombre/número de columnas) debe sincronizarse con el parser de `main()` que asume índices fijos `partes[0..8]` correspondientes a `so, version, cve_id, published, lastModified, vulnStatus, severity, description, remediacion`. Romper el orden produce datos cruzados **sin error visible**.

- **Frontend espera 6 columnas** (`so, version, cve_id, severity, description, remediacion`) en `static/index.html:46-62`, pero el CSV escribe 9. Las demás (`published`, `lastModified`, `vulnStatus`) viajan en el JSON pero no se renderizan. Si añades columnas al CSV, recuerda actualizar también el `<thead>`/`<tbody>` del Vue.

- **El scanner sobrescribe `gemini_resumen_vulnerabilidades.csv` solo al final** (a diferencia de `script-basico/` que hace guardado parcial por chunk). Si el subproceso muere a mitad, se pierde todo el progreso del chunk en curso. La versión "básica" tiene este patrón ya resuelto si necesitas portarlo.

- **`out_path = "gemini_resumen_vulnerabilidades.xlsx"`** (línea 416) apunta a `.xlsx` pero el archivo real es `.csv` (línea 472); el nombre solo se usa en el `print` final.

- **Encoding del archivo fuente**: hay caracteres no-ASCII corruptos en algunos `print` (`Llamando a Gemini en {len(chunks)} bloque(s)¦`, `Preparando TSV para Gemini¦`). El archivo declara `# -*- coding: utf-8 -*-`; no los "arregles" silenciosamente sin verificar el encoding del editor.

- **Rate limiting**: `time.sleep(1.5)` entre páginas NVD y `time.sleep(0.2)` entre chunks de Gemini. Si reduces los delays prepárate para más 429. El reintento de Gemini en `main()` solo cubre **un** retry tras 60 s; un segundo 429 propaga la excepción.

- **CSVs separados con `;` y UTF-8** — tanto `vulnerabilidades_completas.csv` como `gemini_resumen_vulnerabilidades.csv`. `main.py:19` usa el mismo separador al leer; si cambias uno, cambia el otro.
