# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Visión general

Proyecto académico (UPC, curso "agile") de un solo archivo (`proyecto-agile.py`) que automatiza la detección y resumen de vulnerabilidades para una lista de activos (sistemas operativos / hipervisores). El flujo es:

1. Carga el inventario de activos desde un Excel (`INVENTARIO_PATH`, columna `Guest OS` de la hoja `Master List`).
2. Consulta la API REST v2.0 de NVD por cada activo, troceando el rango de fechas en sub-rangos de 120 días.
3. Normaliza los CVEs a un `DataFrame` de pandas y los persiste en `vulnerabilidades_completas.csv`.
4. Trocea el CSV en bloques de texto y los envía a Gemini (`gemini-2.5-flash`) para que devuelva una tabla Markdown resumida + columna `Remediacion`.
5. Parsea las filas Markdown y guarda el resultado final en `gemini_resumen_vulnerabilidades.csv`.

No hay tests, build, lint, README ni configuración externa — todo el comportamiento se controla editando constantes dentro del archivo.

## Ejecución

```powershell
pip install requests pandas google-genai
python proyecto-agile.py
```

Genera dos CSVs (separador `;`, UTF-8) en el directorio de ejecución:
- `vulnerabilidades_completas.csv` — datos crudos de NVD.
- `gemini_resumen_vulnerabilidades.csv` — datos resumidos por Gemini con columna de remediación.

No hay forma de ejecutar un solo activo o un solo bloque desde CLI; para acotar pruebas, edita la lista `activos` o el rango `inicio`/`fin` en `main()`.

## Arquitectura del pipeline

El archivo está organizado en 6 secciones numeradas por comentarios (`# === N) ... ===`). Para cambios no triviales conviene entender cómo se conectan:

- **`cargar_activos_desde_excel(path)`** — lee el Excel de inventario (hoja `Master List`, columna `Guest OS`), filtra filas con `Guest OS` nulo, y normaliza el string vía `_limpiar_guest_os` (quita prefijo `Microsoft ` y sufijo `(64|32-bit)`) para mejorar el match en NVD. Devuelve dicts `{name, nombre, version}`. `version` queda vacío porque el filtro local por versión está desactivado y no aporta a `keywordSearch`. Para ejecutar contra el inventario completo, cambia `INVENTARIO_PATH` al archivo grande (ambos comparten el mismo schema).

- **`obtener_vulnerabilidades(...)`** — wrapper completo de la API NVD que expone TODOS los filtros documentados (CPE, CVSS v2/v3/v4, KEV, fechas, versiones, etc.). Implementa: validación cruzada de parámetros mutuamente obligatorios, paginación por `startIndex`/`resultsPerPage` (2000), reintentos con backoff lineal y manejo de 429. La normalización al `DataFrame` aplana `metrics` priorizando CVSS v3.1 > v3.0 > v2 y prefiere descripciones en `es` antes de hacer fallback a `en`.

- **`dividir_rango_fechas(inicio, fin, dias=120)`** — la NVD limita rangos `pubStartDate`/`pubEndDate` a ~120 días. `main()` parte el rango global (2014–2026) en sub-rangos y llama a `obtener_vulnerabilidades` por cada uno, concatenando los DataFrames. Si tocas el tamaño del rango, mantenlo ≤ 120 días o la API devolverá error.

- **`coincide_version(cve, version_objetivo)`** — filtro local (post-API) que recorre `configurations[].nodes[].cpeMatch[].criteria` buscando coincidencia de substring con la versión. **Actualmente está desactivado** (las llamadas en `main()` están comentadas en líneas 187–189); el filtrado real lo hace el parámetro `cvssV3Severity="CRITICAL"` de la API. Si lo reactivas, considera que el match es por substring case-insensitive sobre el string CPE completo.

- **Pipeline Gemini (`df_to_tsv_rows` → `chunk_text_by_size` → `build_instruction_header` → `call_gemini_on_chunk`)** — el DataFrame se serializa a TSV de 8 columnas, se trocea por tamaño (default 15 000 caracteres respetando saltos de línea) y cada chunk se envía como una sola llamada en streaming. El prompt exige una tabla Markdown de exactamente 9 columnas SIN cabecera (la cabecera se omite porque se concatenan múltiples chunks). El parser en `main()` (líneas ~444–471) descarta líneas con `---`, ` ``` `, o que parezcan cabecera, y solo acepta filas con ≥ 9 columnas tras `split("|")`.

## Consideraciones críticas al editar

- **Credenciales por variables de entorno**: el script lee `GEMINI_API_KEY` (obligatoria, falla con `RuntimeError` si falta) y `NVD_API_KEY` (opcional, sin ella el rate limit de NVD baja a ~5 req/30s). El nombre de la env var de NVD se controla con el parámetro `nvd_api_key_env` de `obtener_vulnerabilidades`. Hay un `.env.example` en la raíz como plantilla; el archivo real `.env` está en `.gitignore`. El script NO carga `.env` automáticamente — exporta las variables en la shell (`$env:GEMINI_API_KEY = "..."` en PowerShell) o añade `python-dotenv` si quieres soporte de archivo.

- **Contrato del prompt ↔ parser**: cualquier cambio en `build_instruction_header` (orden/nombre de columnas, número de columnas) debe sincronizarse con el parser de `main()` que asume índices fijos `partes[0..8]` correspondientes a `so, version, cve_id, published, lastModified, vulnStatus, severity, description, remediacion`. Romper el orden produce datos cruzados sin error visible.

- **Variable `out_path`** apunta a `.xlsx` pero el código escribe `.csv` (línea 476). El nombre solo se usa en el `print` final.

- **Encoding del archivo fuente**: contiene caracteres no-ASCII parcialmente corruptos en comentarios (`Llamando a Gemini en {len(chunks)} bloque(s)¦`, `Preparando TSV para Gemini¦`). No los "arregles" silenciosamente — el archivo declara `# -*- coding: utf-8 -*-` y editores distintos pueden re-romperlos.

- **Rate limiting**: hay `time.sleep(1.5)` entre páginas y `time.sleep(0.2)` entre chunks de Gemini. Si reduces estos delays, prepárate para gestionar más 429.
