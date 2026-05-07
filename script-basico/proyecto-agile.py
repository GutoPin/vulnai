# -*- coding: utf-8 -*-
# pip install requests pandas google-genai

import os
import re
import time
import json
import math
import requests
import pandas as pd
from dotenv import load_dotenv

from google import genai
from google.genai import types

# Carga variables desde .env si existe (no falla si no está).
load_dotenv()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ruta al archivo Excel con el inventario de activos a escanear.
# Para una corrida completa, apunta a "Inventario de Activos POC.xlsx".
INVENTARIO_PATH = "Inventario de Activos POC - prueba.xlsx"

# =========================
# 1) Cliente Gemini
# =========================
def get_gemini_client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Falta la variable de entorno GEMINI_API_KEY.")
    return genai.Client(api_key=api_key)

# =========================
# 2) Llamado NVD con TODOS los filtros
# =========================
def coincide_version(cve, version_objetivo):
  configs = cve.get("configurations", [])

  for conf in configs:
      for node in conf.get("nodes", []):
          for match in node.get("cpeMatch", []):
              criteria = match.get("criteria", "")

              if version_objetivo in criteria.lower():
                  return True
  return False

def obtener_vulnerabilidades(
    cpeName=None,
    cveId=None,
    cveTag=None,
    cvssV2Metrics=None,
    cvssV2Severity=None,
    cvssV3Metrics=None,
    cvssV3Severity=None,
    cvssV4Metrics=None,
    cvssV4Severity=None,
    cweId=None,
    hasCertAlerts=False,
    hasCertNotes=False,
    hasKev=False,
    hasOval=False,
    isVulnerable=False,
    keywordExactMatch=False,
    keywordSearch=None,
    lastModStartDate=None,
    lastModEndDate=None,
    noRejected=False,
    pubStartDate=None,
    pubEndDate=None,
    resultsPerPage=2000,
    startIndex=0,
    sourceIdentifier=None,
    versionEnd=None,
    versionEndType=None,
    versionStart=None,
    versionStartType=None,
    virtualMatchString=None,
    nvd_api_key_env="NVD_API_KEY",
    request_timeout=60,
    max_retries=3,
    backoff_sec=2.0,
    version_objetivo=None,
):
    params = {}

    # ParÃ¡metros opcionales
    if cpeName: params['cpeName'] = cpeName
    if cveId: params['cveId'] = cveId
    if cveTag: params['cveTag'] = cveTag
    if cvssV2Metrics: params['cvssV2Metrics'] = cvssV2Metrics
    if cvssV2Severity: params['cvssV2Severity'] = cvssV2Severity
    if cvssV3Metrics: params['cvssV3Metrics'] = cvssV3Metrics
    if cvssV3Severity: params['cvssV3Severity'] = cvssV3Severity
    if cvssV4Metrics: params['cvssV4Metrics'] = cvssV4Metrics
    if cvssV4Severity: params['cvssV4Severity'] = cvssV4Severity
    if cweId: params['cweId'] = cweId
    if hasCertAlerts: params['hasCertAlerts'] = ''
    if hasCertNotes: params['hasCertNotes'] = ''
    if hasKev: params['hasKev'] = ''
    if hasOval: params['hasOval'] = ''
    if isVulnerable: params['isVulnerable'] = ''
    if keywordExactMatch: params['keywordExactMatch'] = ''
    if keywordSearch: params['keywordSearch'] = keywordSearch
    if lastModStartDate and lastModEndDate:
        params['lastModStartDate'] = lastModStartDate
        params['lastModEndDate'] = lastModEndDate
    if noRejected: params['noRejected'] = ''
    if pubStartDate and pubEndDate:
        params['pubStartDate'] = pubStartDate
        params['pubEndDate'] = pubEndDate
    if resultsPerPage: params['resultsPerPage'] = resultsPerPage
    if startIndex: params['startIndex'] = startIndex
    if sourceIdentifier: params['sourceIdentifier'] = sourceIdentifier
    if versionEnd and versionEndType:
        params['versionEnd'] = versionEnd
        params['versionEndType'] = versionEndType
    if versionStart and versionStartType:
        params['versionStart'] = versionStart
        params['versionStartType'] = versionStartType
    if virtualMatchString: params['virtualMatchString'] = virtualMatchString

    # Validaciones
    if isVulnerable and not cpeName:
        raise ValueError("Si 'isVulnerable' es True, 'cpeName' es obligatorio.")
    if (lastModStartDate and not lastModEndDate) or (lastModEndDate and not lastModStartDate):
        raise ValueError("'lastModStartDate' y 'lastModEndDate' deben proporcionarse juntos.")
    if (pubStartDate and not pubEndDate) or (pubEndDate and not pubStartDate):
        raise ValueError("'pubStartDate' y 'pubEndDate' deben proporcionarse juntos.")
    if (versionEnd and not versionEndType) or (versionEndType and not versionEnd) or (versionEnd and not virtualMatchString):
        raise ValueError("'versionEnd', 'versionEndType' y 'virtualMatchString' son obligatorios juntos.")
    if (versionStart and not versionStartType) or (versionStartType and not versionStart) or (versionStart and not virtualMatchString):
        raise ValueError("'versionStart', 'versionStartType' y 'virtualMatchString' son obligatorios juntos.")
    if keywordExactMatch and not keywordSearch:
        raise ValueError("'keywordSearch' es obligatorio si 'keywordExactMatch' es True.")
    if (cvssV2Metrics and cvssV3Metrics) or (cvssV2Metrics and cvssV4Metrics) or (cvssV3Metrics and cvssV4Metrics):
        raise ValueError("No mezclar 'cvssV2Metrics' con 'cvssV3Metrics' o 'cvssV4Metrics'.")
    if (cvssV2Severity and cvssV3Severity) or (cvssV2Severity and cvssV4Severity) or (cvssV3Severity and cvssV4Severity):
        raise ValueError("No mezclar 'cvssV2Severity' con 'cvssV3Severity' o 'cvssV4Severity'.")

    # API key de NVD (opcional, recomendada para subir el rate limit)
    nvd_api_key = os.environ.get(nvd_api_key_env)

    todas = []
    total_resultados = None
    start = int(params.get('startIndex', 0))

    session = requests.Session()
    headers = {
        "User-Agent": "NVD-Client/1.0 (+https://example.local)",
        "Accept": "application/json"
    }
    if nvd_api_key:
      headers["apiKey"] = nvd_api_key

    while True:
        params['startIndex'] = start
        data = None
        # Retries con backoff. 429 espera la ventana completa de NVD (30s).
        for attempt in range(1, max_retries + 1):
            try:
                resp = session.get(NVD_BASE_URL, params=params, headers=headers, timeout=request_timeout)
                print(resp.url)
                if resp.status_code == 429:
                    # Si el servidor sugiere un Retry-After, lo respetamos; si no, 30s (ventana NVD).
                    wait = int(resp.headers.get("Retry-After", "30"))
                    print(f"Rate limit alcanzado, esperando {wait}s (intento {attempt}/{max_retries})...")
                    time.sleep(wait)
                    continue
                if resp.status_code != 200:
                    raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:500]}")
                data = resp.json()
                break
            except Exception as e:
                if attempt == max_retries:
                    raise
                time.sleep(backoff_sec * attempt)

        if data is None:
            raise RuntimeError(
                f"NVD devolvió 429 en {max_retries} intentos consecutivos. "
                "Verifica que NVD_API_KEY esté configurada o aumenta los delays."
            )

        vulns = data.get('vulnerabilities', [])
        todas.extend(vulns)

        if total_resultados is None:
            total_resultados = data.get('totalResults', 0)

        results_per_page = data.get('resultsPerPage', len(vulns))
        if start + results_per_page >= total_resultados:
            break
        start += results_per_page
        # Respetar un pequeÃ±o delay para no golpear lÃ­mites
        time.sleep(1.5)

    # Normalizar a DataFrame
    registros = []  # o 25h2, etc.
    print(f"La API devolvió {len(todas)} vulnerabilidades crudas.")
    for v in todas:
        cve = v.get('cve', {})

        #if version_objetivo:
        #  if not coincide_version(cve, version_objetivo):
        #      continue

        cid = cve.get('id', '')
        published = cve.get('published', '')
        modified = cve.get('lastModified', '')
        status = cve.get('vulnStatus', '')

        descriptions = cve.get('descriptions', [])

        # intentar español primero
        desc = next((d.get('value', '') for d in descriptions if d.get('lang') == 'es'), None)

        # fallback a inglés
        if not desc:
            desc = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), '')

        # fallback final
        if not desc and descriptions:
            desc = descriptions[0].get('value', '')

        metrics = cve.get('metrics', {})
        sev = None
        if 'cvssMetricV31' in metrics:
            sev = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity')
        elif 'cvssMetricV30' in metrics:
            sev = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity')
        elif 'cvssMetricV2' in metrics:
            sev = metrics['cvssMetricV2'][0].get('baseSeverity')

        registros.append({
            "cve_id": cid,
            "published": published,
            "lastModified": modified,
            "vulnStatus": status,
            "severity": sev if sev else "",
            #"description": desc_en if desc_en else ""
            "description": desc if desc else ""
        })
    df = pd.DataFrame(registros)
    return df

# =========================
# 3) Utilidades para preparar prompt y chunking
# =========================
def df_to_tsv_rows(df):
    rows = []
    for _, r in df.iterrows():
        cid = str(r.get("cve_id", "")).strip()
        sev = str(r.get("severity", "")).strip()
        desc = str(r.get("description", "")).replace("\n", " ").strip()
        so = str(r.get("so", "")).strip()
        ver = str(r.get("version", "")).strip()
        # Sumamos los campos que faltaban:
        pub = str(r.get("published", "")).strip()
        mod = str(r.get("lastModified", "")).strip()
        status = str(r.get("vulnStatus", "")).strip()

        rows.append(f"{so}\t{ver}\t{cid}\t{pub}\t{mod}\t{status}\t{sev}\t{desc}")
    return "\n".join(rows)


def chunk_text_by_size(text: str, max_chars: int = 80000) -> list:
    """Parte el texto en trozos respetando saltos de lÃ­nea para no cortar registros."""
    if len(text) <= max_chars:
        return [text]
    lines = text.splitlines()
    chunks, current, size = [], [], 0
    for ln in lines:
        l = len(ln) + 1
        if size + l > max_chars and current:
            chunks.append("\n".join(current))
            current, size = [], 0
        current.append(ln)
        size += l
    if current:
        chunks.append("\n".join(current))
    return chunks

# =========================
# 4) Prompt para Gemini y llamada por bloques
# =========================
def build_instruction_header(no_header_rows=True, max_words=40) -> str:
    parts = [
        "Eres un experto analista de ciberseguridad.",
        "Recibirás datos (separados por tabulaciones o punto y coma) con 8 campos originales: so, version, cve_id, published, lastModified, vulnStatus, severity, description.",
        "Tarea: Devuelve una tabla en formato Markdown con EXACTAMENTE 9 columnas.",
        "",
        "REGLAS ESTRICTAS:",
        "1. COPIA EXACTAMENTE los valores originales para las columnas: SO, Version, CVE, Publicado, Modificado, Estado y Severidad. PROHIBIDO poner 'N/A', debes mantener las fechas exactas.",
        f"2. RESUME la Descripcion original en máximo {max_words} palabras, traduciéndola al español si es necesario.",
        "3. GENERA una nueva columna llamada 'Remediacion' con 1 o 2 pasos técnicos claros para mitigar la vulnerabilidad.",
        "",
        "El encabezado de tu tabla Markdown DEBE SER EXACTAMENTE ESTE:",
        "SO | Version | CVE | Publicado | Modificado | Estado | Severidad | Descripcion | Remediacion",
        "|---|---|---|---|---|---|---|---|---|",
        "",
        "Datos:"
    ]
    if no_header_rows:
        parts.append("- IMPORTANTE: NO incluyas la cabecera de la tabla, SOLO las filas.")
    else:
        parts.append("- Incluye cabecera de tabla en Markdown.")
    parts.extend(["- No agregues textos antes o despues de la tabla.", "", "Datos (TSV):"])
    return "\n".join(parts)

def _extraer_retry_delay(err) -> int:
    """Si Gemini devuelve 429 con retryDelay, lo extrae en segundos. Default 60s."""
    try:
        details = err.details if hasattr(err, "details") else {}
        if isinstance(details, dict):
            for d in details.get("error", {}).get("details", []):
                if d.get("@type", "").endswith("RetryInfo"):
                    delay = d.get("retryDelay", "60s")
                    return int(float(delay.rstrip("s"))) + 1
    except Exception:
        pass
    return 60


def call_gemini_on_chunk(client, model_name: str, instructions: str, tsv_chunk: str,
                         max_retries: int = 5) -> str:
    """Llama a Gemini en streaming. Reintenta automáticamente en 429."""
    contents = [
        types.Content(
            role="user",
            parts=[types.Part.from_text(text=instructions + "\n" + tsv_chunk)]
        ),
    ]
    config = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_budget=-1),
    )

    for attempt in range(1, max_retries + 1):
        try:
            out = []
            for piece in client.models.generate_content_stream(
                model=model_name,
                contents=contents,
                config=config,
            ):
                if hasattr(piece, "text") and piece.text:
                    out.append(piece.text)
            return "".join(out)
        except Exception as e:
            msg = str(e)
            is_429 = "429" in msg or "RESOURCE_EXHAUSTED" in msg
            if is_429 and attempt < max_retries:
                wait = _extraer_retry_delay(e)
                print(f"     Gemini rate limit. Esperando {wait}s (intento {attempt}/{max_retries})...")
                time.sleep(wait)
                continue
            raise



from datetime import datetime, timedelta

def dividir_rango_fechas(inicio, fin, dias=120):

    inicio = datetime.fromisoformat(inicio)
    fin = datetime.fromisoformat(fin)

    rangos = []
    actual = inicio

    while actual < fin:
        siguiente = min(actual + timedelta(days=dias), fin)
        rangos.append((actual, siguiente))
        actual = siguiente + timedelta(seconds=1)

    return rangos

# =========================
# 5) Carga de inventario desde Excel
# =========================
def _limpiar_guest_os(guest_os: str) -> str:
    """Normaliza el string de Guest OS para usarlo como keyword en NVD.
    Quita el prefijo 'Microsoft' y los sufijos '(64-bit)' / '(32-bit)' que confunden la búsqueda."""
    s = re.sub(r"\s*\((?:32|64)-bit\)\s*$", "", guest_os, flags=re.IGNORECASE)
    s = re.sub(r"^\s*Microsoft\s+", "", s, flags=re.IGNORECASE)
    return s.strip()


# Keywords genéricos del inventario que no representan un OS real y que solo
# generan ruido en NVD (ej. "Other" matchea miles de CVEs irrelevantes).
KEYWORDS_INUTILES = {
    "other",
    "other 3.x or later linux",
    "2019 stnd",
    "win 10 ent",
}


def cargar_activos_desde_excel(path: str, sheet_name: str = "Master List") -> list:
    """Lee el inventario y devuelve una lista de dicts {name, nombre, version}.
    Filtra filas sin Guest OS y descarta keywords genéricos que generan ruido."""
    df = pd.read_excel(path, sheet_name=sheet_name)
    df = df[df["Guest OS"].notna()].copy()

    activos = []
    for _, r in df.iterrows():
        nombre = _limpiar_guest_os(str(r["Guest OS"]))
        if not nombre:
            continue
        if nombre.lower() in KEYWORDS_INUTILES:
            print(f"  Saltando activo con keyword genérico: {nombre!r} (name={r.get('Name', '')!r})")
            continue
        activos.append({
            "name": str(r.get("Name", "")).strip(),
            "nombre": nombre,
            "version": "",
        })
    return activos


# =========================
# 6) Main: consulta NVD -> guarda DF -> llama Gemini -> guarda salida
# =========================
def main():
    # Diagnóstico de credenciales (no imprime los valores, solo si están).
    if not os.environ.get("GEMINI_API_KEY"):
        raise RuntimeError("Falta GEMINI_API_KEY (en .env o como variable de entorno).")
    if os.environ.get("NVD_API_KEY"):
        print("NVD_API_KEY detectada -> rate limit alto.")
    else:
        print("ADVERTENCIA: NVD_API_KEY no detectada -> solo 5 req/30s; esperar 429 frecuentes.")

    activos = cargar_activos_desde_excel(INVENTARIO_PATH)
    print(f"Cargados {len(activos)} activos desde {INVENTARIO_PATH}")

    dfs = []

    for activo in activos:
        nombre = activo["nombre"]
        #cpe = activo["cpe"]+activo["version"]
        version_objetivo = activo["version"]

        filtros = dict(
            keywordSearch=nombre,
            noRejected=True,
            cvssV3Severity="CRITICAL"  # Le decimos a la API: solo críticas
            #hasKev=True
        )
        inicio = "2014-01-01"
        fin = "2026-01-01"

        print(f"\n=== Procesando {nombre} {version_objetivo} ===")

        rangos = dividir_rango_fechas(inicio, fin)
        total_descargado_api = 0
        for r_inicio, r_fin in rangos:

            filtros['pubStartDate'] = r_inicio.strftime("%Y-%m-%dT%H:%M:%SZ")
            filtros['pubEndDate'] = r_fin.strftime("%Y-%m-%dT%H:%M:%SZ")
            df_temp = obtener_vulnerabilidades(**filtros, version_objetivo=version_objetivo)
            df_temp.insert(0, "so", nombre)
            df_temp.insert(1, "version", version_objetivo if version_objetivo else "")
            total_descargado_api += len(df_temp)
            # agregar columnas del activo


            dfs.append(df_temp)

        print(f" -> Sobrevivieron al filtro de versión: {total_descargado_api} CVEs")

    if len(dfs) == 0:
        print("\n ALERTA: La NVD devolvió 0 vulnerabilidades. Tu dataframe está vacío.")
        return
    # unir todo
    df = pd.concat(dfs, ignore_index=True)
    #df = df[df["severity"].isin(["HIGH", "CRITICAL"])]
    # Guardar el DF completo a TXT (sin truncar)
    #df.to_string('vulnerabilidades_completas.txt', index=False, justify='left')
    #df.to_excel('vulnerabilidades_completas.xlsx', index=False)
    df.to_csv('vulnerabilidades_completas.csv', index=False, sep=';', encoding='utf-8')
    print("OK: vulnerabilidades_completas.xlsx generado.")


    # Preparar TSV (cve_id, severity, description)
    print("Preparando TSV para Gemini...")
    tsv = df_to_tsv_rows(df)
    # Chunks grandes -> menos llamadas a Gemini -> menor riesgo de rate limit.
    chunks = chunk_text_by_size(tsv, max_chars=60000)

    # Cliente Gemini
    client = get_gemini_client()
    model = "gemini-2.5-flash"

    # Instrucciones (sin cabecera, producimos una sola cabecera global)
    instructions = build_instruction_header(no_header_rows=True, max_words=40)

    print(f"Llamando a Gemini en {len(chunks)} bloque(s)...")

    salida_csv = "gemini_resumen_vulnerabilidades.csv"
    filas = []
    for i, ch in enumerate(chunks, 1):
        print(f"  -> Procesando bloque {i}/{len(chunks)} ...")
        rows_md = call_gemini_on_chunk(client, model, instructions, ch)
        lineas = rows_md.strip().split("\n")
        for linea in lineas:
            linea = linea.strip()

            # 1. El Filtro: Ignorar la decoración de Markdown y las cabeceras repetidas
            if not linea or "---" in linea or "```" in linea or "SO |" in linea or "Version |" in linea:
                continue

            # 2. La Extracción Segura:
            # Quitamos los "|" de los extremos de la línea, y luego separamos por "|".
            # Esto EVITA que se borren las columnas vacías (ej. si falta la severidad).
            linea_limpia = linea.strip("|")
            partes = [p.strip() for p in linea_limpia.split("|")]

            # 3. Guardar en la tabla si tiene las 9 columnas esperadas
            if len(partes) >= 9:
                filas.append({
                    "so": partes[0],
                    "version": partes[1],
                    "cve_id": partes[2],
                    "published": partes[3],
                    "lastModified": partes[4],
                    "vulnStatus": partes[5],
                    "severity": partes[6],
                    "description": partes[7],
                    "remediacion": partes[8]
                })

        # Guardado parcial: si crashea el siguiente bloque, no perdemos lo procesado.
        pd.DataFrame(filas).to_csv(salida_csv, index=False, sep=';', encoding='utf-8')
        print(f"     ({len(filas)} filas acumuladas, guardadas en {salida_csv})")

        time.sleep(0.2)

    print(f"OK: {salida_csv} generado con {len(filas)} filas.")


if __name__ == "__main__":
    main()