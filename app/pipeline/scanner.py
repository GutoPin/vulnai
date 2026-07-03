# -*- coding: utf-8 -*-
"""Orquestador del pipeline de análisis de vulnerabilidades (VulnAI).

Implementa el flujo:
  1. Recepción del inventario de activos       -> domain.inventory
  2. Normalización de datos del activo         -> domain.inventory
  3. Consulta a la API de NVD/NIST             -> infrastructure.nvd
  4. Obtención de vulnerabilidades CVE         -> (parte del paso 3)
  5. Filtrado y organización de resultados     -> domain.vulnerabilities
  6. Procesamiento por bloques o chunks        -> domain.vulnerabilities
  7. Envío de información a la IA generativa   -> infrastructure.gemini
        - Explicación simple (por CVE)
        - Remediación sugerida (por CVE)
        - Resumen ejecutivo (global, en una llamada aparte)
  8. Consolidación de resultados               -> domain.prioritization
  9. Generación de dashboard HTML y Excel      -> infrastructure.reports
 10. Entrega de resultados                     -> archivos en data/

Se ejecuta como módulo:  python -m app.pipeline.scanner
(el backend lo lanza así como subproceso desde POST /api/scan).
"""

import os
import time

import pandas as pd

from app import config
from app.domain.inventory import cargar_activos_desde_inventario
from app.domain.prioritization import aplicar_prioridad
from app.domain.vulnerabilities import (
    chunk_text_by_size,
    df_to_tsv_rows,
    filtrar_y_organizar,
)
from app.infrastructure.gemini import (
    build_instruction_header,
    call_gemini_on_chunk,
    generar_resumen_ejecutivo,
    get_gemini_client,
    parsear_filas_markdown,
)
from app.infrastructure.nvd import dividir_rango_fechas, obtener_vulnerabilidades
from app.infrastructure.progress import actualizar_progreso
from app.infrastructure.reports import generar_excel
from app.infrastructure.storage import ruta_inventario_actual


def _resolver_inventario() -> str:
    """Ruta del inventario a escanear: INVENTARIO_PATH (env) o el último subido."""
    env_path = os.environ.get("INVENTARIO_PATH")
    if env_path:
        return env_path
    actual = ruta_inventario_actual()
    if actual:
        return str(actual)
    raise RuntimeError(
        "No hay inventario: define INVENTARIO_PATH o sube uno vía POST /api/upload-inventario."
    )


def _ejecutar_pipeline():
    """Lógica principal del pipeline. Levanta excepciones; main() las atrapa
    para reportarlas al frontend vía progress.json."""
    # Validación de credenciales
    if not config.gemini_api_key():
        raise RuntimeError("Falta GEMINI_API_KEY (en .env o como variable de entorno).")
    if config.nvd_api_key():
        print("NVD_API_KEY detectada -> rate limit alto.")
    else:
        print("ADVERTENCIA: NVD_API_KEY no detectada -> solo 5 req/30s; esperar 429 frecuentes.")

    config.ensure_dirs()
    inventario_path = _resolver_inventario()

    # === Etapa 1: Recepción + normalización del inventario ===
    actualizar_progreso(1, "Cargando inventario", f"Leyendo {os.path.basename(inventario_path)}...")
    print(f"\n[1/8] Cargando inventario desde {inventario_path}...")
    activos = cargar_activos_desde_inventario(inventario_path)
    print(f"      {len(activos)} activos a procesar.\n")
    actualizar_progreso(1, "Cargando inventario", f"{len(activos)} activos válidos detectados.")

    if not activos:
        raise RuntimeError("No hay activos válidos en el inventario.")

    # === Etapa 2: Consulta NVD (CRITICAL + HIGH) ===
    # Construimos una tabla de criticidad por SO para la matriz de prioridad más adelante.
    criticidad_por_so = {a["nombre"]: a["criticidad"] for a in activos}

    actualizar_progreso(2, "Consultando NVD",
                        f"0/{len(activos)} activos procesados...")
    print("[2/8] Consultando NVD (severidades " + ", ".join(config.SEVERIDADES_NVD) + ")...")
    dfs = []
    total_cves = 0
    for i, activo in enumerate(activos, 1):
        nombre = activo["nombre"]
        version_objetivo = activo["version"]
        crit = activo["criticidad"]
        print(f"      === {nombre} (criticidad: {crit}) ===")
        actualizar_progreso(2, "Consultando NVD",
                            f"{i}/{len(activos)} — {nombre} ({total_cves} CVEs hasta ahora)")
        rangos = dividir_rango_fechas(config.FECHA_INICIO, config.FECHA_FIN)
        total_descargado = 0
        # NVD acepta solo una severidad por request, así que iteramos.
        for severidad in config.SEVERIDADES_NVD:
            filtros = dict(
                keywordSearch=nombre,
                noRejected=True,
                cvssV3Severity=severidad,
            )
            for r_inicio, r_fin in rangos:
                filtros['pubStartDate'] = r_inicio.strftime("%Y-%m-%dT%H:%M:%SZ")
                filtros['pubEndDate'] = r_fin.strftime("%Y-%m-%dT%H:%M:%SZ")
                df_temp = obtener_vulnerabilidades(**filtros, version_objetivo=version_objetivo)
                df_temp.insert(0, "so", nombre)
                df_temp.insert(1, "version", version_objetivo if version_objetivo else "")
                total_descargado += len(df_temp)
                dfs.append(df_temp)
        total_cves += total_descargado
        print(f"      -> {total_descargado} CVEs encontrados ({'/'.join(config.SEVERIDADES_NVD)})\n")

    df_crudo = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
    if df_crudo.empty:
        raise RuntimeError("La NVD devolvió 0 vulnerabilidades para todos los activos.")
    df_crudo.to_csv(config.CSV_CRUDO, index=False, sep=';', encoding='utf-8')
    print(f"      OK: {config.CSV_CRUDO} ({len(df_crudo)} filas)\n")
    actualizar_progreso(2, "Consultando NVD", f"{len(df_crudo)} CVEs descargados.")

    # === Etapa 3: Filtrado y organización ===
    actualizar_progreso(3, "Filtrando y organizando", "")
    print("[3/8] Filtrando y organizando resultados...")
    df_filtrado = filtrar_y_organizar(df_crudo)
    print(f"      {len(df_filtrado)} CVEs únicos tras filtrado.\n")
    actualizar_progreso(3, "Filtrando y organizando",
                        f"{len(df_filtrado)} CVEs únicos tras dedup.")

    if df_filtrado.empty:
        raise RuntimeError("No quedan CVEs tras el filtrado.")

    # === Etapa 4: Procesamiento por chunks ===
    actualizar_progreso(4, "Preparando bloques para IA", "")
    print("[4/8] Preparando chunks para IA generativa...")
    tsv = df_to_tsv_rows(df_filtrado)
    chunks = chunk_text_by_size(tsv, max_chars=60000)
    print(f"      {len(chunks)} bloque(s) generado(s).\n")
    actualizar_progreso(4, "Preparando bloques para IA",
                        f"{len(chunks)} bloque(s) preparado(s).")

    # === Etapa 5: IA — explicación simple + remediación por CVE ===
    actualizar_progreso(5, "Procesando con Gemini",
                        f"Bloque 0/{len(chunks)}...")
    print("[5/8] Enviando a IA (Gemini) — explicación simple + remediación...")
    client = get_gemini_client()
    instructions = build_instruction_header(no_header_rows=True, max_words=40)

    filas = []
    for i, ch in enumerate(chunks, 1):
        actualizar_progreso(5, "Procesando con Gemini",
                            f"Bloque {i}/{len(chunks)} — {len(filas)} filas acumuladas...")
        print(f"      -> Bloque {i}/{len(chunks)}...")
        rows_md = call_gemini_on_chunk(client, config.MODELO_GEMINI, instructions, ch)
        filas.extend(parsear_filas_markdown(rows_md))
        # Guardado parcial: si crashea el siguiente bloque, conservamos lo procesado.
        pd.DataFrame(filas).to_csv(config.CSV_RESUMEN, index=False, sep=';', encoding='utf-8')
        print(f"         ({len(filas)} filas acumuladas, guardadas en {config.CSV_RESUMEN})")
        time.sleep(0.2)

    df_resumen = pd.DataFrame(filas)
    if df_resumen.empty:
        raise RuntimeError("Gemini no devolvió filas válidas para ninguna vulnerabilidad.")

    # Recuperar cvss_score numérico del df_filtrado (Gemini no lo conoce; lo necesitamos
    # para la matriz). Merge por (so, cve_id).
    score_lookup = df_filtrado.set_index(["so", "cve_id"])["cvss_score"].to_dict()
    df_resumen["cvss_score"] = df_resumen.apply(
        lambda r: score_lookup.get((r["so"], r["cve_id"])), axis=1,
    )

    # === Etapa 6: IA — resumen ejecutivo (llamada agregada) ===
    actualizar_progreso(6, "Generando resumen ejecutivo", "")
    print("\n[6/8] Generando resumen ejecutivo...")
    resumen_ejecutivo = generar_resumen_ejecutivo(client, df_resumen)
    with open(config.RESUMEN_EJECUTIVO_TXT, "w", encoding="utf-8") as f:
        f.write(resumen_ejecutivo)
    print(f"      OK: {config.RESUMEN_EJECUTIVO_TXT}\n")

    # === Etapa 7: Consolidación + matriz de prioridad ===
    actualizar_progreso(7, "Consolidando resultados", "")
    print("[7/8] Consolidando resultados y aplicando matriz de prioridad...")
    df_resumen = aplicar_prioridad(df_resumen, criticidad_por_so)
    # Persistimos el CSV final con criticidad y prioridad incluidas.
    df_resumen.to_csv(config.CSV_RESUMEN, index=False, sep=';', encoding='utf-8')
    print(f"      Total CVEs analizados: {len(df_resumen)}")
    print(f"      Distribución por severidad: {df_resumen['severity'].value_counts().to_dict()}")
    print(f"      Distribución por prioridad: {df_resumen['prioridad'].value_counts().to_dict()}\n")

    # === Etapa 8: Generación de Excel ===
    actualizar_progreso(8, "Generando Excel", "")
    print("[8/8] Generando Excel...")
    generar_excel(df_resumen, resumen_ejecutivo, config.XLSX_RESUMEN)
    print(f"      OK: {config.XLSX_RESUMEN}\n")

    print("=== Escaneo completado ===")
    print("Archivos generados:")
    print(f"  - {config.CSV_CRUDO}              (datos crudos NVD)")
    print(f"  - {config.CSV_RESUMEN}            (resumen IA — leído por dashboard)")
    print(f"  - {config.XLSX_RESUMEN}           (Excel con hojas de resumen)")
    print(f"  - {config.RESUMEN_EJECUTIVO_TXT}  (resumen ejecutivo en texto plano)")


def main():
    """Wrapper que ejecuta el pipeline y reporta éxito/error vía progress.json."""
    try:
        _ejecutar_pipeline()
        actualizar_progreso(config.TOTAL_ETAPAS, "Escaneo completado", "", finished=True)
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        actualizar_progreso(0, "Error en el escaneo", msg, finished=True, error=msg)
        raise


if __name__ == "__main__":
    main()
