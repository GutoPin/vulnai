# -*- coding: utf-8 -*-
"""Etapas 3-4 del pipeline: consulta a la API de NVD/NIST y obtención de CVEs."""

import os
import time
from datetime import datetime, timedelta

import pandas as pd
import requests

from app import config


def coincide_version(cve, version_objetivo):
    """Filtro post-API por substring sobre cpeMatch[].criteria. Actualmente NO se usa."""
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if version_objetivo in match.get("criteria", "").lower():
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
    """Wrapper de la API NVD v2.0 con paginación, validaciones y retry inteligente en 429."""
    params = {}

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

    nvd_api_key = os.environ.get(nvd_api_key_env)

    todas = []
    total_resultados = None
    start = int(params.get('startIndex', 0))

    session = requests.Session()
    headers = {
        "User-Agent": "VulnAI/1.0",
        "Accept": "application/json",
    }
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    while True:
        params['startIndex'] = start
        data = None
        for attempt in range(1, max_retries + 1):
            try:
                resp = session.get(config.NVD_BASE_URL, params=params, headers=headers, timeout=request_timeout)
                print(resp.url)
                if resp.status_code == 429:
                    # Piso de 30s: NVD a veces devuelve Retry-After: 0 que llevaría
                    # a un loop instantáneo de reintentos quemando los 3 attempts.
                    wait = max(int(resp.headers.get("Retry-After", "30") or "0"), 30)
                    print(f"NVD rate limit, esperando {wait}s (intento {attempt}/{max_retries})...")
                    time.sleep(wait)
                    continue
                if resp.status_code != 200:
                    # NVD pone el motivo en el header 'message' (ej. 'Invalid apiKey.').
                    nvd_msg = resp.headers.get("message", "").strip()
                    if resp.status_code == 404 and "apikey" in nvd_msg.lower():
                        raise RuntimeError(
                            "NVD rechazó la API key (HTTP 404 'Invalid apiKey.'). "
                            "Verifica NVD_API_KEY en .env o genera una nueva en "
                            "https://nvd.nist.gov/developers/request-an-api-key (recuerda activarla por email)."
                        )
                    detalle = nvd_msg or resp.text[:500]
                    raise RuntimeError(f"HTTP {resp.status_code}: {detalle}")
                data = resp.json()
                break
            except Exception:
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
        time.sleep(1.5)

    # Normalizar a DataFrame
    registros = []
    print(f"La API devolvió {len(todas)} vulnerabilidades crudas.")
    for v in todas:
        cve = v.get('cve', {})
        cid = cve.get('id', '')
        published = cve.get('published', '')
        modified = cve.get('lastModified', '')
        status = cve.get('vulnStatus', '')

        descriptions = cve.get('descriptions', [])
        desc = next((d.get('value', '') for d in descriptions if d.get('lang') == 'es'), None)
        if not desc:
            desc = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), '')
        if not desc and descriptions:
            desc = descriptions[0].get('value', '')

        metrics = cve.get('metrics', {})
        sev = None
        score = None
        if 'cvssMetricV31' in metrics:
            data_cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
            sev, score = data_cvss.get('baseSeverity'), data_cvss.get('baseScore')
        elif 'cvssMetricV30' in metrics:
            data_cvss = metrics['cvssMetricV30'][0].get('cvssData', {})
            sev, score = data_cvss.get('baseSeverity'), data_cvss.get('baseScore')
        elif 'cvssMetricV2' in metrics:
            entry = metrics['cvssMetricV2'][0]
            sev = entry.get('baseSeverity')
            score = entry.get('cvssData', {}).get('baseScore')

        registros.append({
            "cve_id": cid,
            "published": published,
            "lastModified": modified,
            "vulnStatus": status,
            "severity": sev if sev else "",
            "cvss_score": float(score) if score is not None else None,
            "description": desc if desc else "",
        })
    return pd.DataFrame(registros)


def dividir_rango_fechas(inicio, fin, dias=120):
    """Divide [inicio, fin] en sub-rangos de máximo `dias` días (NVD limita a ~120)."""
    inicio = datetime.fromisoformat(inicio)
    fin = datetime.fromisoformat(fin)
    rangos = []
    actual = inicio
    while actual < fin:
        siguiente = min(actual + timedelta(days=dias), fin)
        rangos.append((actual, siguiente))
        actual = siguiente + timedelta(seconds=1)
    return rangos
