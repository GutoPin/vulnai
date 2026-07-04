# -*- coding: utf-8 -*-
"""Tests de la API HTTP (FastAPI TestClient) con directorios temporales."""

import json

from app import config


class TestRoot:
    def test_sirve_el_dashboard(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "VulnAI" in r.text


class TestUploadInventario:
    def test_rechaza_extension_invalida(self, client):
        r = client.post("/api/upload-inventario",
                        files={"file": ("notas.txt", b"hola", "text/plain")})
        assert r.status_code == 400
        assert "no soportada" in r.json()["detail"]

    def test_acepta_csv_valido(self, client):
        contenido = b"Name,Guest OS,Criticidad\nsrv-01,Windows Server 2019,Alta\n"
        r = client.post("/api/upload-inventario",
                        files={"file": ("inv.csv", contenido, "text/csv")})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["n_activos"] == 1
        assert body["ejemplos"] == ["srv-01"]
        assert (config.UPLOADS_DIR / "inventario.csv").exists()

    def test_rechaza_csv_sin_columna_so(self, client):
        contenido = b"Hostname X,IP\nsrv,10.0.0.1\n"
        r = client.post("/api/upload-inventario",
                        files={"file": ("inv.csv", contenido, "text/csv")})
        assert r.status_code == 400
        # El archivo inválido no debe quedar guardado.
        assert not (config.UPLOADS_DIR / "inventario.csv").exists()


class TestInventarioActual:
    def test_sin_inventario(self, client):
        r = client.get("/api/inventario-actual")
        assert r.status_code == 200
        assert r.json() == {"ok": False}

    def test_con_inventario_subido(self, client):
        contenido = b"Name,Guest OS\nweb-01,Ubuntu Linux\n"
        client.post("/api/upload-inventario",
                    files={"file": ("inv.csv", contenido, "text/csv")})
        r = client.get("/api/inventario-actual")
        body = r.json()
        assert body["ok"] is True
        assert body["n_activos"] == 1


class TestScan:
    def test_scan_sin_inventario_devuelve_400(self, client):
        r = client.post("/api/scan")
        assert r.status_code == 400
        assert "inventario" in r.json()["detail"].lower()

    def test_progress_sin_escaneo(self, client):
        r = client.get("/api/scan-progress")
        assert r.status_code == 200
        body = r.json()
        assert body["stage_idx"] == 0
        assert body["finished"] is False
        assert body["error"] is None

    def test_progress_lee_archivo(self, client):
        payload = {"stage_idx": 3, "total": 8, "label": "Filtrando",
                   "detail": "", "finished": False, "error": None}
        config.PROGRESS_PATH.write_text(json.dumps(payload), encoding="utf-8")
        r = client.get("/api/scan-progress")
        assert r.json()["stage_idx"] == 3


class TestResultados:
    def test_vulnerabilidades_vacio_si_no_hay_csv(self, client):
        r = client.get("/api/vulnerabilidades")
        assert r.status_code == 200
        assert r.json() == []

    def test_vulnerabilidades_lee_csv(self, client):
        config.CSV_RESUMEN.write_text(
            "so;cve_id;severity\nWindows 10;CVE-2024-1;HIGH\n", encoding="utf-8")
        r = client.get("/api/vulnerabilidades")
        assert r.json() == [{"so": "Windows 10", "cve_id": "CVE-2024-1", "severity": "HIGH"}]

    def test_resumen_vacio_si_no_existe(self, client):
        r = client.get("/api/resumen-ejecutivo")
        assert r.json() == {"resumen": ""}

    def test_resumen_lee_txt(self, client):
        config.RESUMEN_EJECUTIVO_TXT.write_text("Todo en orden.", encoding="utf-8")
        r = client.get("/api/resumen-ejecutivo")
        assert r.json() == {"resumen": "Todo en orden."}

    def test_descargas_404_sin_archivos(self, client):
        assert client.get("/api/csv").status_code == 404
        assert client.get("/api/excel").status_code == 404

    def test_descarga_csv_existente(self, client):
        config.CSV_RESUMEN.write_text("so;cve_id\nW;CVE-1\n", encoding="utf-8")
        r = client.get("/api/csv")
        assert r.status_code == 200
        assert "csv" in r.headers["content-type"]


class TestConfigNotificaciones:
    def test_sin_config_devuelve_defaults(self, client):
        r = client.get("/api/config-notificaciones")
        assert r.status_code == 200
        body = r.json()
        assert body["destinatarios"] == config.DESTINATARIOS_DEFAULT
        assert body["custom"] is False

    def test_guardar_lista_custom(self, client):
        r = client.post("/api/config-notificaciones",
                        json={"destinatarios": ["Ana@Empresa.com", "beto@empresa.com"]})
        assert r.status_code == 200
        assert r.json()["destinatarios"] == ["ana@empresa.com", "beto@empresa.com"]
        # GET posterior devuelve lo guardado
        r = client.get("/api/config-notificaciones")
        assert r.json()["destinatarios"] == ["ana@empresa.com", "beto@empresa.com"]
        assert r.json()["custom"] is True

    def test_rechaza_correo_invalido(self, client):
        r = client.post("/api/config-notificaciones",
                        json={"destinatarios": ["no-es-un-correo"]})
        assert r.status_code == 400
        assert "inválido" in r.json()["detail"]

    def test_deduplica_y_limpia(self, client):
        r = client.post("/api/config-notificaciones",
                        json={"destinatarios": [" a@b.co ", "a@b.co", ""]})
        assert r.status_code == 200
        assert r.json()["destinatarios"] == ["a@b.co"]

    def test_lista_vacia_vuelve_a_defaults(self, client):
        client.post("/api/config-notificaciones", json={"destinatarios": ["a@b.co"]})
        r = client.post("/api/config-notificaciones", json={"destinatarios": []})
        assert r.json()["custom"] is False
        assert r.json()["destinatarios"] == config.DESTINATARIOS_DEFAULT
        assert not config.CONFIG_NOTIFICACIONES_PATH.exists()

    def test_rechaza_mas_de_20(self, client):
        muchos = [f"user{i}@empresa.com" for i in range(21)]
        r = client.post("/api/config-notificaciones", json={"destinatarios": muchos})
        assert r.status_code == 400
