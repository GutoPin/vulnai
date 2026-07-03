# -*- coding: utf-8 -*-
"""Tests de app.domain.inventory: normalización y carga del inventario."""

import pytest

from app.domain.inventory import (
    cargar_activos_desde_inventario,
    limpiar_guest_os,
    normalizar_criticidad,
    resolver_columna,
)


class TestLimpiarGuestOs:
    def test_quita_prefijo_microsoft_y_sufijo_bits(self):
        assert limpiar_guest_os("Microsoft Windows 10 (64-bit)") == "Windows 10"

    def test_quita_sufijo_32_bit(self):
        assert limpiar_guest_os("Ubuntu Linux (32-bit)") == "Ubuntu Linux"

    def test_sin_cambios_si_no_aplica(self):
        assert limpiar_guest_os("Debian 12") == "Debian 12"

    def test_solo_prefijo(self):
        assert limpiar_guest_os("Microsoft Windows Server 2019") == "Windows Server 2019"

    def test_case_insensitive(self):
        assert limpiar_guest_os("microsoft windows 11 (64-BIT)") == "windows 11"


class TestNormalizarCriticidad:
    @pytest.mark.parametrize("entrada,esperado", [
        ("ALTA", "Alta"), ("alta", "Alta"), ("high", "Alta"), ("H", "Alta"), ("1", "Alta"),
        ("media", "Media"), ("MEDIUM", "Media"), ("2", "Media"),
        ("baja", "Baja"), ("low", "Baja"), ("3", "Baja"),
    ])
    def test_valores_validos(self, entrada, esperado):
        assert normalizar_criticidad(entrada) == esperado

    @pytest.mark.parametrize("entrada", [None, "", "nan", "n/a", "-", "invalid_data", 42])
    def test_valores_invalidos_devuelven_default(self, entrada):
        assert normalizar_criticidad(entrada) == "Media"


class TestResolverColumna:
    def test_encuentra_alias_case_insensitive(self):
        cols = ["Name", "Guest OS", "Criticidad"]
        assert resolver_columna(cols, ["guest os", "os"]) == "Guest OS"

    def test_ignora_espacios_extra(self):
        cols = ["  Guest OS  "]
        assert resolver_columna(cols, ["guest os"]) == "  Guest OS  "

    def test_devuelve_none_si_no_hay_match(self):
        assert resolver_columna(["foo", "bar"], ["guest os"]) is None


class TestCargarActivos:
    def _csv(self, tmp_path, contenido):
        p = tmp_path / "inventario.csv"
        p.write_text(contenido, encoding="utf-8")
        return str(p)

    def test_carga_basica_con_criticidad(self, tmp_path):
        path = self._csv(tmp_path, (
            "Name,Guest OS,Criticidad\n"
            "srv-01,Microsoft Windows Server 2019 (64-bit),Alta\n"
            "web-01,Ubuntu Linux (64-bit),baja\n"
        ))
        activos = cargar_activos_desde_inventario(path)
        assert len(activos) == 2
        assert activos[0] == {
            "name": "srv-01", "nombre": "Windows Server 2019",
            "version": "", "criticidad": "Alta",
        }
        assert activos[1]["criticidad"] == "Baja"

    def test_sin_columna_criticidad_usa_default(self, tmp_path):
        path = self._csv(tmp_path, "Name,Guest OS\nsrv-01,Windows 10\n")
        activos = cargar_activos_desde_inventario(path)
        assert activos[0]["nombre"] == "Windows 10"
        assert activos[0]["criticidad"] == "Media"

    def test_descarta_keywords_genericos(self, tmp_path):
        path = self._csv(tmp_path, (
            "Name,Guest OS\n"
            "srv-01,Other\n"
            "srv-02,Windows 10\n"
        ))
        activos = cargar_activos_desde_inventario(path)
        assert [a["nombre"] for a in activos] == ["Windows 10"]

    def test_descarta_filas_sin_so(self, tmp_path):
        path = self._csv(tmp_path, "Name,Guest OS\nsrv-01,Windows 10\nsrv-02,\n")
        activos = cargar_activos_desde_inventario(path)
        assert len(activos) == 1

    def test_sin_columna_so_lanza_error(self, tmp_path):
        path = self._csv(tmp_path, "Hostname X,IP\nsrv,10.0.0.1\n")
        with pytest.raises(ValueError, match="columna de SO"):
            cargar_activos_desde_inventario(path)

    def test_extension_no_soportada(self, tmp_path):
        p = tmp_path / "inventario.txt"
        p.write_text("Guest OS\nWindows\n")
        with pytest.raises(ValueError, match="no soportada"):
            cargar_activos_desde_inventario(str(p))

    def test_csv_con_punto_y_coma(self, tmp_path):
        path = self._csv(tmp_path, "Guest OS;Criticidad\nWindows 10;alta\n")
        activos = cargar_activos_desde_inventario(path)
        assert activos[0]["nombre"] == "Windows 10"
        assert activos[0]["criticidad"] == "Alta"
