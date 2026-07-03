from vulnerability_management import _limpiar_guest_os, _normalizar_criticidad

def test_limpiar_guest_os():
    assert _limpiar_guest_os("Microsoft Windows 10 (64-bit)") == "Windows 10"
    assert _limpiar_guest_os("Ubuntu Linux (32-bit)") == "Ubuntu Linux"

def test_normalizar_criticidad():
    assert _normalizar_criticidad("ALTA") == "Alta"
    assert _normalizar_criticidad("invalid_data") == "Media"