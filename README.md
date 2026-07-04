# VulnAI

Dashboard de análisis de vulnerabilidades: cruza un inventario de activos con la
API de NVD/NIST y usa Gemini para generar explicaciones simples, remediaciones y
un resumen ejecutivo por escaneo.

## Arquitectura

```
app/
├── main.py            # Aplicación FastAPI (app factory)
├── config.py          # Rutas, constantes y claves (única fuente de verdad)
├── api/               # Capa HTTP: inventario, escaneo, resultados
├── domain/            # Lógica de negocio pura (sin red ni disco externo)
│   ├── inventory.py       # Carga y normalización del inventario
│   ├── prioritization.py  # Matriz CVSS x criticidad del activo
│   └── vulnerabilities.py # Filtrado, dedup, chunking
├── infrastructure/    # Adaptadores a servicios externos
│   ├── nvd.py             # API NVD v2.0 (paginación + retries)
│   ├── gemini.py          # Cliente, prompts y parseo de respuestas
│   ├── storage.py         # Persistencia del inventario subido
│   ├── progress.py        # progress.json (polling del frontend)
│   └── reports.py         # Excel de resultados
└── pipeline/
    └── scanner.py     # Orquestador de las 8 etapas del escaneo

static/index.html      # Frontend (Vue 3 + Tailwind + Chart.js vía CDN)
tests/                 # Tests de dominio + API (pytest)
scripts/               # Prototipos / scripts legacy (no forman parte de la app)
```

Los archivos generados por el scanner van a `data/` y los inventarios subidos a
`data/uploads/` (ignorados por git; un único volumen en `/vulnai/data` persiste
todo al desplegar en Railway/Docker).

## Requisitos

- Python 3.12+
- Claves en `.env` (ver `.env.example`): `GEMINI_API_KEY` obligatoria,
  `NVD_API_KEY` recomendada.

## Correr en local

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # y completa tus claves
uvicorn app.main:app --reload
```

Abre <http://127.0.0.1:8000>, sube el inventario (.xlsx/.csv) y ejecuta el escaneo.
(`uvicorn main:app` también funciona: `main.py` re-exporta la app.)

## Correr con Docker

```bash
docker build -t vulnai .
docker run -p 8000:8000 --env-file .env -v vulnai-data:/vulnai/data vulnai
```

## Tests y lint

```bash
pip install -r requirements-dev.txt
pytest -v
flake8 . --select=E9,F63,F7,F82 --exclude=venv
```

CI (GitHub Actions) corre lint + tests + build de Docker en cada push/PR a `main`.
