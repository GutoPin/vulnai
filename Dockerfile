FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /vulnai

# Instalar dependencias primero para aprovechar la caché de capas.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY static/ static/
COPY main.py .

# data/ (incluye uploads/) se crea al arrancar; montarla como volumen para persistencia:
#   docker run -p 8000:8000 --env-file .env -v vulnai-data:/vulnai/data vulnai
EXPOSE 8000

# Forma shell para expandir $PORT (Railway y otros PaaS lo inyectan; local usa 8000).
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
