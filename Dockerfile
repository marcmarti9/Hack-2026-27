FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 vigia \
    && install -d -o vigia -g vigia /var/lib/vigia

COPY backend backend
COPY frontend frontend
COPY data data
COPY tests tests

USER vigia
