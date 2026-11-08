FROM python:3.11-slim@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79
WORKDIR /vigia
COPY apps/web/requirements.lock ./requirements.lock
RUN pip install --no-cache-dir -r requirements.lock
COPY apps/backend ./apps/backend
COPY apps/engine ./apps/engine
COPY apps/__init__.py ./apps/__init__.py
COPY apps/web ./apps/web
COPY scripts ./scripts
COPY eval/lote-presentacion-091.jsonl ./eval/lote-presentacion-091.jsonl
ENV VIGIA_DATA_DIR=/dataset VIGIA_OUT_DIR=/index VIGIA_WEB_OUT=/state PYTHONUNBUFFERED=1
EXPOSE 8100
CMD ["sh", "apps/web/scripts/servir.sh", "--host", "0.0.0.0"]
