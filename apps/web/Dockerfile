FROM python:3.11-slim
WORKDIR /vigia
COPY requirements.txt ./requirements.txt
COPY apps/web/requirements.txt ./apps/web/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r apps/web/requirements.txt
COPY apps/backend ./apps/backend
COPY apps/desktop ./apps/desktop
COPY apps/__init__.py ./apps/__init__.py
COPY apps/web ./apps/web
COPY scripts ./scripts
COPY eval/lote-presentacion-091.jsonl ./eval/lote-presentacion-091.jsonl
ENV VIGIA_DATA_DIR=/dataset VIGIA_OUT_DIR=/index VIGIA_WEB_OUT=/state PYTHONUNBUFFERED=1
EXPOSE 8100
CMD ["sh", "apps/web/scripts/servir.sh", "--host", "0.0.0.0"]
