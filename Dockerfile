FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /vigia
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY apps apps
COPY scripts scripts
