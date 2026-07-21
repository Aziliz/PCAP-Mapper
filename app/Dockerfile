FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
ENV PORT=8000
ENV WORKERS=1
ENV MAX_UPLOAD_GB=500
ENV CHECKPOINT_EVERY=50000
ENV MAX_FLOWS=250000
ENV MAX_EVENTS=500000
ENV REPORTS_BACKGROUND=0
ENV ATTACK_STIX_STRICT=1
ENV ATTACK_STIX_AUTO_DOWNLOAD=1
EXPOSE 8000
CMD ["python", "run.py"]
