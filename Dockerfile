FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMR_DATA_DIR=/data
WORKDIR /opt/openmikrorout
RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 dnsmasq-base conntrack \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY app ./app
RUN mkdir -p /data && chmod 700 /data
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8088/api/health', timeout=2)"
CMD ["python", "-m", "uvicorn", "app.main:create_app", "--factory", "--host", "127.0.0.1", "--port", "8088", "--workers", "1", "--no-access-log", "--no-proxy-headers"]
