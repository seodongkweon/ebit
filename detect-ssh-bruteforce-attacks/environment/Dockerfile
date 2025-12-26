FROM ghcr.io/laude-institute/t-bench/ubuntu-24-04:20250624

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir \
    pip==24.0 \
    pytest==8.4.1 \
    pluggy==1.6.0 \
    packaging==24.2 \
    iniconfig==2.0.0