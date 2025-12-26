FROM ghcr.io/laude-institute/t-bench/ubuntu-24-04:20250624

WORKDIR /app

RUN apt-get update && apt-get install -y \
    jq \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*