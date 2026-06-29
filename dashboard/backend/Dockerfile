# ── Stage 1: build wheels ────────────────────────────────────────────────────
# gcc and librdkafka-dev are only needed to compile the confluent-kafka extension.
# They stay in this throwaway stage and never reach the final image.
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        librdkafka-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
# Only the shared library is needed at runtime — headers and compiler are gone.
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        librdkafka1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels /wheels/*.whl \
    && rm -rf /wheels

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
