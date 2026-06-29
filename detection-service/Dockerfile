FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 120 --prefer-binary \
        -r requirements.txt

# Only source files — model artifacts mounted via volume at runtime
COPY detector.py main.py ./

RUN mkdir -p /models

ENV MODEL_DIR=/models \
    LOG_LEVEL=INFO

CMD ["python", "main.py"]
