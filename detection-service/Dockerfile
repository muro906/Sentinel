FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY detector.py .
COPY main.py .

# Model artifacts are mounted via volume at runtime
# Place: encoder_weights.pt, scaler.joblib, centroid.npy, model_meta.json
# under the path set by MODEL_DIR env var (default /models)
RUN mkdir -p /models

ENV MODEL_DIR=/models
ENV LOG_LEVEL=INFO

CMD ["python", "main.py"]
