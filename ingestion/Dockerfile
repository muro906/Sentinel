# confluent-kafka, pandas, numpy, and watchdog all ship as manylinux wheels,
# so no compiler is needed — build-essential has been removed entirely.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 120 --prefer-binary -r requirements.txt

# Copy only the application code, not the zeek sub-directory (it has its own image)
COPY main.py .
COPY features/ features/
COPY kafka/ kafka/
COPY pipeline/ pipeline/

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
