FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    RBL_REPORT_PATH=/app/report.html

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY lab/ lab/

# The container IS the security-regression run: it exits non-zero if any
# attack goes undetected, so it can gate a pipeline directly.
CMD ["python", "-m", "lab.runner"]
