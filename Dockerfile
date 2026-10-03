FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SURAKSHAEDGE_HOST=0.0.0.0 \
    SURAKSHAEDGE_PORT=8080 \
    SURAKSHAEDGE_OFFLINE_MODE=true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8080
CMD ["python", "app.py"]
