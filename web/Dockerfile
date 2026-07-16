FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends \
		build-essential \
		gcc \
		libssl-dev \
		libffi-dev \
		python3-dev \
		pkg-config \
	&& pip install --no-cache-dir -r requirements.txt \
	&& apt-get purge -y --auto-remove build-essential pkg-config \
	&& rm -rf /var/lib/apt/lists/*

COPY . .

# Create a non-root user and switch to it
RUN useradd --create-home --uid 1000 --shell /bin/bash appuser \
	&& chown -R appuser:appuser /app

USER appuser

EXPOSE 4325
EXPOSE 5678

CMD ["sh", "-c", "if [ \"${ENABLE_DEBUGPY:-0}\" = \"1\" ]; then exec python -m debugpy --listen 0.0.0.0:5678 app.py; else exec python3 app.py; fi"]
#CMD ["python3", "app.py"]