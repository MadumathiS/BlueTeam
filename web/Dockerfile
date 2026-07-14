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

EXPOSE 4325

CMD ["python3", "app.py"]