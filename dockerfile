FROM python:3.13-slim

WORKDIR /app
RUN apt-get update && apt-get install -y curl unzip && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv
COPY pyproject.toml uv.lock ./
RUN uv sync || (cat uv.lock && echo "uv sync failed" && exit 1)
RUN pip install fastapi uvicorn boto3 python-dotenv cryptography python-jose python-multipart
COPY . .
RUN chmod +x start.sh
EXPOSE 8000
CMD ["/bin/sh", "./start.sh"]