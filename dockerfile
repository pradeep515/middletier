FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml .
RUN pip install uv && uv sync
COPY app ./app
COPY start.sh .
EXPOSE 8000
CMD ["./start.sh"]