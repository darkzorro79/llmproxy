FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
COPY llmproxy /app/llmproxy

EXPOSE 443 61150

ENTRYPOINT ["python3", "-m", "llmproxy"]
CMD ["serve", "--config", "/app/config.toml"]
