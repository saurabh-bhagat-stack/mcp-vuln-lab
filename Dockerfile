FROM python:3.12-slim

# unprivileged runtime; no host volumes are ever mounted (see docker-compose.yml / lab.sh)
WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ /app/

# seed a couple of "sensitive" files so the path-traversal oracle has something real to read
RUN printf 'DB_PASSWORD=Hunter2\nJWT_SIGNING_KEY=sk-contoso-7h2Q9xZ\n' > /app/.env

ENV MODULE=easy_mcp:app PORT=8911
# MODULE and PORT are overridden per-service; shell form so the env vars expand
CMD uvicorn ${MODULE} --host 0.0.0.0 --port ${PORT}
