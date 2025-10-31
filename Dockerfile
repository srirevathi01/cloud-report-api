FROM public.ecr.aws/docker/library/python:3.11-slim AS fastapi

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy FastAPI app
COPY . .

FROM caddy:2-alpine

RUN apk add --no-cache python3 py3-pip supervisor

# Copy app from previous stage
COPY --from=fastapi /app /app

# Copy configs
COPY Caddyfile /etc/caddy/Caddyfile
COPY supervisord.conf /etc/supervisord.conf

# Persistent directories for SSL certs
VOLUME ["/opt/caddy/data", "/opt/caddy/config"]

EXPOSE 80 443

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

# # Expose the port Uvicorn will run on
# EXPOSE 8000

# # Start FastAPI
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]