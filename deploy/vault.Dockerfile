# Vault: Python FastAPI + the same Go verifier binary used in the field.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/sigap ./cmd/sigap

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SIGAP_BIN=/usr/local/bin/sigap
COPY --from=build /out/sigap /usr/local/bin/sigap
COPY vault/requirements.txt /tmp/requirements.txt
# Offline install: pip install --no-index --find-links /wheelhouse -r /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY vault /opt/vault
WORKDIR /opt/vault
RUN useradd -r -u 10001 vault && mkdir -p /data/vault && chown vault /data/vault
USER vault
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
