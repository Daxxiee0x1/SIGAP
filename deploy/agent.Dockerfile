# Sensor node: Go agent (static binary) + Python telemetry simulator.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/sigap ./cmd/sigap

FROM python:3.12-slim-bookworm
COPY --from=build /out/sigap /usr/local/bin/sigap
COPY configs/agent.json /etc/sigap/agent.json
COPY simulation /opt/sigap/simulation
COPY simulation/sensor.conf /etc/sensor/sensor.conf
COPY deploy/agent-entrypoint.sh /usr/local/bin/agent-entrypoint.sh
RUN mkdir -p /var/log/sensor /var/lib/sigap/outbox && chmod +x /usr/local/bin/agent-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/agent-entrypoint.sh"]
