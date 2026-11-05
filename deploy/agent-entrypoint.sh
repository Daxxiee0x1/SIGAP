#!/bin/sh
set -eu
NODE_ID="${SIGAP_NODE_ID:-sensor-01}"
KEY=/var/lib/sigap/node.key
TRUST=/data/trust/trust_store.json

# Demo enrollment: create the node key once and publish only its PUBLIC key to the
# shared trust store. In the field this is manual: copy trust_store.json over a
# trusted channel to every verifier.
if [ ! -f "$KEY" ]; then
  sigap keygen --key-id "node-${NODE_ID}-$(date +%Y)-a" --out "$KEY" --trust "$TRUST"
fi

python3 /opt/sigap/simulation/sensor_node.py &
sleep 2
exec sigap agent --config /etc/sigap/agent.json
