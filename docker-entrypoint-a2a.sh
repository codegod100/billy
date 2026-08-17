#!/bin/sh
set -e

# A2A server, internal-only — docker-agent has no auth of its own for this,
# so it only ever listens on loopback. The OIDC proxy is the only thing
# exposed publicly, on Railway's assigned $PORT.
/docker-agent serve a2a /work/agent.yaml --listen 127.0.0.1:9091 &

sleep 1

A2A_PUBLIC_PORT="${PORT:-8090}" exec node /oidc-proxy.js
