#!/bin/sh
set -e

# Existing OpenAI-compatible chat endpoint, public on Railway's assigned $PORT,
# still protected by its own static CHAT_API_KEY bearer token. Unchanged.
/docker-agent serve chat /work/agent.yaml --listen "0.0.0.0:${PORT:-8080}" --api-key-env CHAT_API_KEY &

# A2A server, internal-only — docker-agent has no auth of its own for this,
# so it only listens on loopback. The OIDC proxy in front of it is the only
# thing exposed publicly for A2A traffic.
/docker-agent serve a2a /work/agent.yaml --listen 127.0.0.1:9091 &

# give both a moment to bind before the proxy starts forwarding to them
sleep 1

exec node /oidc-proxy.js
