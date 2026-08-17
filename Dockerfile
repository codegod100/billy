FROM docker/docker-agent:latest

COPY agent.yaml /work/agent.yaml

ENTRYPOINT []
CMD ["/bin/sh", "-c", "/docker-agent serve chat /work/agent.yaml --listen 0.0.0.0:${PORT:-8080} --api-key-env CHAT_API_KEY"]
