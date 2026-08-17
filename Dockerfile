FROM docker/docker-agent:latest

USER root
RUN apk add --no-cache nodejs

COPY agent.yaml /work/agent.yaml
COPY oidc-proxy.js /oidc-proxy.js
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh \
    && chown docker-agent:docker-agent /work/agent.yaml /oidc-proxy.js /docker-entrypoint.sh

USER docker-agent
ENTRYPOINT ["/docker-entrypoint.sh"]
