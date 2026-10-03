# AgentGuard default sandbox image, built automatically on first use.
# Keep it small: anything installed here can be started by an allowed
# interpreter (node, npm, git) even though only allowed commands are on PATH.
FROM node:22-alpine
LABEL org.agentguard.image="sandbox" org.agentguard.version="0.1"
RUN apk add --no-cache git \
 && (find / -xdev -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null || true) \
 && mkdir -p /workspace /home/agent /opt/agentguard/bin \
 && chmod 0755 /workspace
WORKDIR /workspace
USER 65534:65534
