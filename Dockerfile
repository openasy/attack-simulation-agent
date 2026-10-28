# syntax=docker/dockerfile:1

# The agent needs no tool of its own: it runs the benign tests of its own built-in pack with Node and the usual host
# programs (whoami, uname, id). Debian slim rather than distroless, as for the other agents, so those programs are
# present. The agent has no runtime dependencies: Node runs the TypeScript sources directly.
FROM node:26.12.0-trixie-slim
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn* \
  && mkdir -p /data && chown node:node /data && chmod 0700 /data
WORKDIR /app
COPY package.json ./
COPY agent ./agent
# The agent's secret lives sealed in /data. It runs as an unprivileged user and takes no inbound work: it only asks
# the server for assignments and reports what it did (ADR 0022, 0023, 0072).
ENV NODE_ENV=production ATTACKSIM_AGENT_STATE=/data/agent.state HOST_ROOT=/host
VOLUME /data
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:2812/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "agent/main.ts"]
