# syntax=docker/dockerfile:1.7
# vault: this checkout's Worker under `wrangler dev` (workerd, local Durable
# Objects persisted to /state). Build context is the repository root.
# .env and .dev.vars files are excluded from the context
# (Dockerfile.dockerignore), so no local secret can reach the image.
FROM node:22-bookworm-slim
# The ak-vault commit this image was built from; run.sh records it with the results.
ARG VAULT_COMMIT=unknown
LABEL org.opencontainers.image.revision=$VAULT_COMMIT
ENV PNPM_HOME=/pnpm CI=1 NO_COLOR=1 WRANGLER_SEND_METRICS=false
RUN corepack enable && corepack prepare pnpm@10.18.0 --activate
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/protocol/package.json packages/protocol/
COPY worker/package.json worker/
RUN --mount=type=cache,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm install --frozen-lockfile --filter ak-vault-worker...
COPY packages/protocol/src packages/protocol/src
COPY worker/ worker/
COPY e2e/docker/vault/vault-entrypoint.sh /usr/local/bin/vault-entrypoint
COPY e2e/docker/scanner/disclosure-scan.mjs /app/e2e/disclosure-scan.mjs
RUN mkdir -p /state /logs && chown -R node:node /state /logs /app/worker
USER node
WORKDIR /app/worker
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/vault-entrypoint"]
