# The partner portal + loopback gateway (scripts/demo-web.ts) as ONE always-on service.
#
# Deliberately a single stage with dev dependencies kept: the entry point runs under `tsx`
# (a devDependency) and the four workspace builds need `typescript`. Pruning would mean
# editing package.json for the sake of an image a few hundred MB smaller — not worth it for a
# testnet demo. No Rust, no stellar CLI: the contracts are already deployed (deployments.json
# is committed) and the deployer secret arrives as STELLARONRAMP_DEPLOYER_SECRET.
FROM node:22-bookworm-slim

WORKDIR /app

# Manifests first so `npm ci` is cached across source-only changes.
COPY package.json package-lock.json tsconfig.json tsconfig.base.json ./
COPY packages/identity/package.json packages/identity/
COPY packages/gateway/package.json  packages/gateway/
COPY packages/sdk/package.json      packages/sdk/
COPY apps/gateway-http/package.json apps/gateway-http/
RUN npm ci --include=dev --no-audit --no-fund

COPY packages ./packages
COPY apps ./apps
COPY scripts ./scripts
COPY deployments.json ./

# Dependency order: identity -> gateway -> gateway-http, sdk.
RUN npm run build -w packages/identity \
 && npm run build -w packages/gateway \
 && npm run build -w apps/gateway-http \
 && npm run build -w packages/sdk

# HOST=0.0.0.0 so the platform can reach the public server; the gateway stays on 127.0.0.1.
# PORTAL_PREBUILT=1 makes boot assert the builds above instead of shelling out to npm.
# PORTAL_DATA_DIR is the volume mount: accounts, sessions, credentials, revocation index.
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8788 \
    GATEWAY_PORT=8791 \
    PORTAL_PREBUILT=1 \
    PORTAL_DATA_DIR=/data \
    PORTAL_SECURE_COOKIES=1

VOLUME ["/data"]
EXPOSE 8788

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8788)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"

CMD ["node_modules/.bin/tsx", "scripts/demo-web.ts"]
