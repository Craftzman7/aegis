#!/usr/bin/env bash
# First-time + repeat deploy of Aegis to Cloudflare. Idempotent: existing resources are reused.
# Needs: wrangler logged in (npx wrangler login). Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."
W="npx wrangler"

echo "== D1"
$W d1 create aegis 2>/dev/null || true
DB_ID=$($W d1 list --json | node -e 'const l=JSON.parse(require("fs").readFileSync(0));process.stdout.write((l.find(d=>d.name==="aegis")||{}).uuid||"")')
[ -n "$DB_ID" ] || { echo "could not find D1 id"; exit 1; }
sed -i.bak "s|\"database_id\": \"[^\"]*\"|\"database_id\": \"$DB_ID\"|" wrangler.jsonc && rm -f wrangler.jsonc.bak

echo "== R2, Queues, Vectorize"
$W r2 bucket create aegis-evidence 2>/dev/null || true
$W queues create aegis-triage 2>/dev/null || true
$W queues create aegis-triage-dlq 2>/dev/null || true
$W vectorize create aegis-memory --dimensions=768 --metric=cosine 2>/dev/null || true
# AI Gateway "aegis": optional (runner.ts falls back to direct Workers AI); create it in the dashboard for logs/caching.

echo "== Migrations"
$W d1 migrations apply aegis --remote

echo "== Signing key (only if not set yet; never rotate silently: agents pin the public key)"
if ! $W secret list 2>/dev/null | grep -q SIGNING_KEY_JWK; then
  node scripts/gen-signing-key.mjs | sed -E "s/^SIGNING_KEY_JWK='(.*)'$/\1/" | $W secret put SIGNING_KEY_JWK
fi

echo "== Dashboard + agent binaries"
(cd ../dashboard && npm run build)
make -C ../agent build-linux
for a in amd64 arm64; do
  $W r2 object put "aegis-evidence/releases/agent/latest/aegis-agent-linux-$a" --file "../agent/dist/aegis-agent-linux-$a" --remote
done

echo "== Deploy"
$W deploy
echo "Done. Protect /console* with a Cloudflare Access app, then set ACCESS_AUD in wrangler.jsonc and redeploy."
