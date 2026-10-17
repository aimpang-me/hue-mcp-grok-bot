#!/usr/bin/env bash
# Local-only proof: wrangler dev (workerd) + mock Philips cloud. Needs `wrangler` on PATH or WRANGLER=/path. Dummy secrets only.
set -euo pipefail
cd "$(dirname "$0")/.."
W=${WRANGLER:-wrangler}; MP=${MOCK_PORT:-18799}; WP=${DEV_PORT:-18787}; export PORT=$MP
D=$(mktemp -d)
cleanup() { pkill -P $$ 2>/dev/null || true; pkill -f "persist-to $D" 2>/dev/null || true; pkill -f "workerd.*$D" 2>/dev/null || true; }
trap 'rc=$?; cleanup; [ $rc = 0 ] && rm -rf "$D" || echo "logs kept in $D"; exit $rc' EXIT
cat > "$D/.dev.vars" <<V
SIGNING_SECRET=dummy-signing-secret
HUE_CLIENT_ID=dummy-client
HUE_CLIENT_SECRET=dummy-secret
HUE_APP_ID=dummy-app
V
cp wrangler.toml.example "$D/wrangler.toml"
sed -i "s#main = \"worker/index.js\"#main = \"$PWD/worker/index.js\"#" "$D/wrangler.toml"
node scripts/mock-cloud.mjs > "$D/cloud.log" 2>&1 &
(cd "$D" && $W dev --port $WP --var HUE_CLOUD_BASE:http://127.0.0.1:$MP --persist-to "$D/state" > "$D/dev.log" 2>&1) &
for i in $(seq 60); do curl -s -o /dev/null localhost:$WP/x && break; sleep 1; done
U=http://localhost:$WP
ok=0
chk() { if [ "$2" = "$3" ]; then echo "PASS $1 ($3)"; else echo "FAIL $1 got $2 want $3"; ok=1; fi; }
WORKER=$U MOCK=http://127.0.0.1:$MP node scripts/e2e-flow.mjs || ok=1
# PUTs must have gone out with each user's OWN key/token path
grep -q 'PUT /route/clip/v2/resource/grouped_light/grouplight-alice as alice' "$D/cloud.log" && grep -q 'PUT /route/clip/v2/resource/grouped_light/grouplight-bob as bob' "$D/cloud.log" && echo "PASS each user's dim_room hit their own grouped_light" || { echo "FAIL per-user PUTs"; ok=1; }
grep -q '"brightness":30' "$D/cloud.log" && grep -q '"brightness":60' "$D/cloud.log" && echo "PASS bodies reached cloud" || { echo "FAIL bodies"; ok=1; }
grep -q 'UNPAIR alice' "$D/cloud.log" && echo "PASS disconnect freed alice's bridge key" || { echo "FAIL unpair"; ok=1; }
chk "no mock key/token in worker dev log" "$(grep -cE 'KEY-|ACC-|REF-' "$D/dev.log")" 0
exit $ok
