#!/bin/sh
# Render the config with credentials from env (never written to the host), validate, then run.
set -e
: "${MUDFISH_USER:?MUDFISH_USER missing (see .env.local)}"
: "${MUDFISH_PASS:?MUDFISH_PASS missing (see .env.local)}"
: "${CLASH_SECRET:=m0-dev-secret}"
export CLASH_SECRET

mkdir -p /run/m0/work
envsubst '${MUDFISH_USER} ${MUDFISH_PASS} ${CLASH_SECRET}' < /m0/config.template.json > /run/m0/config.json
chmod 600 /run/m0/config.json

sing-box check -c /run/m0/config.json
echo "config OK, starting sing-box"
# tee so tests.py can grep routing decisions from inside the container
sing-box run -c /run/m0/config.json -D /run/m0/work 2>&1 | tee /run/m0/sing-box.log
