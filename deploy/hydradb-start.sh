#!/bin/sh
set -eu
: "${HYDRADB_PASSWORD:?Set HYDRADB_PASSWORD}"
: "${RAILWAY_PRIVATE_DOMAIN:?Private Railway domain is required}"
mkdir -p /data/store /data/cache
printf '%s' "$HYDRADB_PASSWORD" > /data/auth-token
chown -R 10001:10001 /data/store /data/cache /data/auth-token
chmod 600 /data/auth-token
export GRAPH_USAGE_REPORT_ENABLED=false CLOUD_PROVIDER=local LOCAL_PATH=/data/store
export GRAPH_NAMESPACE=default GRAPH_ID=default GRAPH_CELL_ID=cell-0 GRAPH_CELLS=cell-0
export GRAPH_NODE_ID=node-0 GRAPH_BOLT_NODE_ADDRESSES=node-0=0.0.0.0:7687
export GRAPH_ADVERTISED_BOLT_ADDR="$RAILWAY_PRIVATE_DOMAIN:7687"
export GRAPH_DATA_CACHE_DIR=/data/cache GRAPH_AUTH_TOKEN_FILE=/data/auth-token
export GRAPH_ALLOW_PLAINTEXT=true RUST_MIN_STACK=33554432
exec su -s /bin/sh graph -c 'exec /usr/local/bin/graph-node'
