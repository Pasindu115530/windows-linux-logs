#!/bin/sh
set -eu
: "${API_UPSTREAM:=api:8000}"
: "${API_PROTOCOL:=http}"
export API_UPSTREAM API_PROTOCOL
envsubst '${API_UPSTREAM} ${API_PROTOCOL}' < /etc/nginx/conf.d/accessreview.template > /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'
