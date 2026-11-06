#!/bin/sh
set -eu
cp /etc/nginx/conf.d/accessreview.template /etc/nginx/conf.d/default.conf
exec nginx -g 'daemon off;'
