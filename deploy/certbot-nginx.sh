#!/bin/sh
# Certbot deploy hook for the HTTPS console. The SMTP hook remains separate.
set -eu
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx.service
