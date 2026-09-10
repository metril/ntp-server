#!/bin/sh
# test-ntp.sh: smoke-test a running ntp-server stack from the host.
#
# Run after `docker compose up -d`. Prints chrony's own view of sync state,
# the exporter's scraped metric, and Alloy's readiness - all read-only.
set -u

status=0

section() {
    echo
    echo "==> $*"
}

run() {
    echo "+ $*"
    if ! "$@"; then
        echo "FAIL: $*" >&2
        status=1
    fi
}

section "chronyc tracking"
run docker compose exec chrony chronyc tracking

section "chronyc sources -v"
run docker compose exec chrony chronyc sources -v

section "chronyc sourcestats"
run docker compose exec chrony chronyc sourcestats

section "chronyc serverstats"
run docker compose exec chrony chronyc serverstats

section "chrony_exporter: chrony_tracking_stratum"
if command -v curl >/dev/null 2>&1; then
    metric=$(curl -fsS 127.0.0.1:9123/metrics 2>/dev/null | grep chrony_tracking_stratum)
    if [ -n "$metric" ]; then
        echo "$metric"
    else
        echo "FAIL: chrony_tracking_stratum not found on 127.0.0.1:9123/metrics" >&2
        status=1
    fi
else
    echo "FAIL: curl not found" >&2
    status=1
fi

section "alloy readiness"
if command -v curl >/dev/null 2>&1; then
    if curl -fsS 127.0.0.1:12345/-/ready >/dev/null 2>&1; then
        echo "alloy is ready"
    else
        echo "FAIL: 127.0.0.1:12345/-/ready did not respond OK" >&2
        status=1
    fi
fi

exit "$status"
