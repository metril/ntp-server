#!/bin/sh
# check-host.sh: verify the host is ready to run the chrony container.
#
# Exits non-zero if any BLOCKING problem is found (a competing time daemon
# still active, or something already bound to UDP 123). Informational items
# (docker gid, hwmon names, logging driver) are printed either way so the
# operator can wire them into .env / compose without a second pass.
set -u

status=0

fail() {
    echo "FAIL: $*" >&2
    status=1
}

warn() {
    echo "WARN: $*" >&2
}

info() {
    echo "INFO: $*"
}

# ---------------------------------------------------------------------------
# Competing time daemons. Two steppers (a host daemon and the container)
# fighting over the clock is one of the documented risks; both must be
# inactive AND masked so a reboot doesn't silently bring one back.
# ---------------------------------------------------------------------------
check_daemon() {
    unit="$1"
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemctl not found, cannot check $unit"
        return
    fi

    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        fail "$unit is active - stop it: systemctl disable --now $unit"
    fi

    if ! systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
        case "$state" in
            masked)
                info "$unit is masked"
                ;;
            ""|not-found|disabled)
                warn "$unit is not masked (state: ${state:-unknown}) - mask it: systemctl mask $unit"
                ;;
            *)
                warn "$unit is in unexpected state '$state' (not masked/disabled/not-found) - mask it: systemctl mask $unit"
                ;;
        esac
    fi
}

check_daemon systemd-timesyncd.service
check_daemon chronyd.service
check_daemon ntpd.service
check_daemon ntp.service
check_daemon ntpsec.service

# ---------------------------------------------------------------------------
# UDP 123 must be free for the container (network_mode: host).
# ---------------------------------------------------------------------------
if command -v ss >/dev/null 2>&1; then
    listeners=$(ss -lunp 2>/dev/null | awk 'NR>1 && $4 ~ /:123$/')
    if [ -n "$listeners" ]; then
        fail "something is already listening on UDP 123:"
        echo "$listeners" >&2
    else
        info "UDP 123 is free"
    fi
else
    warn "ss not found, cannot check UDP 123"
fi

# ---------------------------------------------------------------------------
# Docker logging driver. Alloy's discovery.docker + loki.source.docker tail
# container stdout via the Docker API, which needs json-file (or local).
# ---------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
    driver=$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || true)
    if [ -z "$driver" ]; then
        warn "could not determine docker LoggingDriver (is the daemon running / permissions ok?)"
    elif [ "$driver" = "json-file" ] || [ "$driver" = "local" ]; then
        info "docker LoggingDriver is $driver"
    else
        fail "docker LoggingDriver is '$driver', expected json-file or local"
    fi
else
    warn "docker not found, cannot check LoggingDriver"
fi

# ---------------------------------------------------------------------------
# docker gid, for DOCKER_GID in .env (alloy's group_add needs to match the
# host's docker.sock group so it can read it as an unprivileged user).
# ---------------------------------------------------------------------------
if command -v getent >/dev/null 2>&1; then
    docker_gid=$(getent group docker | cut -d: -f3)
    if [ -n "$docker_gid" ]; then
        info "docker group gid: $docker_gid (set DOCKER_GID=$docker_gid in .env)"
    else
        warn "no 'docker' group found via getent"
    fi
else
    warn "getent not found, cannot determine docker gid"
fi

# ---------------------------------------------------------------------------
# hwmon sensor names, to pin the temperature panel query after discovery -
# the Orange Pi's thermal label varies by board/kernel.
# ---------------------------------------------------------------------------
found_hwmon=0
for name_file in /sys/class/hwmon/*/name; do
    [ -e "$name_file" ] || continue
    found_hwmon=1
    hwmon_dir=$(dirname "$name_file")
    info "hwmon: $(basename "$hwmon_dir") name=$(cat "$name_file" 2>/dev/null)"
done
if [ "$found_hwmon" -eq 0 ]; then
    warn "no /sys/class/hwmon/*/name entries found"
fi

# ---------------------------------------------------------------------------
# Host bind-mount directories. ./data (alloy's storage.path, uid 1000 inside
# the container) must exist and be writable by that uid before `docker
# compose up` first creates the container; ./chrony-data doesn't need the
# chown since the chrony container chowns it itself as root on start.
# ---------------------------------------------------------------------------
compose_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for d in data chrony-data; do
    dir="$compose_dir/$d"
    if [ ! -d "$dir" ]; then
        if mkdir -p "$dir" 2>/dev/null; then
            info "created $dir"
        else
            warn "could not create $dir - run: mkdir -p $dir"
        fi
    fi
done

data_dir="$compose_dir/data"
if [ "$(id -u)" = "0" ]; then
    if chown 1000:1000 "$data_dir" 2>/dev/null; then
        info "chowned $data_dir to 1000:1000"
    else
        warn "could not chown $data_dir - run: chown 1000:1000 $data_dir"
    fi
else
    warn "not root - run this to fix ownership: sudo chown 1000:1000 $data_dir"
fi

exit "$status"
