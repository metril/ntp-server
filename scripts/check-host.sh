#!/bin/sh
# check-host.sh: verify the host is ready to run the chrony container.
#
# Exits non-zero if any BLOCKING problem is found (a competing time daemon
# still active, or something already bound to UDP 123). Informational items
# (docker gid, hwmon names, logging driver) are printed either way so the
# operator can wire them into .env / compose without a second pass.
#
# Usage: check-host.sh [--fix|--no-fix] [-h|--help]
#   --fix     apply fixes for detected problems without prompting
#   --no-fix  check only, never prompt or fix (default when stdin isn't a tty)
#   (none)    if stdin is a tty, prompt per problem "Fix now? [y/N]";
#             otherwise behaves like --no-fix
set -u

status=0
MODE=""

usage() {
    cat <<'EOF'
Usage: check-host.sh [--fix|--no-fix] [-h|--help]

  --fix     apply fixes for detected problems without prompting
  --no-fix  check only, never prompt or fix (this is the default when
            stdin is not a terminal)
  -h, --help  show this help

With no flag and an interactive terminal, you're prompted per problem:
"Fix now? [y/N]".
EOF
}

for arg in "$@"; do
    case "$arg" in
        --fix) MODE="fix" ;;
        --no-fix) MODE="nofix" ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "unknown argument: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ -z "$MODE" ]; then
    if [ -t 0 ]; then
        MODE="prompt"
    else
        MODE="nofix"
    fi
fi

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
# offer_fix "description" "command" "fail|warn"
#
# Prints the command, then either applies it (--fix), prompts for it
# (interactive default), or just reports it (--no-fix / non-interactive).
# If root is needed and we're not root, prefixes with sudo when available;
# with neither root nor sudo, prints the manual command and gives up.
# Returns 0 if the problem is now fixed, 1 otherwise (and logs via
# fail()/warn() per the given severity so callers don't have to).
# ---------------------------------------------------------------------------
offer_fix() {
    desc="$1"
    cmd="$2"
    severity="$3"

    if [ "$MODE" = "nofix" ]; then
        if [ "$severity" = "fail" ]; then fail "$desc - fix: $cmd"; else warn "$desc - fix: $cmd"; fi
        return 1
    fi

    if [ "$(id -u)" = "0" ]; then
        run_cmd="$cmd"
    elif command -v sudo >/dev/null 2>&1; then
        run_cmd="sudo $cmd"
    else
        echo "MANUAL: $desc - run: $cmd" >&2
        if [ "$severity" = "fail" ]; then fail "$desc - fix: $cmd"; else warn "$desc - fix: $cmd"; fi
        return 1
    fi

    if [ "$MODE" = "fix" ]; then
        apply=1
    else
        printf '%s\n  %s\n' "$desc" "$run_cmd"
        printf 'Fix now? [y/N] '
        if [ -r /dev/tty ]; then
            read -r ans < /dev/tty
        else
            read -r ans
        fi
        case "$ans" in
            [yY]*) apply=1 ;;
            *) apply=0 ;;
        esac
    fi

    if [ "$apply" = "1" ]; then
        echo "Running: $run_cmd"
        if sh -c "$run_cmd"; then
            echo "OK: $desc"
            return 0
        fi
        echo "FAILED: $desc"
    else
        echo "SKIPPED: $desc"
    fi
    if [ "$severity" = "fail" ]; then fail "$desc - fix: $cmd"; else warn "$desc - fix: $cmd"; fi
    return 1
}

# ---------------------------------------------------------------------------
# Competing time daemons. Two steppers (a host daemon and the container)
# fighting over the clock is one of the documented risks; both must be
# inactive AND masked so a reboot doesn't silently bring one back.
# ---------------------------------------------------------------------------
DAEMON_UNITS="systemd-timesyncd.service chronyd.service ntpd.service ntp.service ntpsec.service"

check_daemon() {
    unit="$1"
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemctl not found, cannot check $unit"
        return
    fi

    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        offer_fix "$unit is active" "systemctl disable --now $unit" fail
    fi

    if ! systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
        case "$state" in
            masked)
                info "$unit is masked"
                ;;
            ""|not-found|disabled)
                offer_fix "$unit is not masked (state: ${state:-unknown})" "systemctl mask $unit" warn
                ;;
            *)
                offer_fix "$unit is in unexpected state '$state' (not masked/disabled/not-found)" "systemctl mask $unit" warn
                ;;
        esac
    fi
}

for unit in $DAEMON_UNITS; do
    check_daemon "$unit"
done

# Re-run once so a fix applied above (e.g. disabling an active daemon) is
# reflected in the final exit status, not just in the fixed-at-the-time check.
if command -v systemctl >/dev/null 2>&1; then
    for unit in $DAEMON_UNITS; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            status=1
        fi
    done
fi

# ---------------------------------------------------------------------------
# UDP 123 must be free for the container (network_mode: host).
# ---------------------------------------------------------------------------
if command -v ss >/dev/null 2>&1; then
    listeners=$(ss -lunp 2>/dev/null | awk 'NR>1 && $4 ~ /:123$/')
    if [ -n "$listeners" ]; then
        if echo "$listeners" | grep -Eq 'chronyd|ntpd|ntpsec|systemd-timesyncd'; then
            fail "UDP 123 is still bound by a time daemon (see daemon checks above):"
        else
            fail "something is already listening on UDP 123 (no automatic fix):"
        fi
        echo "$listeners" >&2
    else
        info "UDP 123 is free"
    fi
else
    warn "ss not found, cannot check UDP 123"
fi

# ---------------------------------------------------------------------------
# net.core.rmem_max/rmem_default/netdev_max_backlog must be large enough
# that the exporter's TPACKET_V3 ring (64 MiB default, NTP_CAPTURE_RING_BYTES)
# and the NIC's per-CPU backlog aren't silently capped -- a capped buffer
# overflows under 5K req/s load and packets are dropped before userspace
# ever sees them.
# ---------------------------------------------------------------------------
if command -v sysctl >/dev/null 2>&1; then
    rmem_max=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
    rmem_default=$(sysctl -n net.core.rmem_default 2>/dev/null || echo 0)
    netdev_backlog=$(sysctl -n net.core.netdev_max_backlog 2>/dev/null || echo 0)
    sysctl_bad=0
    [ "$rmem_max" -lt 67108864 ] && sysctl_bad=1
    [ "$rmem_default" -lt 16777216 ] && sysctl_bad=1
    [ "$netdev_backlog" -lt 5000 ] && sysctl_bad=1
    if [ "$sysctl_bad" -eq 1 ]; then
        offer_fix \
            "net.core.rmem_max=${rmem_max} rmem_default=${rmem_default} netdev_max_backlog=${netdev_backlog}, below the 67108864/16777216/5000 the capture path needs" \
            "sh -c 'printf \"net.core.rmem_max = 67108864\nnet.core.rmem_default = 16777216\nnet.core.netdev_max_backlog = 5000\n\" > /etc/sysctl.d/90-ntp-capture.conf && chmod 0644 /etc/sysctl.d/90-ntp-capture.conf && sysctl --system'" \
            warn
    else
        info "net.core.rmem_max=${rmem_max} rmem_default=${rmem_default} netdev_max_backlog=${netdev_backlog}"
    fi
else
    warn "sysctl not found, cannot check net.core.rmem_max/rmem_default/netdev_max_backlog"
fi

# ---------------------------------------------------------------------------
# RT group scheduling (cpu.rt_runtime_us) throttles SCHED_FIFO/SCHED_RR
# threads outside their allotted runtime; if the cgroup controller is
# active, chronyd's sched_priority (CHRONY_SCHED_PRIORITY) may be silently
# denied or throttled even though the container has CAP_SYS_NICE.
# ---------------------------------------------------------------------------
rt_cgroup_found=""
for rt_runtime_file in \
    /sys/fs/cgroup/cpu.rt_runtime_us \
    /sys/fs/cgroup/cpu/cpu.rt_runtime_us \
    /sys/fs/cgroup/cpu,cpuacct/cpu.rt_runtime_us
do
    if [ -e "$rt_runtime_file" ]; then
        warn "RT group scheduling is active ($rt_runtime_file exists) - this can block chronyd's SCHED_FIFO request; verify with: chrt -p \$(pidof chronyd)"
        rt_cgroup_found=1
    fi
done
if [ -z "$rt_cgroup_found" ]; then
    info "no cpu.rt_runtime_us cgroup found (RT group scheduling not restricting SCHED_FIFO)"
fi

# ---------------------------------------------------------------------------
# Pin the eth0 RX IRQ(s) to cpu 5, alongside chrony's cpuset (compose.yaml
# pins chrony to cpus 4,5) so interrupt handling and chronyd share an A76
# core close to each other instead of contending with the capture exporter
# (pinned to 6,7).
# ---------------------------------------------------------------------------
eth0_irqs=$(grep -E 'eth0' /proc/interrupts 2>/dev/null | awk -F: '{print $1}' | tr -d ' ')
if [ -z "$eth0_irqs" ]; then
    warn "no eth0 IRQ found in /proc/interrupts, skipping IRQ affinity pin"
else
    for irq in $eth0_irqs; do
        affinity_file="/proc/irq/${irq}/smp_affinity_list"
        if [ ! -w "$affinity_file" ] && [ "$(id -u)" != "0" ] && ! command -v sudo >/dev/null 2>&1; then
            warn "cannot write $affinity_file (no root/sudo) - pin eth0 IRQ $irq to cpu 5 manually"
            continue
        fi
        current=$(cat "$affinity_file" 2>/dev/null || echo "?")
        if [ "$current" = "5" ]; then
            info "eth0 IRQ $irq already pinned to cpu 5"
        else
            offer_fix \
                "eth0 IRQ $irq affinity is '$current', not pinned to cpu 5" \
                "sh -c 'echo 5 > $affinity_file'" \
                warn
        fi
    done
fi

# ---------------------------------------------------------------------------
# CLIENTLOGLIMIT (from .env, default 268435456 = 256 MiB) needs headroom on
# an 8 GB Pi; on a much smaller host it could pressure chronyd/the kernel
# page cache. Only a FAIL-worthy sanity check, not a tuning recommendation.
# ---------------------------------------------------------------------------
env_file="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/.env"
clientloglimit=268435456
if [ -f "$env_file" ]; then
    file_value=$(grep -E '^CLIENTLOGLIMIT=' "$env_file" 2>/dev/null | tail -n1 | cut -d= -f2-)
    [ -n "$file_value" ] && clientloglimit="$file_value"
fi
if [ "$clientloglimit" -gt 67108864 ] 2>/dev/null; then
    mem_total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "$mem_total_kb" -lt 2097152 ]; then
        fail "CLIENTLOGLIMIT=${clientloglimit} (>64 MiB) but MemTotal is only ${mem_total_kb} kB (<2 GB) - lower CLIENTLOGLIMIT in .env or add RAM"
    else
        info "CLIENTLOGLIMIT=${clientloglimit}, MemTotal=${mem_total_kb} kB (>=2 GB, OK)"
    fi
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
        fail "docker LoggingDriver is '$driver', expected json-file or local - not auto-fixable: set \"log-driver\": \"json-file\" in /etc/docker/daemon.json and restart docker"
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
# Host bind-mount directory. ./chrony-data must exist before `docker compose
# up`; the chrony container chowns it itself as root on start. Alloy's state
# is on a tmpfs, nothing to prepare.
# ---------------------------------------------------------------------------
compose_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dir="$compose_dir/chrony-data"
if [ ! -d "$dir" ]; then
    if mkdir -p "$dir" 2>/dev/null; then
        info "created $dir"
    else
        warn "could not create $dir - run: mkdir -p $dir"
    fi
fi

exit "$status"
