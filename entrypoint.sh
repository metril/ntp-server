#!/bin/sh
# POSIX sh (busybox ash on alpine). Renders /tmp/chrony.conf from
# chrony.conf.template + env, then execs chronyd in the background so this
# script can watch for NTS cert/key changes while still propagating chronyd's
# exit status (and forwarding TERM to it) for `restart: unless-stopped`.
set -eu

TEMPLATE=/etc/chrony/chrony.conf.template
RENDERED=/tmp/chrony.conf
# NTS_CERT_DIR is bind-mounted read-only at /certs by compose.nts.yaml;
# NTS_CERT_NAME/NTS_KEY_NAME are paths relative to it (may include
# subdirectories, e.g. "live/<host>/fullchain.pem" when NTS_CERT_DIR points
# at the whole /etc/letsencrypt so live/'s symlinks into archive/ resolve).
NTS_CERT_SRC="/certs/${NTS_CERT_NAME:-fullchain.pem}"
NTS_KEY_SRC="/certs/${NTS_KEY_NAME:-privkey.pem}"
NTS_KEY_TMP=/tmp/nts-server.key
NTS_CERT_TMP=/tmp/nts-server.crt

NTS_ENABLED="${NTS_ENABLED:-false}"
RATELIMIT_INTERVAL="${RATELIMIT_INTERVAL:-3}"
RATELIMIT_BURST="${RATELIMIT_BURST:-8}"
RATELIMIT_LEAK="${RATELIMIT_LEAK:-2}"
CLIENTLOGLIMIT="${CLIENTLOGLIMIT:-4194304}"
POOL_SERVERS="${POOL_SERVERS:-}"

if [ -z "${GRANDMASTER_HOST:-}" ]; then
	echo "entrypoint: GRANDMASTER_HOST must be set" >&2
	exit 1
fi

render_pool_servers() {
	# One "server X iburst" line per whitespace-separated POOL_SERVERS entry.
	out=""
	for s in $POOL_SERVERS; do
		out="${out}server ${s} iburst
"
	done
	printf '%s' "$out"
}

render_nts_config() {
	if [ "$NTS_ENABLED" != "true" ]; then
		printf ''
		return
	fi
	cat <<-EOF
	ntsservercert ${NTS_CERT_TMP}
	ntsserverkey ${NTS_KEY_TMP}
	ntsport 4460
	ntsdumpdir /var/lib/chrony
	ntsprocesses 1
	EOF
}

copy_nts_files() {
	# Copy cert/key into /tmp with perms the dropped-priv `chrony` user can
	# read (root:chrony 0640), since the host-mounted originals under
	# /certs are read-only and may not be group-readable by chrony.
	if [ ! -r "$NTS_CERT_SRC" ] || [ ! -r "$NTS_KEY_SRC" ]; then
		echo "entrypoint: NTS cert/key files missing or unreadable at $NTS_CERT_SRC / $NTS_KEY_SRC" >&2
		exit 1
	fi
	cp "$NTS_CERT_SRC" "$NTS_CERT_TMP"
	cp "$NTS_KEY_SRC" "$NTS_KEY_TMP"
	chown root:chrony "$NTS_CERT_TMP" "$NTS_KEY_TMP"
	chmod 0640 "$NTS_CERT_TMP" "$NTS_KEY_TMP"
}

hash_nts_files() {
	# Hash the ORIGINAL host-mounted files, not our /tmp copies, so we
	# detect the external renewal.
	md5sum "$NTS_CERT_SRC" "$NTS_KEY_SRC" 2>/dev/null | md5sum
}

render_config() {
	pool_block="$(render_pool_servers)"
	nts_block="$(render_nts_config)"
	sed \
		-e "s#\${GRANDMASTER_HOST}#${GRANDMASTER_HOST}#g" \
		-e "s#\${RATELIMIT_INTERVAL}#${RATELIMIT_INTERVAL}#g" \
		-e "s#\${RATELIMIT_BURST}#${RATELIMIT_BURST}#g" \
		-e "s#\${RATELIMIT_LEAK}#${RATELIMIT_LEAK}#g" \
		-e "s#\${CLIENTLOGLIMIT}#${CLIENTLOGLIMIT}#g" \
		"$TEMPLATE" >"$RENDERED.tmp"
	# Multi-line substitutions can't safely go through sed's s#..#..# above,
	# so splice them in with awk instead.
	awk -v pool="$pool_block" -v nts="$nts_block" '
		{
			if ($0 == "__POOL_SERVERS__") { printf "%s", pool; next }
			if ($0 == "__NTS_CONFIG__") { printf "%s", nts; next }
			print
		}
	' "$RENDERED.tmp" >"$RENDERED"
	rm -f "$RENDERED.tmp"
}

render_config

if [ "$NTS_ENABLED" = "true" ]; then
	copy_nts_files
fi

# Fresh bind mounts (./chrony-data, the chrony-run volume) come up
# root-owned; chronyd runs as chrony:chrony after dropping privs and needs
# to write drift/rtc/nts-dump files and create its command socket.
chown -R chrony:chrony /var/lib/chrony
# chmod as root needs CAP_FOWNER (dropped by compose) unless root owns the
# dir, and on restarts the persistent volume is already chrony-owned. Take
# it back with CAP_CHOWN, set the mode, then hand it to chrony.
mkdir -p /run/chrony
chown root:root /run/chrony
chmod 0750 /run/chrony
chown chrony:chrony /run/chrony
# The volume persists across restarts, so a stale pid file/socket from an
# unclean stop survives; in a fresh pid namespace the recorded pid often
# exists, making chronyd refuse to start ("Another chronyd may already be
# running"). Nothing else runs in this container, so they're always stale.
rm -f /run/chrony/chronyd.pid /run/chrony/chronyd.sock

CHRONYD_PID=""

forward_term() {
	if [ -n "$CHRONYD_PID" ]; then
		kill -TERM "$CHRONYD_PID" 2>/dev/null || true
		# Wait for chronyd to actually exit before this script exits, so
		# `docker stop` doesn't tear down the container (and the shared
		# chrony-run volume's socket) out from under a still-running chronyd.
		waited=0
		while kill -0 "$CHRONYD_PID" 2>/dev/null; do
			[ "$waited" -ge 10000 ] && break
			sleep 0.2
			waited=$((waited + 200))
		done
	fi
}
trap forward_term TERM INT

chronyd -d -f "$RENDERED" &
CHRONYD_PID=$!

if [ "$NTS_ENABLED" = "true" ]; then
	# chrony 4.5 cannot hot-reload ntsservercert/ntsserverkey ("chronyd
	# needs to be restarted in order to load a renewed certificate" -
	# chrony-project.org/doc/4.5/chrony.conf.html; chronyc rekey only
	# reloads externally-managed NTS server keys, not this TLS cert/key
	# pair). So on change we just exit and let `restart: unless-stopped`
	# bring chronyd back up with the new files. NTS-KE cookies survive via
	# ntsdumpdir.
	if ! command -v inotifywait >/dev/null 2>&1; then
		echo "entrypoint: inotifywait not found (inotify-tools missing from image)" >&2
		kill -TERM "$CHRONYD_PID" 2>/dev/null || true
	else
		(
			prev_hash="$(hash_nts_files)"

			check_and_restart() {
				if ! kill -0 "$CHRONYD_PID" 2>/dev/null; then
					exit 0
				fi
				cur_hash="$(hash_nts_files)"
				if [ "$cur_hash" != "$prev_hash" ]; then
					echo "entrypoint: NTS cert/key changed, restarting chronyd to load it"
					copy_nts_files
					kill -TERM "$CHRONYD_PID" 2>/dev/null || true
					exit 0
				fi
			}

			# inotifywait on a symlink follows it to the archive/ inode,
			# which certbot never touches again after the swap - so watch
			# the containing directories instead (create/moved_to/etc.)
			# and keep the md5sum compare as the authoritative test;
			# inotify events here are only a wake-up.
			watch_dirs="$(dirname "$NTS_CERT_SRC")"
			resolved_dir="$(dirname "$(readlink -f "$NTS_CERT_SRC" 2>/dev/null)" 2>/dev/null || true)"
			if [ -n "$resolved_dir" ] && [ -d "$resolved_dir" ] && [ "$resolved_dir" != "$watch_dirs" ]; then
				watch_dirs="$watch_dirs $resolved_dir"
			fi

			# Run once up front to close the race between prev_hash above
			# and inotifywait actually starting to watch.
			check_and_restart

			set +e
			inotifywait -m -q -e create,moved_to,delete,delete_self,attrib,close_write $watch_dirs |
				while read -r _; do
					sleep 2
					check_and_restart
				done
			# Reached only if the pipeline exits on its own (inotifywait
			# died, etc.) without check_and_restart having exited us -
			# that's a watcher failure, not a clean shutdown.
			if kill -0 "$CHRONYD_PID" 2>/dev/null; then
				echo "entrypoint: NTS cert/key watcher exited unexpectedly" >&2
				kill -TERM "$CHRONYD_PID" 2>/dev/null || true
			fi
			exit 0
		) &
	fi
fi

set +e
wait "$CHRONYD_PID"
STATUS=$?
set -e
exit "$STATUS"
