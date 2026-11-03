#!/usr/bin/env bash
# Executed ONLY inside a GitHub-hosted Linux runner container, never locally.
set -euo pipefail
umask 077
BOOT_STAGE=IMAGE_KEY_CONTRACT
trap 'code=$?; set +e; printf "R33_BOOT_FAILURE_%s\n" "$BOOT_STAGE"; for log in /tmp/init.log /tmp/start.log /tmp/server.log /tmp/helper-error.log; do if test -f "$log"; then for marker in "Permission denied" "invalid secret key" "does not exist" "Read-only file system" "could not load library"; do if grep -Fq "$marker" "$log"; then case "$marker" in "Permission denied") echo R33_BOOT_PERMISSION_DENIED;; "invalid secret key") echo R33_BOOT_INVALID_KEY;; "does not exist") echo R33_BOOT_MISSING_PATH;; "Read-only file system") echo R33_BOOT_READ_ONLY_PATH;; "could not load library") echo R33_BOOT_LIBRARY_MISSING;; esac; fi; done; fi; done; exit "$code"' ERR
# Verify the actual pinned image helper before creating the disposable key.
key_helper="$(pg_config --sharedir)/extension/pgsodium_getkey"
test -x "$key_helper"
key_real="$(readlink -f "$key_helper")"
key_file=/etc/postgresql-custom/pgsodium_root.key
grep -Fq "$key_file" "$key_real"
test -w /etc/postgresql-custom
BOOT_STAGE=KEY_SETUP
# Synthetic random key, never a hosted key. This directory is a bounded tmpfs
# owned by the postgres UID/GID discovered from this exact image.
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$key_file"
chmod 600 "$key_file"
provided_key="$("$key_helper" 2>/tmp/helper-error.log)"
test "${#provided_key}" -eq 64
cmp -s <(printf '%s' "$provided_key") "$key_file"
unset provided_key
helper_sha="$(sha256sum "$key_real")"
printf '%s\n%s\n%s\n' "$key_file" "$key_real" "${helper_sha%% *}" >/tmp/R33_IMAGE_KEY_CONTRACT
BOOT_STAGE=INITDB
initdb -D /tmp/r33-data -U r33_isolated_restore --auth=trust --encoding=UTF8 --no-locale >/tmp/init.log 2>&1
cat >>/tmp/r33-data/postgresql.conf <<'CONF'
listen_addresses=''
unix_socket_directories='/tmp'
shared_preload_libraries='supabase_vault,pg_stat_statements'
max_locks_per_transaction=512
CONF
printf "vault.getkey_script='%s'\n" "$key_helper" >>/tmp/r33-data/postgresql.conf
BOOT_STAGE=POSTGRES_START
pg_ctl -D /tmp/r33-data -l /tmp/server.log -w start >/tmp/start.log 2>&1
trap 'pg_ctl -D /tmp/r33-data -m fast -w stop >/dev/null 2>&1 || true' EXIT
touch /tmp/R33_READY
while test ! -f /tmp/R33_STOP; do sleep 1; done
