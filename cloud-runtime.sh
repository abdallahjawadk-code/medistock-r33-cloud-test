#!/usr/bin/env bash
# Executed ONLY inside a GitHub-hosted Linux runner container, never locally.
set -euo pipefail
umask 077
BOOT_STAGE=INITDB
trap 'set +e; printf "R33_BOOT_FAILURE_%s\n" "$BOOT_STAGE"; for log in /tmp/init.log /tmp/start.log /tmp/server.log; do if test -f "$log"; then for marker in "Permission denied" "invalid secret key" "does not exist" "Read-only file system" "could not load library"; do if grep -Fq "$marker" "$log"; then case "$marker" in "Permission denied") echo R33_BOOT_PERMISSION_DENIED;; "invalid secret key") echo R33_BOOT_INVALID_KEY;; "does not exist") echo R33_BOOT_MISSING_PATH;; "Read-only file system") echo R33_BOOT_READ_ONLY_PATH;; "could not load library") echo R33_BOOT_LIBRARY_MISSING;; esac; fi; done; fi; done' ERR
initdb -D /tmp/r33-data -U r33_isolated_restore --auth=trust --encoding=UTF8 --no-locale >/tmp/init.log 2>&1
# Disposable test root key only. No existing encrypted Vault secret is claimed
# decryptable with this key. Hosted Vault must be empty before backup proceeds.
BOOT_STAGE=KEY_SETUP
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >/tmp/vault-root.key
printf '#!/bin/sh\ncat /tmp/vault-root.key\n' >/tmp/get-vault-key
chmod 700 /tmp/get-vault-key
cat >>/tmp/r33-data/postgresql.conf <<'CONF'
listen_addresses=''
unix_socket_directories='/tmp'
shared_preload_libraries='supabase_vault,pg_stat_statements'
vault.getkey_script='/tmp/get-vault-key'
max_locks_per_transaction=512
CONF
BOOT_STAGE=POSTGRES_START
pg_ctl -D /tmp/r33-data -l /tmp/server.log -w start >/tmp/start.log 2>&1
trap 'pg_ctl -D /tmp/r33-data -m fast -w stop >/dev/null 2>&1 || true' EXIT
touch /tmp/R33_READY
while test ! -f /tmp/R33_STOP; do sleep 1; done
