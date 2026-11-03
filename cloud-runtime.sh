#!/usr/bin/env bash
# Executed ONLY inside a GitHub-hosted Linux runner container, never locally.
set -euo pipefail
umask 077
initdb -D /tmp/r33-data -U r33_isolated_restore --auth=trust --encoding=UTF8 --no-locale >/tmp/init.log 2>&1
# Disposable test root key only. No existing encrypted Vault secret is claimed
# decryptable with this key. Hosted Vault must be empty before backup proceeds.
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
pg_ctl -D /tmp/r33-data -l /tmp/server.log -w start >/tmp/start.log 2>&1
trap 'pg_ctl -D /tmp/r33-data -m fast -w stop >/dev/null 2>&1 || true' EXIT
touch /tmp/R33_READY
while test ! -f /tmp/R33_STOP; do sleep 1; done
