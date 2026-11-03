# MediStock Phoenix R33 — cloud runtime probe only

Owner-authorized phase 1. This repository contains only the manual runtime probe.
No application SQL migrations, database backups, credentials, or GitHub Secrets.
No Staging/Production connections, deployment, Vercel integration, or buckets.

The workflow accepts the exact reviewed automation commit SHA and only runs for
the owner on master through workflow_dispatch on GitHub-hosted Linux.
It checks the pinned official Supabase PostgreSQL image, PostgreSQL 17.11,
supabase_vault 0.3.1, and synthetic create/decrypt/update/decrypt round trips.
The disposable PostgreSQL container has no network, published ports, or persistent
volume. Its root is read-only; data and a newly generated synthetic test root key
exist only in tmpfs and disappear when the container is removed.

No existing Vault secret is decrypted, and no Staging backup/restore is implied
by PASS_RUNTIME_PROBE. Further phases require their separate setup authorization.
