# R34 production recovery preparation

This workflow is credential-free preparation, not a backup, restore, qualification of the restored database, deployment or SQL executor. Its only input is the exact automation SHA. `master`, owner and triggering actor, first attempt and a separately configured approved SHA are mandatory. Thirteen SQL sources are reconstructed in memory from the pinned public application and existing accepted transformations; no SQL files, hosted credentials or backups are published.

The environment requires owner review. No secret is referenced by this preparation workflow. Production-only secrets must be entered through GitHub environment settings after review of the actual capture/restore workflow; do not enter any in chat. R2 signup/checkout is completed by the owner; unknown quota, missing secure input or incomplete coverage keeps capture on HOLD. A future reviewed capture/restore implementation must replace the preparation boundary before any Production export. This repository never applies hosted SQL.

The existing R33 synthetic probes and accepted tests remain unchanged. The new tests validate only R34 trust/identity/TLS/quota gates. Passing source preparation does not prove PostgreSQL restoration, Auth, PostgREST, FEFO or backend activation.
