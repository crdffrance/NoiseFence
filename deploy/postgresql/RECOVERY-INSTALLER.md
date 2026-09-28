# Fenced recovery credential installation

`recovery_install.py` is the privileged installation step between native recovery
preparation and verification of installed worker credentials. It does **not**
promote a console, authorize SMTP startup, remove a service fence or start a service.
Protocol-2 promotion still requires its complete supervisor integration and rehearsal.

Install this file together with the matching `migration_agent.py`,
`migration_protocol.py` and `migration_snapshot.py` from the same release in a
root-owned directory. Mixing helper versions is unsupported. Python 3.11 or newer,
Linux, systemd and the existing unprivileged NoiseFence account are required.

The recovery supervisor must publish a private root-owned authorization with these
fields (unknown fields are rejected):

| Field | Required value |
| --- | --- |
| `protocol` | `noisefence-recovery-install-1` |
| `operation` | The canonical recovery UUID |
| `selection` | Exact existing worker management selection, including database and node epoch |
| `config` | Absolute physical path of the protected installed worker configuration |
| `config_sha256` | SHA-256 of its original bytes |
| `bundle_sha256` | SHA-256 of the complete prepared private worker-key JSON file |
| `coordinator_url` | Approved HTTPS console origin, without credentials, path, query or fragment |
| `user` | Existing non-root service account |
| `expires_at` | Unix expiry, no more than one hour in the future |

All authorization/configuration ancestors and credential destination ancestors must
be root-owned and not writable by group or others. The destination key path is read
from the protected installed configuration, never from the key bundle or a service-
writable plan. The installed systemd service must run the authorized account with
exactly `noisefence --config <this-config> serve`. Wrapped/custom startup commands
are refused pending an explicitly supported installation adapter.

```sh
python3 /usr/local/libexec/noisefence-management/recovery_install.py \
  --authorization /etc/noisefence-recovery/install-worker.json \
  --keys /private/recovery/admin.json.workers.json
```

The helper verifies the pinned bundle, recovery/database/node identity and original
configuration, then creates a persistent systemd condition and stops the daemon,
training, URL-feed and quality services and their known timers. It holds the actual
worker's daemon and calibration locks, verifies its durable selection, installs the
key as a private service-owned file and updates only the coordinator URL. It preserves
configuration ownership/mode and records progress privately under
`/var/lib/noisefence-recovery-install`. Files are atomically replaced and synchronized.
No token is included in the result.

A partial installation remains fenced. Retry the same authorization and key bundle;
its expiry may be refreshed, but its pinned identity and contents must not change.
Do not restore an old key or automatically restart the original configuration after
a partial publication. Run native recovery preparation with installed-key verification,
console activation, console health checks and guarded worker release before the
supervisor removes any persistent condition. This helper deliberately does not
implement that final service release or proxy switching.

The local contract suite tests interrupted publication, mismatching keys/identities,
configuration changes, source locks, systemd command mismatch and path redirection.
`tests_python/recovery_install_linux.py` is an explicitly destructive **disposable
container fixture**, not a production diagnostic. It uses a harmless sleep process
as the worker to verify actual root ownership and systemd restart prevention; it
does not test SMTP or the full PostgreSQL recovery.
