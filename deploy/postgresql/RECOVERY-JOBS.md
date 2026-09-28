# Background work after console recovery

The worker and recovered console have separate data directories on the surviving
MX. Research must use the recovered console configuration and PostgreSQL authority.
Do not restart the old training or quality units against the worker's directory.
The original coordinator must remain fenced throughout this procedure.

The bundled `noisefence-recovered-quality` and `noisefence-recovered-train` units
use `deploy/recovered-job.py`. Every run checks native console authorization,
requires selected PostgreSQL management and resolves the worker and training
scripts from the same installed release. Candidates and reports stay under
`/var/lib/noisefence-standby/active/data`; temporary feature exports use private
systemd runtime directories. Neither job activates a model automatically.

PostgreSQL's research session lock prevents two quality runners from claiming jobs
at once. Training additionally uses the candidate directory lock. These locks do
not replace fencing of the previous database host. An old database copy must never
be left serving another coordinator.

## Installation and activation

Complete and verify the runtime recovery first. Install the matching release,
including `deploy/recovered-job.py`, `deploy/quality-worker.py`,
`deploy/train-feedback.py` and their `research/` dependencies. The training Python
environment configured in `/etc/noisefence/training.env` must be installed on the
surviving host too; it is not part of the console checkpoint.

Install the two recovered `.service` and `.timer` pairs from `deploy/ha/` under
`/etc/systemd/system`, root-owned mode 0644. Then run as root:

```sh
systemctl disable --now noisefence-train.timer noisefence-quality.timer
systemctl stop noisefence-train.service noisefence-quality.service
systemctl daemon-reload
systemctl start noisefence-recovered-quality.service
journalctl -u noisefence-recovered-quality.service --no-pager -n 20
```

A successful quality run reports `idle` when no job is queued, or processes an
eligible administrator job. Inspect failures before enabling the timer:

```sh
systemctl enable --now noisefence-recovered-quality.timer
```

Enable weekly training only if it was intended before recovery and the training
runtime is present. Run the service once and inspect its aggregate
`active/data/models/last-training.json` result before enabling its timer. A failed
or insufficient-feedback result never replaces the active model.

Both services require the promotion marker and refuse new starts while a recovery
installation hold or coordinator fence is present. The recovery installer stops
these services and timers before changing authority. They run without network
access, use a local PostgreSQL Unix socket, and are limited to one CPU and 1 GiB
of memory so research cannot consume all surviving MX resources.

## URL-feed ownership

URL reputation feed files belong to each SMTP worker's local
`data_dir/protection/url-feed.json`. Keep `noisefence-url-feed.service` directed at
that worker directory; do not point it at restored management storage. Restore its
licensed feed environment and enable its normal timer only on the intended worker
hosts, after their recovery hold is released. Research isolation does not prevent
the feed updater from making its explicitly configured HTTPS request.

## Validation limits

Local regression tests verify configuration selection, authority checks, output
paths and service guards. The recovered quality unit has also completed a real
systemd run against the restored synthetic PostgreSQL database in Debian 13,
with `PrivateNetwork=yes`, the unprivileged account and the 1 GiB memory limit.
A subsequent rehearsal queued training through the authenticated Web API on
1,020 synthetic labelled observations. The real systemd worker exported the
selected PostgreSQL sample, fitted a candidate, passed native Rust/Python
prediction parity and stored the completed result without activating the model.
That run took approximately 17 seconds and peaked at 126 MiB in the test VM.
It used Debian's Python 3.13 scientific packages (NumPy 2.2.4, SciPy 1.15.3 and
scikit-learn 1.4.2); it does not replace verification of the separately pinned
production training environment. Synthetic accuracy is not a filtering benchmark.
Recovery does not recreate missing training dependencies or infer
which optional jobs the administrator intended to enable; review those settings
before scheduling work. Original mail archives are not present in console
checkpoints, so jobs requiring missing local inputs can still fail explicitly.
