# Coordinated policy and model activation

Implementation in progress; production rollout is not yet qualified. Durable
authority/participant journals, runtime preparation, SMTP fences, authenticated
cluster-v2 exchange and the authority loop are implemented. Administrator APIs
stage, inspect, abort and recover rollouts. The English Web console now exposes
these operations and routes normal settings/personal-preference saves through
coordination after enrollment. Full deployment qualification remains open.
Legacy Web configuration and cluster-v1 synchronization remain unchanged on
unenrolled storage. Enrollment is explicit, never triggered by an ordinary save.
Do not manually enroll production databases before the remaining gates pass.

## Safety contract

A rollout binds a monotonically increasing epoch to one immutable policy/model
bundle and a fixed participant set, including the coordinator. Preparation does
not activate the candidate. Each participant must stop new acceptance, drain
ongoing durable acceptance writes, verify model bytes, and load the candidate
engine before returning a prepared receipt for that exact epoch.

The authority may commit only after all participants are prepared. Its caller
must write the console revision in the same SQLite transaction as that commit.
The participant driver persists the installed bundle and journal before swapping
the runtime. It remains fenced and acknowledges application. The authority can
release admission only after every participant has applied. Replayed receipts
cannot downgrade readiness; stale or conflicting directives cannot reopen an old
policy. No timeout or absent participant counts as successful preparation.

The local driver is `Controller::synchronize_activation`. The worker authenticates
the authority through its configured HTTPS origin; the server authenticates the
worker with the separately revocable node credential. The v2 poller calls the
local driver and returns its volatile runtime receipt on the next exchange. A
stored flag is never sent as readiness immediately after restart. The driver owns
persistence and runtime swap even when its caller disconnects.

The authority loop prepares its own runtime and advances the same journal as the
workers. It inserts the console revision, audit record and activation commit in
one transaction. The stage request checks a live administrator session and CSRF;
commit rechecks the approving account's enabled administrator role and privilege
version. Natural session expiry does not revoke an already authorized job, but
an account/privilege change prevents its commit. Another administrator can abort
before commit or authorize the exact prior-policy recovery after partial commit.

## Authenticated exchange and immutable models

`POST /api/v1/cluster/v2/sync` wraps the existing metadata/budget exchange and adds
an explicit `noisefence-activation-1` protocol and an optional exact-epoch receipt.
It authenticates node credentials again in the transaction that changes readiness.
Fresh v2 capability reports and matching base revision/digest are required from
every enabled worker before staging. A legacy successful synchronization is not
a preparation receipt. Enrolled authorities refuse cluster-v1 policy exchanges.
A new worker falls back to v1 only on a missing v2 endpoint (404, or the 405
returned by older static-file router fallbacks); an enrolled worker
cannot downgrade or accept an authority that lost its activation state.

Models are streamed and hashed into content-addressed directories before a
proposal becomes durable. The v2 artifact endpoint serves only files named in the
current/base/candidate manifests to enrolled node identities. The worker verifies
size and digest before renaming/syncing each file and loading the engine. Source
files can disappear after staging without changing the published bytes. Model
pruning explicitly retains active, pending and recovery manifests. CLI policy
loading also uses the installed cached bundle, including on the coordinator.

A missing participant or network error never substitutes for a readiness receipt.
An old receipt can be ignored after a newer epoch supersedes it; a conflicting or
future receipt is rejected. Losing a release reply does not prevent a subsequent
prepare whose base exactly matches the participant's durably installed epoch.
An abort received before the participant's first preparation installs only the
verified unchanged base and never claims to have prepared the cancelled candidate.

## Administrator API

All browser operations use the existing administrator session and CSRF checks.
Node credentials cannot invoke them. The MX servers and settings pages expose:

- `GET /api/v1/admin/cluster/activation`: authority state, `installed_revision`,
  `committed_revision` and SMTP readiness. An installed runtime may still be fenced
  while other participants apply; only a released phase permits new acceptance.
- `POST /api/v1/admin/cluster/activation`: stage `{revision, settings}` against the
  exact currently active revision. Returns a staged proposal, not active settings.
- `POST /api/v1/admin/cluster/activation/abort`: `{epoch}`, before commit only.
- `POST /api/v1/admin/cluster/activation/recover`: `{epoch}`, after a partial commit;
  creates a higher revision restoring the exact previous policy and models.

The fixed membership must continue to match enabled registered nodes. Revocation
is honored immediately at the exchange boundary and blocks further activation;
it does not silently remove a missing participant from the barrier. Adding or
removing participants from an enrolled cluster needs the remaining membership
workflow. Existing staged rollouts are never automatically promoted by old-style
configuration saves.

## Web saves and scoped preferences

The MX servers page offers explicit enrollment with the current settings. Before
that action, ordinary saves retain their existing behavior. Once enrolled,
`POST /admin/config` and `POST /preferences` return `{revision, staged: true}`;
the revision is proposed, not yet active. Immediate legacy saves return
`staged: false`. Concurrent or stale proposals are refused, not silently merged.
The frontend preserves unsaved drafts and refreshes installed settings after a
completed change. Preparation, central commit, local installation and permission
to resume SMTP are distinct states. An `applied` participant acknowledgement is
not proof that it has already received the release directive.

`GET /admin/cluster/activation/view` is a compact administrator projection with
participant progress, installed/committed/proposed revisions, local SMTP readiness,
and available abort/recovery actions. It remains readable while preparation waits
for an ongoing durable SMTP write. The UI polls without overlapping background
requests, rejects superseded responses and disables saves on unknown/stale status.
The legacy detailed journal endpoint remains available to administrators only.

`GET /preferences/activation` returns progress without bundles, model hashes,
participant identities, other recipients or approving-account names. It includes
one personal change only when the viewer submitted it and still has access to
that scope. Scope visibility is rechecked in the database. HTTP session and CSRF
checks apply to preference mutations, followed by another session/grant check
inside the staging transaction.

A delegated proposal can modify exactly one mailbox/domain preference entry.
It cannot change administrator rules, global limits, models or other recipients.
Before commit, the authority verifies the exact delta against the immutable base,
checks the account is enabled, checks its privilege version, and rechecks the
current grants. Natural session expiry after approval does not cancel a durable
job; account/privilege revocation prevents commit. Another administrator can
cancel it before commit or restore the previous policy after partial commit.

Authority-step failures persist a bounded incident tied to its epoch. Safe codes
identify approval, membership or runtime-preparation failures; unclassified errors
use a generic code. Private provider/model error strings remain in server logs.
Successful progress clears the incident; a newer epoch does not display an older
failure. A user can see the generic incident only for their still-authorized own
proposal. Browser rendering is separately tested for escaping and scoped display.

## Explicit model selection

Ordinary coordinated settings and personal saves retain the installed model
slots, rebased to their immutable manifest files. They neither re-read old
installation files nor silently adopt replacements at those paths. An unchanged
managed shadow candidate uses its cached bytes; an explicit empty candidate
selection disables it. Dropping its selection metadata alone is refused rather
than misrepresenting the still-installed candidate.

The English Filters → Model files section previews the installation files for the
current draft via `POST /admin/cluster/models/preview` with `{revision, settings}`.
This requires an administrator session and CSRF. The response names logical model
slots, sizes and SHA-256 hashes, including validation reports and encoder files;
it does not expose filesystem paths. Identity is stable when internal capture
filenames change. `qualification: not_evaluated` is explicit: hashing does not
establish filtering accuracy, and the existing validation/Proton gates still apply.

After reviewing the preview, the administrator can add
`installation_models_sha256` to the ordinary `/admin/config` save. The server
requires enrolled coordination, re-reads the draft's configured installation
models, verifies that their complete logical manifest matches the preview digest,
and freezes the exact bytes before staging. Changed files are refused until
previewed again. Personal preferences cannot submit this option. Model selection
alone creates a visible unsaved draft even when policy parameters are unchanged.
Edits to the draft/revision invalidate that selection; stale preview requests are
cancelled. Preparation on every MX still loads and validates the chosen runtime
before any policy commit or SMTP release.

The calibration workbench's shadow-candidate selection and removal also stage a
coordinated revision after enrollment, preserving their observation-only role.
Its UI shows pending activation and refreshes the installed selection after release.

This is explicit installed-versus-installation selection, not a complete retained
artifact catalog. Disabling a detector omits its files from the new bundle; later
re-enabling a missing model requires an explicit installation selection. Arbitrary
model uploads, independent qualification records for selectable model sets and
long-lived selection of inactive historical artifacts remain future catalog work.
A newer managed shadow candidate still requires its referenced research file and
matching digest; an unavailable new candidate never falls back to the old one.

## SMTP and queue behavior

MAIL receives `451 4.3.2` while admission is fenced. A transaction begun before
the fence retains its engine and epoch; acceptance checks that epoch again after
DATA. An old-policy transaction cannot enter the durable queue after a newer
epoch has resumed. Queue batches cannot mix epochs.

The acceptance lease follows the owned disk/SQLite write, including when its
asynchronous caller is cancelled. Waiting for a fence cannot mistake that
cancelled caller for a completed write. The barrier does not wait for already
accepted messages to be delivered, nor does it rescan or delete their receipts.
Two-copy requirements remain independent. SMTP retries and the existing possible
duplicate after a lost final response are unchanged.

## Restart and rollback

Participant storage retains both the authority view and the locally installed
epoch. If staging became durable before the authority prepared its own participant
journal, startup uses its frozen base bundle. Otherwise startup materializes the
installed bundle and checks its model hashes,
but always keeps admission closed. A verified matching release/abort is needed
to reopen. A missing/corrupt model cannot earn a prepared receipt. A released
journal alone is not evidence that the resident engine has loaded correctly.

Before commit, abort restores admission on the unchanged base epoch. After
commit, abort is forbidden: some nodes may have installed the candidate. Recovery
is a new, higher epoch/revision restoring the exact previous settings and model
manifest with the same participant set. It goes through prepare/apply/release and
cannot be aborted back into a mixture of policies.

Enrolled databases use format 6. Older binaries must refuse this format instead
of ignoring the fence. MFA, replication and cluster initialization preserve a
newer database format rather than lowering it. Missing or identity-mismatched
journals fail startup. Downgrading `user_version` is not a rollback procedure.

## Remaining integration and qualification

- Finish the retained/qualified artifact catalog and credential-update workflows.
  Installed model retention and explicit digest-bound installation selection work
  as described above; inactive historical models are not a retained catalog.
- Bound resident model generations retained by old SMTP analyses, not just disk
  manifests; measure work and memory on the reference hardware.
- Define membership changes, upgrade negotiation and console recovery for enrolled
  clusters, without silently bypassing revoked or missing participants.
- Carry activation identity through canonical receipt/header diagnostics.
- Qualify actual process crashes, concurrent SMTP/two-copy replication, deployment
  upgrades and console failover together, then measure throughput and latency.

Local network tests run real HTTP authority/worker loops, immutable model transfer,
revoked admin and personal-scope permissions, normal Web saves, scoped status,
nonblocking progress during durable-write draining, partition after partial application, lost responses,
early abort, missing release and higher-revision recovery. They also verify cached
runtime/CLI restart when original model files have disappeared. Earlier tests
cover real SMTP epoch crossing and uncancellable durable disk acceptance. These
are software consistency tests, not measured spam capture or false-positive rates.
Production observation, Proton prerequisites and independent model qualification
remain in force.
