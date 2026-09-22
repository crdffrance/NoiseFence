# Coordinated policy and model activation

Implementation in progress, not an enable-ready deployment feature. The durable
authority state machine, participant runtime driver and SMTP acceptance barrier
are implemented and tested locally. The authenticated network/controller loop,
administrator workflow and automatic authority commit are not connected yet.
Legacy Web configuration and cluster-v1 synchronization remain unchanged on
unenrolled storage. Do not manually enroll production databases.

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

The local driver is `Controller::synchronize_activation`. Its caller must
authenticate the authority before passing the directive. It owns its persistence
and runtime swap even when its caller disconnects. No HTTP route currently calls
it; it is not a replacement for authentication or coordinator orchestration.

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
epoch. Startup materializes the installed bundle and checks its model hashes,
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

- Wire authenticated, versioned prepare/applied/release exchanges to the worker
  poller and authority loop; legacy poll success is not a readiness receipt.
- Stage immutable active/pending model files on all participants, retain recovery
  artifacts and bound the number of resident model generations.
- Commit console revisions and authority state atomically with session/ACL checks;
  show pending versus active revisions, progress, abort and recovery in English.
- Define membership changes, revocation, upgrade negotiation and console recovery
  for enrolled clusters, without silently bypassing missing participants.
- Carry the activation identity through canonical receipt/header diagnostics and
  qualify real SMTP, two-copy replication and failover as one deployed pipeline.
- Exercise network partitions, lost HTTP replies and process crashes across the
  complete transport, followed by reference-hardware throughput/latency tests.

The local tests cover real controller/model loading, partial application,
recovery, restart, corruption, SMTP deferral and uncancellable disk acceptance.
They do not establish that a deployed two-MX coordinated rollout is complete,
nor measure spam capture or false positives. Production observation, Proton
marking prerequisites and independent model qualification remain in force.
