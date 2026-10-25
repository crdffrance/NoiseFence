# Coordinated retained-release activation

The development tree provides an explicit two-node rollback protocol. It can
activate only the exact original release of a completed paired upgrade, after a
new maintenance validation against the **current** database, policy and queues.
It never restores a database snapshot or rewinds accepted-message generations.

This is an operator procedure, not an unattended updater. Production use requires
a passing native rehearsal for the exact two archives, architectures and installed
security profiles. Unit tests or a shared storage format are insufficient. The
published 0.31.9 binary lacks the maintenance command and cannot pass this gate.
The rc.3 candidate is intended for a positive rehearsal with the
immutable rc.2 archive; that pair is not qualified merely by naming it here.

## Prerequisites

Keep the prior upgrade's complete reports from both MXs and its retained release
directories. Verify the current administrative tooling and both archives. Reserve
both MXs under a new, common operation UUID, then follow the
[retained identity and maintenance validation procedure](paired-upgrades.md#validate-a-retained-runtime-without-activating-it).
Leave both validators running and require fresh readiness from each one.

Use root-owned, private files and authenticated administrator channels to exchange
reports. The restricted forward-upgrade SSH completion helper does not accept
rollback reports. Never rename a protocol field to work around that boundary.

The retained history binds the previous upgrade's proposal and decision, both
completion reports, the current installed archive, retained archive, node identity,
authority selection, configuration, policy and service definitions. An old
completion report alone cannot authorize this operation. A changed binding or
expired authorization blocks new preparation and activation.

## Prepare and commit the pair

Run the following helper from verified current tooling, with the new reservation
UUID as `OPERATION` and `umask 077`. Save each result under a fresh private filename.

```sh
python3 /usr/local/libexec/noisefence-management/rollback_promotion.py prepare \
  --operation "$OPERATION" > /root/retained-prepared.json
```

Prepare **both** nodes while their validators are ready. Exchange their reports.
On each MX, promote using the other node's prepared report:

```sh
python3 /usr/local/libexec/noisefence-management/rollback_promotion.py promote \
  --operation "$OPERATION" --peer-report /root/peer-retained-prepared.json \
  > /root/retained-promoted.json
```

Promotion stops the validator and changes only the release pointer. Normal SMTP,
relay, administration and auxiliary jobs remain held. Both nodes must use the
same retained application version and source commit; architecture-specific
archive hashes may differ and remain bound to their respective nodes.

Use `rollback_activation.py` for the subsequent actions, in this order:

| Action | Node | Peer report required |
| --- | --- | --- |
| `arm` | Coordinator | Worker's retained promoted report |
| `arm` | Worker | Coordinator's retained armed report |
| `decide --outcome activate` | Coordinator | Worker's retained armed report |
| `accept` | Worker | Coordinator's retained decision |
| `start` | Both | Other node's accepted/decided retained report |
| `check` | Both | Other node's retained started report |
| `verify` | Both | Other node's fresh retained runtime proof |
| `finish` | Both | Other node's retained verified or completed report |

Every invocation needs `--operation "$OPERATION"`; report-consuming actions also
need `--peer-report /root/PEER-REPORT.json`. The detailed state transitions follow
the [paired activation procedure](maintenance-activation.md), using the retained
helper and its distinct reports throughout. The ordinary forward helper still
refuses new downgrades and cannot consume these reports.

`check` verifies the actual retained executable, SMTP readiness, a new authenticated
policy exchange, a fresh peer heartbeat and zero unprotected or pending message
generations. `verify` binds both proofs. Auxiliary jobs stay fenced until both
nodes have verified the committed pair. A `complete` receipt describes a completed
operation; use fresh health checks for current availability.

## Interrupted operations

Use `status --operation "$OPERATION"` to read durable progress. Retrying the same
action with the same report recovers lost replies. Do not create another operation
while the previous one owns a reservation.

Before either activation promise, `rollback_promotion.py restore` restores the
previously running newer release. Once both nodes are restored, exchange those
reports, run `release` on both, then cancel the reservations. If one node never
prepared, `abandon` requires its own retained history and the other node's report;
it does not fabricate a successful validation.

After arming, the coordinator can decide `--outcome abort` only if it has not
already committed activation. The worker accepts that abort, both run `abort`,
then exchange aborted reports and run `cancel`. An accepted activation decision
is immutable: recover the committed retained pair rather than invoking pre-commit
restoration. A later upgrade needs a new operation and fresh validation.

## Native rehearsal

The isolated fixture accepts `--require-retained-activation` together with
`--archive-candidate`. It fails if either retained binary cannot validate the
current state. It exercises actual retained promotion and normal startup, discarded
start/completion replies, unchanged management data before startup, preservation of all accepted
messages, restored timers, new mail acceptance, and a new forward upgrade back to
the exact candidate. The ordinary historical baseline rehearsal remains separate
and continues to verify safe refusal of unsupported retained binaries.

Keep the fixture's private evidence local. Public qualification must identify both
archive hashes, tested commits, architecture, scenarios and verified cleanup;
never publish synthetic credentials or raw fixture directories. A skipped or
unsupported retained probe is not successful rollback qualification.
