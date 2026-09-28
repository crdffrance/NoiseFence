# Retiring a restored console after planned handoff

Use this procedure only after arranging the replacement management authority and
reviewing the final checkpoint received by the replacement. It archives the old
console locally. It does not promote the replacement, restart SMTP, re-enrol a
worker or migrate a PostgreSQL database.

1. Run `fence.py --recovered-console` on the old restored source. Require a completed
   receipt and keep all its service fences in place.
2. Run `standby.py push --recovered-console` manually and verify the destination and
   exact snapshot UUID in root-private `last-transfer.json`. The final export must
   have started after the completed fence.
3. Install the matching root-owned `deploy/ha/retire.py` beside `standby.py` and
   `fence.py`, then invoke it with the reviewed snapshot UUID:

   ```sh
   sudo python3 /usr/local/libexec/noisefence-ha/retire.py --snapshot <final-snapshot-uuid>
   ```

The helper takes the upgrade and checkpoint transport locks. It requires an exact
source configuration, fencing operation and final transfer receipt; it checks
that every installed writer/timer is stopped and still persistently fenced.
`active` and `promoted.json` move into root-private
`/var/lib/noisefence-standby/retired/<fence-operation>/`, alongside the final receipts
and a durable retirement journal. Interrupted renames can be retried with the
same snapshot. Existing archives are never overwritten or deleted.

The local worker queue is untouched. The PostgreSQL database is retained, as are
its role and the original recovery journals. The root-level fence remains in
place. Removing the active promotion marker permits checkpoint reception; it does
not permit an old console or worker to resume. Incoming checkpoints must still
pass the normal authority, integrity, build and ordering checks.

Do not remove service fences to restart a retired installation. A subsequent
promotion or worker return requires fresh coordinated authorization, current keys
and authority reconciliation. For a newly prepared console on the retired host,
use the [guard replacement procedure](RECOVERY-REENTRY.md). An archived console configuration still references
its former live path and must not be used as a startup configuration. Keep the
archive private until a reviewed backup/retention decision allows its removal;
this tool never purges recovery material.

## Verification

The Debian VM rehearsal archived a stopped, authorized restored console after its
verified final checkpoint transfer. The worker SQLite file had the same SHA-256
before and after retirement, and repeating retirement returned the same result.
The retired source then accepted that valid checkpoint through the real receiver
implementation while preserving the worker file and root-level service fence.
Unit tests also interrupt the two renames and verify a safe retry. These checks
establish retirement and reception behavior; they do not authorize a subsequent
promotion or demonstrate a new production management authority.
