# Retained model sets

Available in the unreleased 0.28.0-rc.3 candidate. This feature does not enroll
production, qualify a detector or authorize delivery actions. Use **Filters →
Model files → Retained model sets** on an enrolled coordinator.

## Operator workflow

1. After a coordinated release, name and **Retain installed models**. This copies
   the actual installed model files, including encoder files and any validation
   reports. It does not read replacement installation files or save a policy.
2. Replace or disable detectors through the normal coordinated settings workflow.
   Explicitly retained sets survive cleanup of active/previous rollout caches.
3. To restore model files, edit the desired filtering draft, then select **Preview
   for this draft** beside a retained set. The preview verifies every retained
   byte and shows the effective logical slots against the installed set.
4. Review the shadow candidate as well as the model hashes. Selection includes
   that retained candidate, or its explicit absence. It remains observation only.
   Unselected retained detector files do not enable disabled detectors.
5. Choose **Use this retained set in the next save**, review and save settings.
   This stages a new revision; every MX must load and validate it before release.
   Clearing the selection restores the ordinary draft without changing its
   original shadow-candidate choice. Editing the draft invalidates the selection.
6. **Remove retained copy** deletes only that catalog entry. It does not remove
   models already frozen into a staged rollout, installed models or accepted
   receipt records. Retain needed recovery sets before deleting their last copy.

Selection preserves the current draft's rules, thresholds, recipient preferences,
provider settings and pinned credentials. It does not restore the historical
configuration associated with the model. Machine-local capabilities must still
be installed; the catalog is not a way to install a missing encoder runtime or
external service. Incompatible models/settings fail preparation and keep SMTP
fenced until corrected or aborted. Existing observation and Proton gates apply.

## Qualification is separate from retention

Every preview reports `whole_pipeline: not_evaluated`. A digest identifies bytes;
it does not prove detection quality. When a fusion model and validation report
are present, the preview also checks the existing model-bound report contract,
including expiry and its declared counts/latency limits. Possible results are
`not_applicable`, `missing`, `report_contract_valid` and `invalid_or_stale`.

A valid report contract is not an independent audit of its source evidence, a
whole-pipeline qualification or a compatibility guarantee for the current draft.
Preparation and inference keep the existing model/artifact and expiry checks.
No report is fabricated from Rspamd agreement, retention dates or regression tests.
Independent evaluation and model promotion remain separate release gates.

## Storage and limits

Explicit retention creates private files under
`data_dir/cluster/model-catalog/<id>/`. The bounded manifest names logical slots,
file sizes/hashes, source build/revision, retention time, label and optional
managed shadow reference. It contains no provider key or credential generation,
recipient rules, routing configuration, original source path or message content.
The identity binds the source build, logical file manifest and shadow reference.
Retaining the same identity again is idempotent and keeps the original label.

Copies are streamed, hashed, synced and published through a directory rename.
Changed sources fail without publishing a partial entry. Catalog paths and file
types are constrained; symlinked files/directories are refused. Reads and
mutations share the controller's operation limit with policy preparation, and
owned copy/hash tasks retain it after their HTTP caller disconnects.

The current bounds are 16 retained sets, 8 GiB of declared retained file bytes,
768 MiB per set, 512 MiB per file and 32 logical files per set. The installation's
free-space reserve also applies. Capacity refusal never evicts another set.
Interrupted `.stage-*` directories can require operator cleanup after a process
crash; do not remove a staging directory while its operation is live.

The catalog is coordinator-local and must be included in its backups. It is not
replicated catalog storage or console failover. A selected draft copies its exact
files into ordinary immutable rollout storage before publishing the activation
journal. Worker downloads and restart therefore do not depend on the catalog or
the original installation/research source files after staging.

## Administrator API

These routes require an administrator session; POST requests also require the
existing origin/CSRF checks. Node credentials and personal accounts cannot select
or retain catalog models. Mutations recheck the approving session in the owned
controller operation. Ordinary settings/preference saves never auto-enroll a
cluster, retain a set or choose a catalog entry.

- `GET /api/v1/admin/cluster/models/catalog`: bounded entry metadata and limits.
- `POST /api/v1/admin/cluster/models/catalog`: `{revision, label}` retains the
  released installed set. The source revision must still be current.
- `POST /api/v1/admin/cluster/models/catalog/preview`:
  `{revision, settings, id}` returns the verified draft manifest and its
  `installation_sha256`, `quality_candidate` and qualification diagnostics.
- `POST /api/v1/admin/config`: supply `catalog_models: {id, sha256}` and the
  preview's `quality_candidate` in `settings`. `sha256` is the preview's effective
  model digest. Supplying both this selection and `installation_models_sha256`
  is refused. A stale revision, missing entry, corrupt file or changed effective
  manifest is refused; the active settings are not silently replaced.
- `POST /api/v1/admin/cluster/models/catalog/remove`: `{id}` removes the retained
  copy under the same operation serialization as staging.

Retention and removal append administrator audit events. Browser errors do not
include private filesystem paths or provider responses; operational details are
recorded in server logs. Selection uses the existing staged configuration audit
and the receipt-time model/policy identities after coordinated release.
