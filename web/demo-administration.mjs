import { directoryFixture } from './demo-directory.mjs';
// Disposable browser-memory data only. No mutation reaches a Rust service.
export function administrationFixture(params, base, version) {
  if (!params.has('administration')) return () => null;
  const scenario = params.get('administration');
  const directory = directoryFixture(params, base);
  let revision = 25,
    settings = structuredClone(base),
    saved = false,
    refreshFailure = scenario === 'refresh-failure',
    conflict = scenario === 'conflict',
    pending = false;
  const old = structuredClone(base);
  old.filters.threshold = 98;
  old.actions.quarantine_days = 7;
  old.rbl.minimum_providers = 3;
  const revisions = new Map([
    [24, old],
    [25, structuredClone(base)],
    [0, structuredClone(base)],
  ]);
  const at = Math.floor(Date.now() / 1000),
    audit = [
      {
        created: at - 30,
        username: 'Alex',
        action: 'configuration',
        object: '25',
      },
      {
        created: at - 45,
        username: 'Alex',
        action: 'configuration_staged',
        object: '999',
      },
      {
        created: at - 3600,
        username: 'Alex',
        action: 'configuration',
        object: '24',
      },
      {
        created: at - 86400,
        username: 'Alex',
        action: 'account',
        object: 'demo-user',
      },
    ];
  return (path, options, url) => {
    if (!path.startsWith('/admin/') && path !== '/metrics') return null;
    if (params.get('role') === 'user')
      return Response.json(
        { error: 'Administrator access required.' },
        { status: 403 },
      );
    const directoryResponse=directory.handle(path,options,url,revision,settings);
    if(directoryResponse)return directoryResponse;
    const post = options?.method === 'POST';
    if (path === '/admin/config' && post) {
      const body = JSON.parse(options.body || '{}');
      if (conflict) {
        conflict = false;
        revision++;
        revisions.set(revision, structuredClone(settings));
        return Response.json(
          { error: 'Synthetic concurrent revision. Reload before saving.' },
          { status: 409 },
        );
      }
      if (body.revision !== revision || pending)
        return Response.json(
          { error: 'Synthetic revision conflict.' },
          { status: 409 },
        );
      saved = true;
      const next = revision + 1;
      if (scenario === 'staged') pending = true;
      else {
        revision = next;
        settings = structuredClone(body.settings);
        directory.commit(settings.identity_directory);
        revisions.set(revision, structuredClone(settings));
        audit.unshift({
          created: Math.floor(Date.now() / 1000),
          username: 'Alex',
          action: 'configuration',
          object: String(revision),
        });
      }
      return Response.json({ revision: next, staged: pending });
    }
    if (post) return null;
    if (path === '/admin/config') {
      if (saved && refreshFailure) {
        refreshFailure = false;
        return Response.json(
          { error: 'Synthetic installed-settings refresh failed.' },
          { status: 503 },
        );
      }
      return Response.json({
        memory_key_id: "d".repeat(64),
        revision,
        settings,
        actions: settings.actions,
        rules: [],
        native_rules: [],
        available: base.filters,
        hostname: 'mx.example.test',
        version,
        sensitivity_levels: [],
        threshold_locked: false,
        sensitivity_locked: false,
        tag_ready: false,
        pub_tag_ready: false,
        mailing_available: false,
        max_connections: 100,
        processing: 4,
        relay_workers: 4,
        max_message_bytes: 26214400,
      });
    }
    if (path === '/admin/cluster/activation/view')
      return Response.json({
        coordinator: true,
        coordinated: scenario === 'staged',
        pending,
        installed_revision: revision,
        committed_revision: scenario === 'staged' ? revision : null,
        smtp_ready: !pending,
        phase: pending ? 'preparing' : null,
        epoch: pending
          ? { sequence: 1000, revision: revision + 1, digest: 'a'.repeat(64) }
          : null,
        participants: pending ? { mx1: 'prepared', mx2: 'waiting' } : null,
        abortable: false,
        recoverable: false,
        personal_change: null,
        incident: null,
      });
    if (path === '/admin/revisions') {
      if (scenario === 'revisions-failure')
        return Response.json(
          { error: 'Synthetic revision history unavailable.' },
          { status: 503 },
        );
      return Response.json(
        [...revisions.keys()]
          .sort((a, b) => b - a)
          .map((id) => ({
            id,
            created: at - (25 - id) * 3600,
            username: 'Alex',
          })),
      );
    }
    if (path.startsWith('/admin/revisions/')) {
      const id = Number(path.split('/').at(-1));
      if (scenario === 'history-missing' || !revisions.has(id))
        return Response.json({ error: 'Revision not found.' }, { status: 404 });
      return Response.json(revisions.get(id));
    }
    if (path === '/admin/audit')
      return scenario === 'audit-failure'
        ? Response.json(
            { error: 'Synthetic audit history unavailable.' },
            { status: 503 },
          )
        : Response.json(audit);
    if (path === '/metrics')
      return scenario === 'operations-failure'
        ? Response.json(
            { error: 'Synthetic metrics unavailable.' },
            { status: 503 },
          )
        : Response.json({
            queued_deliveries: 0,
            quarantined_deliveries: 0,
            unnotified_failures: 0,
            oldest_pending_age_seconds: null,
            received_last_hour: 1,
            incomplete_last_hour: 0,
            max_analysis_ms_last_hour: 485,
            disk_available_bytes: 10 * 1024 ** 3,
          });
    if (path === '/admin/queue')
      return scenario === 'operations-failure'
        ? Response.json(
            { error: 'Synthetic queue unavailable.' },
            { status: 503 },
          )
        : Response.json([]);
    return null;
  };
}
