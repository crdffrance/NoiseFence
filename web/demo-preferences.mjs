// Synthetic local fixture only. No configuration or message reaches a server.
export function preferenceFixture(params) {
  let revision = 25,
    saved = false,
    conflict = params.get('preferences') === 'conflict',
    failRefresh = params.get('preferences') === 'refresh-failure';
  const mailboxes = {};
  const base = () => ({
    ordering: 'scoped',
    personal_enabled: true,
    threshold: 98,
    threshold_source: {
      name: 'Domain baseline',
      scope: '*@example.test',
      origin: 'administrator',
    },
    threshold_locked: false,
    action_source: {
      name: 'Domain baseline',
      scope: '*@example.test',
      origin: 'administrator',
    },
    spam: 'quarantine',
    publicity: 'deliver',
    unassessed: 'deliver',
    quarantine_days: 7,
    require_corroboration: true,
    profiles: [
      {
        source: {
          name: 'Domain baseline',
          scope: '*@example.test',
          origin: 'administrator',
        },
        threshold: 98,
        selected: true,
      },
    ],
    rules: [
      {
        name: 'Organization safeguard',
        scope: '*@example.test',
        origin: 'administrator',
        priority: 10,
        stop: true,
      },
    ],
    traffic: null,
  });
  function mapping(scope, p) {
    const result = base();
    if (p?.profile) {
      const v = p.profile,
        source = { name: v.name, scope, origin: 'personal' };
      Object.assign(result, {
        threshold: v.threshold ?? 98,
        threshold_source:
          v.threshold == null ? result.threshold_source : source,
        action_source: source,
        spam: v.spam,
        publicity: v.publicity,
        unassessed: v.review,
        quarantine_days: v.quarantine_days,
      });
      result.profiles[0].selected = false;
      result.profiles.unshift({
        source,
        threshold: v.threshold,
        selected: true,
      });
    }
    result.rules.unshift(
      ...(p?.rules ?? []).map((r) => ({
        name: r.name,
        scope,
        origin: 'personal',
        priority: r.priority,
        stop: false,
      })),
    );
    return result;
  }
  return (path, options) => {
    if (!path.startsWith('/preferences')) return null;
    const body = JSON.parse(options?.body || '{}');
    if (options?.method === 'POST') {
      if (body.revision !== revision)
        return Response.json(
          {
            error:
              'Configuration changed; reload preferences before reviewing.',
          },
          { status: 409 },
        );
      if (!body.scope.endsWith('@example.test'))
        return Response.json(
          { error: 'Choose an authorized scope.' },
          { status: 403 },
        );
      if (path === '/preferences/preview') {
        if (
          !body.recipient.endsWith('@example.test') ||
          body.recipient.startsWith('*@')
        )
          return Response.json(
            {
              error:
                'Choose one accepted original recipient inside this scope.',
            },
            { status: 422 },
          );
        return Response.json({
          schema: 'preference-preview-1',
          revision,
          checked_at: Math.floor(Date.now() / 1000),
          scope: body.scope,
          recipient: body.recipient,
          mode: 'observe',
          removing: body.preference === null,
          installed: mapping(body.scope, mailboxes[body.scope]),
          draft: mapping(body.scope, body.preference),
        });
      }
      if (path === '/preferences') {
        if (conflict) {
          conflict = false;
          revision++;
          return Response.json(
            {
              error: 'Configuration changed; reload preferences before saving.',
            },
            { status: 409 },
          );
        }
        if (body.preference === null) delete mailboxes[body.scope];
        else mailboxes[body.scope] = body.preference;
        revision++;
        saved = true;
        return Response.json({ revision, staged: false });
      }
    }
    if (path === '/preferences/activation')
      return Response.json({
        coordinator: true,
        coordinated: false,
        pending: false,
        installed_revision: revision,
        committed_revision: null,
        smtp_ready: true,
        phase: null,
        epoch: null,
        participants: null,
        abortable: false,
        recoverable: false,
        personal_change: null,
        incident: null,
      });
    if (path === '/preferences') {
      if (saved && failRefresh) {
        failRefresh = false;
        return Response.json(
          { error: 'Synthetic preferences refresh failure' },
          { status: 503 },
        );
      }
      return Response.json({
        revision,
        defaults: {},
        settings: {
          enabled: true,
          mailboxes,
          minimum_threshold: 85,
          maximum_threshold: 100,
          max_rules: 20,
          allowed_actions: ['deliver', 'tag', 'quarantine'],
        },
        scopes: ['alex@example.test', '*@example.test'],
        mode: 'observe',
        sensitivity_locked: false,
        personal_traffic: false,
        ordering: 'scoped',
      });
    }
    return Response.json(
      { error: 'No synthetic preference fixture' },
      { status: 404 },
    );
  };
}
