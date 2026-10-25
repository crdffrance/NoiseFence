// Synthetic UI-only directory. No identity data or mutation reaches a server.
export function directoryFixture(params, settings) {
  const now = Math.floor(Date.now() / 1000),
    hash = '9'.repeat(64);
  let sources =
    params.get('directory') === 'empty'
      ? []
      : [
          {
            source: {
              id: 'organization',
              label: 'Organization directory',
              provider: 'manual',
              authority: 'example-organization',
              scopes: ['example.test'],
              stale_after_seconds: 2592000,
            },
            generation: 4,
            completed_at: now - 3600,
            people: [
              {
                id: 'finance-001',
                display_name: 'Alex Morgan',
                kind: 'person',
                activity: 'active',
                addresses: ['alex@example.test'],
                protected_roles: ['finance', 'executive'],
              },
              {
                id: 'operations-002',
                display_name: 'Jamie Chen',
                kind: 'person',
                activity: 'active',
                addresses: ['jamie@example.test'],
                protected_roles: ['helpdesk'],
              },
              {
                id: 'shared-finance',
                display_name: 'Accounts payable',
                kind: 'shared_mailbox',
                activity: 'active',
                addresses: ['finance@example.test'],
                protected_roles: ['finance'],
              },
            ],
            groups: [
              {
                id: 'finance',
                display_name: 'Finance team',
                activity: 'active',
                addresses: ['team-finance@example.test'],
                protected: true,
              },
            ],
            memberships: [
              {
                group: 'finance',
                member: { kind: 'person', id: 'finance-001' },
              },
            ],
            delegations: [
              {
                owner: 'shared-finance',
                delegate: 'finance-001',
                address: 'finance@example.test',
              },
            ],
          },
        ];
  if (params.get('administration') === 'identity' && sources.length)
    settings.identity_directory = { sha256: hash, reviewed_from: null };
  else sources = [];
  const candidates = new Map();
  const syncJobs = new Map();
  const connections = new Map();
  let count = 0;
  const status = (s) => ({
    source: s.source,
    generation: s.generation,
    completed_at: s.completed_at,
    fresh: now - s.completed_at < s.source.stale_after_seconds,
    people: s.people.length,
    groups: s.groups.length,
    protected_people: s.people.filter((p) => p.protected_roles.length).length,
    protected_groups: s.groups.filter((g) => g.protected).length,
    memberships: s.memberships.length,
    delegations: s.delegations.length,
  });
  const diff = (before, after) => ({
    added: after.filter((p) => !before.some((o) => o.id === p.id)).length,
    removed: before.filter((p) => !after.some((o) => o.id === p.id)).length,
    changed: after.filter((p) =>
      before.some(
        (o) => o.id === p.id && JSON.stringify(p) !== JSON.stringify(o),
      ),
    ).length,
  });
  return {
    commit(selection) {
      if (candidates.has(selection?.sha256))
        sources = structuredClone(candidates.get(selection.sha256));
    },
    handle(path, options, url, revision, current) {
      if (!path.startsWith('/admin/identity')) return null;
      if (params.get('directory') === 'unavailable')
        return Response.json(
          {
            error:
              'Synthetic directory status failure. Retry without changing the installed snapshot.',
          },
          { status: 503 },
        );
      const currentHash = current.identity_directory?.sha256 ?? null;
      const connectionView = () => ({
        revision,
        catalog_sha256: currentHash,
        vault: connections.size ? 'ready' : 'not_initialized',
        connections: [...connections.values()],
      });
      if (
        path === '/admin/identity/scim/enroll' &&
        options?.method === 'POST'
      ) {
        const body = JSON.parse(options.body),
          old = connections.get(body.source.id);
        if (
          body.revision !== revision ||
          body.catalog_sha256 !== currentHash ||
          (old?.generation ?? null) !== body.expected_generation
        ) {
          return Response.json(
            { error: 'Synthetic enrollment changed. Reload saved access.' },
            { status: 409 },
          );
        }
        const generation = crypto.randomUUID();
        connections.set(body.source.id, {
          source: body.source,
          generation,
          owner: 'Alex',
          created: Math.floor(Date.now() / 1000),
          expires: body.expires,
          status: 'configured',
        });
        if (params.get('scim') === 'lost-response')
          return Response.json(
            { error: 'Synthetic response lost after issuance.' },
            { status: 503 },
          );
        return Response.json({
          source: body.source,
          generation,
          expires: body.expires,
          base_url:
            'https://console.example.test/scim/' + body.source.id + '/v2',
          bearer: 'synthetic-demo-token-not-valid-for-any-server',
        });
      }
      if (
        path === '/admin/identity/scim/inventory' &&
        options?.method === 'POST'
      ) {
        const ref = JSON.parse(options.body),
          access = connections.get(ref.source_id);
        if (
          !access ||
          access.generation !== ref.generation ||
          access.status !== 'configured'
        )
          return Response.json(
            { error: 'Synthetic access unavailable.' },
            { status: 409 },
          );
        return Response.json({
          revision,
          catalog_sha256: currentHash,
          stage: {
            revision: {
              source_id: ref.source_id,
              source_sha256: 'a'.repeat(64),
              enrollment: ref.generation,
              sequence: 1,
            },
            users: 1,
            groups: 0,
            memberships: 0,
            modified: now,
          },
          inventory_sha256: 'b'.repeat(64),
          problem: null,
          draft: {
            source: access.source,
            people: [
              {
                id: 'scim-alex',
                display_name: 'Alex Morgan',
                kind: 'person',
                activity: 'active',
                addresses: ['alex@example.test'],
                protected_roles: [],
              },
            ],
            groups: [],
            memberships: [],
            delegations: [],
          },
        });
      }
      if (path === '/admin/identity/connections' && options?.method !== 'POST')
        return Response.json(connectionView());
      if (
        path === '/admin/identity/connections' &&
        options?.method === 'POST'
      ) {
        const body = JSON.parse(options.body),
          old = connections.get(body.source.id);
        if (
          body.revision !== revision ||
          body.catalog_sha256 !== currentHash ||
          (old?.generation ?? null) !== body.expected_generation
        )
          return Response.json(
            { error: 'Synthetic connection changed. Reload before saving.' },
            { status: 409 },
          );
        connections.set(body.source.id, {
          source: body.source,
          generation: body.operation,
          owner: 'Alex',
          created: Math.floor(Date.now() / 1000),
          expires: body.expires,
          status: 'configured',
        });
        return Response.json(connectionView());
      }
      if (
        path === '/admin/identity/connections/revoke' &&
        options?.method === 'POST'
      ) {
        const body = JSON.parse(options.body),
          old = connections.get(body.source_id);
        if (!old || old.generation !== body.generation)
          return Response.json(
            { error: 'Synthetic access generation changed.' },
            { status: 409 },
          );
        old.status = 'revoked';
        return Response.json(connectionView());
      }
      if (
        [
          '/admin/identity/schedules',
          '/admin/identity/schedules/stop',
        ].includes(path) &&
        options?.method === 'POST'
      ) {
        const body = JSON.parse(options.body),
          old = connections.get(body.connection.source_id),
          now = Math.floor(Date.now() / 1000);
        if (
          !old ||
          old.generation !== body.connection.generation ||
          (old.schedule?.id ?? null) !== body.expected_grant
        )
          return Response.json(
            { error: 'Synthetic schedule changed; reload.' },
            { status: 409 },
          );
        if (path.endsWith('/stop')) {
          old.schedule.revoked_at = now;
          old.schedule.state = 'stopped';
        } else {
          if (
            body.revision !== revision ||
            body.catalog_sha256 !== currentHash ||
            old.status !== 'configured' ||
            body.expires > old.expires ||
            body.expires <= now ||
            body.interval_seconds < 900 ||
            body.interval_seconds > 86400
          )
            return Response.json(
              { error: 'Synthetic schedule authorization refused.' },
              { status: 409 },
            );
          // Browser-memory fixture only: no server timer or provider request.
          old.schedule = {
            id: body.operation,
            expires: body.expires,
            interval_seconds: body.interval_seconds,
            next_due: now,
            revoked_at: null,
            last_run: null,
            state: 'scheduled',
          };
        }
        return Response.json(connectionView());
      }
      if (path === '/admin/identity' && options?.method !== 'POST') {
        const selected = sources.find(
          (s) => s.source.id === url?.searchParams.get('source'),
        );
        const draft = selected
          ? Object.fromEntries(
              Object.entries(selected).filter(
                ([key]) => !['generation', 'completed_at'].includes(key),
              ),
            )
          : null;
        return Response.json({
          revision,
          catalog_sha256: currentHash,
          observation_only: true,
          sources: sources.map(status),
          draft,
        });
      }
      if (
        [
          '/admin/identity/sync/entra',
          '/admin/identity/sync/okta',
          '/admin/identity/sync/google',
          '/admin/identity/sync/aws_identity_store',
          '/admin/identity/sync/stored',
          '/admin/identity/scim/attest',
        ].includes(path) &&
        options?.method === 'POST'
      ) {
        const body = JSON.parse(options.body);
        if (path.endsWith('/stored') || path.endsWith('/attest')) {
          const access = connections.get(body.connection.source_id);
          if (
            !access ||
            access.generation !== body.connection.generation ||
            access.status !== 'configured' ||
            access.expires <= Math.floor(Date.now() / 1000)
          )
            return Response.json(
              { error: 'Synthetic saved access unavailable.' },
              { status: 409 },
            );
          if (
            path.endsWith('/attest') &&
            (!body.complete_inventory ||
              body.inventory_sha256 !== 'b'.repeat(64) ||
              body.staged_revision.enrollment !== access.generation ||
              syncJobs.has(body.operation))
          )
            return Response.json(
              { error: 'Synthetic attestation conflict.' },
              { status: 409 },
            );
          body.source = access.source;
        }
        if (body.revision !== revision || body.catalog_sha256 !== currentHash)
          return Response.json(
            { error: 'Synthetic revision conflict.' },
            { status: 409 },
          );
        const after = {
          source: body.source,
          generation: 1,
          completed_at: now,
          people: [
            {
              id: `${body.source.provider}-alex`,
              display_name: 'Alex Morgan',
              kind: 'person',
              activity: 'active',
              addresses: ['alex@example.test'],
              protected_roles: [],
            },
          ],
          groups: [],
          memberships: [],
          delegations: [],
        };
        const sha256 = (++count).toString(16).padStart(64, '0');
        candidates.set(sha256, [
          ...sources.filter((s) => s.source.id !== body.source.id),
          after,
        ]);
        const prepared = {
          revision,
          selection: { sha256, reviewed_from: currentHash },
          active: false,
          collection: {
            requests: 5,
            pages: 5,
            bytes: 8192,
            excluded_members:
              body.source.provider === 'google'
                ? { external_membership: 2, customer_wide_membership: 1 }
                : {},
          },
          review: {
            operation: 'create',
            source_id: body.source.id,
            source_label: body.source.label,
            people: { added: 1, removed: 0, changed: 0 },
            groups: { added: 0, removed: 0, changed: 0 },
            membership_changes: 0,
            delegation_changes: 0,
            removed_or_disabled: 0,
            protected_identity_changes: 0,
            source_configuration_changed: false,
            requires_attention: body.source.provider === 'google',
            before: null,
            after: status(after),
          },
        };
        if (path.endsWith('/attest')) delete prepared.collection;
        const job = {
          id: body.operation,
          source_id: body.source.id,
          started_at: now,
          deadline: now + 360,
          state: params.get('sync') === 'failed' ? 'failed' : 'ready',
          reason: params.get('sync') === 'failed' ? 'collection' : null,
          stale: false,
          prepared: params.get('sync') === 'failed' ? null : prepared,
        };
        if (path.endsWith('/attest'))
          job.scim = {
            inventory_sha256: body.inventory_sha256,
            verified_at: now,
            revision: body.staged_revision,
          };
        syncJobs.set(body.operation, job);
        return Response.json(
          { id: job.id, deadline: job.deadline, state: 'running' },
          { status: 202 },
        );
      }
      if (
        path.startsWith('/admin/identity/sync/') &&
        options?.method !== 'POST'
      ) {
        const job = syncJobs.get(path.split('/').at(-1));
        return job
          ? Response.json({
              ...job,
              installed:
                !!job.prepared && job.prepared.selection.sha256 === currentHash,
              stale:
                !!job.prepared &&
                (job.prepared.revision !== revision ||
                  job.prepared.selection.reviewed_from !== currentHash),
            })
          : Response.json(
              { error: 'Synthetic receipt not found.' },
              { status: 404 },
            );
      }
      if (path !== '/admin/identity/prepare' || options?.method !== 'POST')
        return null;
      const body = JSON.parse(options.body);
      if (body.revision !== revision || body.catalog_sha256 !== currentHash)
        return Response.json(
          { error: 'Synthetic revision conflict. Reload settings.' },
          { status: 409 },
        );
      const edit = body.edit,
        id = edit.draft?.source.id ?? edit.source_id;
      const before = sources.find((s) => s.source.id === id),
        after =
          edit.operation === 'remove'
            ? null
            : {
                ...edit.draft,
                generation: (before?.generation ?? 0) + 1,
                completed_at: now,
              };
      const sha256 = (++count).toString(16).padStart(64, '0');
      candidates.set(sha256, [
        ...sources.filter((s) => s.source.id !== id),
        ...(after ? [after] : []),
      ]);
      const people = diff(before?.people ?? [], after?.people ?? []),
        groups = diff(before?.groups ?? [], after?.groups ?? []);
      return Response.json({
        revision,
        selection: { sha256, reviewed_from: currentHash },
        active: false,
        review: {
          operation: !after ? 'remove' : before ? 'update' : 'create',
          source_id: id,
          source_label: (after ?? before).source.label,
          people,
          groups,
          membership_changes:
            JSON.stringify(before?.memberships ?? []) ===
            JSON.stringify(after?.memberships ?? [])
              ? 0
              : 1,
          delegation_changes:
            JSON.stringify(before?.delegations ?? []) ===
            JSON.stringify(after?.delegations ?? [])
              ? 0
              : 1,
          removed_or_disabled: people.removed + groups.removed,
          protected_identity_changes: people.changed + groups.changed,
          source_configuration_changed:
            !!before &&
            JSON.stringify(before.source) !== JSON.stringify(after?.source),
          requires_attention: !!before,
          before: before ? status(before) : null,
          after: after ? status(after) : null,
        },
      });
    },
  };
}
