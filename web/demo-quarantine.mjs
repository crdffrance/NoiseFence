// Synthetic, memory-only lifecycle states. Excluded from the production bundle.
export function quarantineFixture(params, mail, diagnostic) {
  const scenario = params.get('quarantine'),
    r = mail.recipients[0];
  const remote = ['remote', 'late', 'unconfirmed'].includes(scenario);
  const events = [],
    requests = [];
  let unavailable = scenario === 'unavailable';
  if (scenario === 'late' || scenario === 'unconfirmed') {
    const at = Math.floor(Date.now() / 1000);
    requests.push({
      id: 'synthetic-command',
      node: 'mx1',
      actor: 'Alex',
      action: 'release',
      requested_at: at - 600,
      expires_at: at - 300,
      result: 'expired',
      finished_at: at - 300,
      execution_result: scenario === 'late' ? 'done' : null,
      acknowledged_at: scenario === 'late' ? at - 60 : null,
    });
  }
  return (path, options, url) => {
    if (path !== `/messages/${mail.id}/quarantine`) return null;
    const at = Math.floor(Date.now() / 1000);
    if (options?.method === 'POST') {
      const body = JSON.parse(options.body || '{}');
      if (body.recipient !== r.address)
        return Response.json(
          { error: 'Recipient not available' },
          { status: 404 },
        );
      if (
        !['release', 'delete'].includes(body.action) ||
        r.status !== 'quarantined' ||
        r.held_until <= at ||
        r.pending_command
      )
        return Response.json(
          { error: 'The delivery is no longer eligible for this action.' },
          { status: 409 },
        );
      if (remote) {
        r.pending_command = 'synthetic-command';
        requests.unshift({
          id: r.pending_command,
          node: 'mx1',
          actor: 'Alex',
          action: body.action,
          requested_at: at,
          expires_at: at + 300,
          result: 'pending',
          finished_at: null,
          execution_result: null,
          acknowledged_at: null,
        });
        return Response.json({
          status: 'queued',
          command_id: r.pending_command,
        });
      }
      r.status = body.action === 'release' ? 'pending' : 'discarded';
      if (body.action === 'release') r.released_at = at;
      diagnostic.status = r.status;
      events.unshift({
        at,
        actor: 'Alex',
        action:
          body.action === 'release'
            ? 'quarantine_release'
            : 'quarantine_delete',
      });
      return Response.json({
        status: body.action === 'release' ? 'pending' : 'discarded',
      });
    }
    if (url.searchParams.get('recipient') !== r.address)
      return Response.json(
        { error: 'Recipient not available' },
        { status: 404 },
      );
    if (unavailable) {
      unavailable = false;
      return Response.json(
        { error: 'Synthetic history unavailable. Retry is safe.' },
        { status: 503 },
      );
    }
    return Response.json({
      schema: 'quarantine-history-1',
      message_id: mail.id,
      recipient: r.address,
      checked_at: at,
      snapshot_at: remote ? at - 120 : at,
      source: remote ? 'central' : 'local',
      node: remote ? 'mx1' : null,
      status: r.status,
      raw_available: true,
      held_until: r.held_until,
      released_at: r.released_at ?? null,
      pending_command_id: r.pending_command ?? null,
      events,
      requests,
      events_truncated: false,
      requests_truncated: false,
    });
  };
}
