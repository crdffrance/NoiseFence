import assert from 'node:assert/strict';
import test from 'node:test';
import {
  classification,
  deliverySummary,
  matchesAccount,
} from '../app/presentation.ts';
const mail = {
  category: 'publicity',
  complete: true,
  score: 99,
  tagged: false,
  pub_tagged: false,
};
test('canonical review and legitimate decisions override the lexical score', () => {
  assert.equal(
    classification(
      {
        ...mail,
        decision: { source: 'fusion', outcome: 'undetermined', score: null },
      },
      95,
    ).label,
    'À vérifier',
  );
  assert.equal(
    classification(
      {
        ...mail,
        decision: { source: 'fusion', outcome: 'legitimate', score: 2 },
      },
      95,
    ).label,
    'PUB',
  );
  assert.equal(classification(mail, 95).label, 'Spam');
});
test('malware keeps priority over PUB and incomplete analysis', () => {
  assert.equal(
    classification(
      {
        ...mail,
        complete: false,
        decision: { source: 'antivirus', outcome: 'unwanted', score: null },
      },
      95,
    ).label,
    'Malware',
  );
  assert.equal(
    classification({ ...mail, complete: false }, 95).label,
    'Analyse incomplète',
  );
});
test('mixed deliveries never look fully delivered while a copy is held or failed', () => {
  assert.equal(
    deliverySummary([{ status: 'delivered' }, { status: 'quarantined' }]).label,
    'Quarantaine',
  );
  assert.equal(
    deliverySummary([{ status: 'delivered' }, { status: 'failed' }]).label,
    'Échec de livraison',
  );
  assert.equal(
    deliverySummary([{ status: 'delivered' }, { status: 'pending' }]).label,
    'En cours',
  );
  assert.equal(
    deliverySummary([{ status: 'delivered' }, { status: 'discarded' }]).label,
    'États multiples',
  );
  assert.equal(deliverySummary([]).label, 'Non renseignée');
});
test('account search combines access scope and role without dropping disabled accounts', () => {
  const account = {
    username: 'Alice',
    addresses: ['*@atelier.test'],
    admin: false,
    disabled: true,
  };
  assert.equal(matchesAccount(account, ' ATELIER ', 'user'), true);
  assert.equal(matchesAccount(account, 'alice', 'disabled'), true);
  assert.equal(matchesAccount(account, '', 'admin'), false);
  assert.equal(matchesAccount(account, 'bob', 'all'), false);
});
