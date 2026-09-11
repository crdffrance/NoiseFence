import assert from 'node:assert/strict';
import test from 'node:test';
import {
  classification,
  deliverySummary,
  matchesAccount,
  checkFailure,
  publicitySignal,
} from '../app/presentation.ts';

test('failure diagnostics use fixed descriptions and do not echo untrusted text', () => {
  assert.match(checkFailure('timeout'), /Délai/);
  assert.match(checkFailure('authentication'), /Authentification/);
  assert.equal(checkFailure(null), '');
  assert.equal(
    checkFailure('private@example.org <script>'),
    'Cause non reconnue',
  );
});

test('publicity evidence stays visible independently of a security decision', () => {
  assert.ok(publicitySignal({ status: 'complete', verdict: 'promotion' }));
  assert.ok(publicitySignal({ status: 'complete', verdict: 'newsletter' }));
  assert.equal(
    publicitySignal({ status: 'limited', verdict: 'promotion' }),
    false,
  );
  assert.equal(
    publicitySignal({ status: 'complete', verdict: 'transactional' }),
    false,
  );
  assert.ok(!publicitySignal(undefined));
});
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
test('message details cannot classify historical mail with an invented threshold', () => {
  assert.equal(
    classification(mail).label,
    'Classement historique non enregistré',
  );
  assert.equal(
    classification(mail, Number.NaN).label,
    'Classement historique non enregistré',
  );
  assert.equal(
    classification({
      ...mail,
      decision: { source: 'legacy', outcome: 'unwanted', score: 99 },
    }).label,
    'Spam',
  );
  assert.equal(
    classification({
      ...mail,
      decision: { source: 'fusion', outcome: 'legitimate', score: 2 },
    }).label,
    'PUB',
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
  assert.equal(
    deliverySummary([{ status: 'delivered' }]).label,
    'Accepté par le serveur',
  );
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

test('recipient classification is visible without rewriting the detector decision', () => {
  const original={...mail,decision:{source:'fusion',outcome:'unwanted',score:99}};
  assert.equal(classification({...original,delivery_classification:'publicity'}).label,'PUB');
  assert.equal(classification({...original,delivery_classification:'legitimate'}).label,'Légitime');
  assert.equal(original.decision.outcome,'unwanted');
  assert.equal(classification({...original,complete:false,delivery_classification:'publicity'}).label,'Analyse incomplète');
  assert.equal(classification({...original,decision:{source:'antivirus',outcome:'unwanted',score:null},delivery_classification:'legitimate'}).label,'Malware');
});
