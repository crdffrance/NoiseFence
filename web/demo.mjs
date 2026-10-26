import { preferenceFixture } from './demo-preferences.mjs';
import { quarantineFixture } from './demo-quarantine.mjs';
import { administrationFixture } from './demo-administration.mjs';
// Local development demo. Synthetic data only; API requests never reach the server.
// This HTML entry is not included in the production build.
const params = new URLSearchParams(location.search);
const preferences=preferenceFixture(params);
const readonlyUser = params.get('role') === 'user';
const writes = [];
let detailedLabels = [{domain:'example.test', class:null}];
let correctionFailures = params.get('correction') === 'failure' ? 1 : 0;
let annotationWritten=false, failQualityRefresh=params.get('annotations')==='refresh-failure';
const setupFilters = {mode: 'observe', rule_weights: {}, threshold: 95, require_corroboration: true, authentication: true, antivirus: false, signatures: false, semantic: false, vision: false, llm: true, smtp_policy: true, smtp_policy_scoring: false, vision_scoring: false, reputation: false};
const setupLlm = {model:'synthetic-model',monthly_budget_micro_eur:20000000,pricing_checked_at:Math.floor(Date.now()/1000)-40*86400,max_text_bytes:12000,timeout_ms:2500,max_parallel:2,score_low:0,score_high:100,review_unconfirmed_high:false};
const setupSettings = {domains: [{name: 'example.test', gateway: 'provider', enabled: true, accept_all_recipients: false, recipients: ['alex@example.test'], aliases: {}}], gateways: [{id: 'provider', name: 'Synthetic mail provider', hosts: ['inbound.provider.test'], port: 25}], filters: setupFilters, actions: {spam:'quarantine',malware:'quarantine',publicity:'deliver',quarantine_days:14}, protection:{identity:true,links:true,campaigns:true,crdf:true,virustotal:false,crdf_quota:{minute:0,day:0},virustotal_quota:null,follow_urls:false,protected_names:[],reply_exceptions:[],link_exceptions:[]}, mailing:null, smtp_admission:{enabled:false,mode:'observe',greylisting:true,minimum_providers:2,allow_networks:[],rate_per_minute:60,rate_burst:120,retry_delay_seconds:120,retry_max_age_seconds:86400,retention_seconds:604800,max_entries:100000,tarpit_delay_ms:250,tarpit_max_concurrent:4,tarpit_session_budget_ms:1000}, rbl:{lists:[],action:'observe',minimum_providers:2,timeout_ms:1000,max_parallel:4,cache_entries:1000,cache_ttl_seconds:300}, detection:{modules:{llm:setupLlm, rspamd:{enabled:true,sample_percent:100,timeout_ms:5000,max_parallel:2,queue_capacity:4,max_bytes:4194304}}}, preferences:{enabled:false,mailboxes:{},minimum_threshold:50,maximum_threshold:99,max_rules:20,allowed_actions:['deliver','tag','quarantine']}, custom_filtering:null};
if (params.get('administration') === 'identity') setupSettings.protection.protected_names = [
  {name:'Alex Morgan',domain:'example.test'}, {name:'Finance Team',domain:'example.test'},
  {name:'Supplier Billing',domain:'supplier.example.test'},
];
if (params.has('contacts')) setupSettings.identity_policy = {mode:'observation',maximum_weight:1};
if (params.has('contacts')) setupSettings.contact_learning = {key_id:"d".repeat(64),enabled:true,retention_days:30,minimum_campaigns:5,minimum_days:3,learn_since:0};
const administration = administrationFixture(params,setupSettings,__NOISEFENCE_CONSOLE__.version);
const sampleId = '00000000-0000-4000-8000-000000000002';
const cohort = 'a'.repeat(64);
const variant = new URLSearchParams(location.search).get('case') ?? 'spam';
const held = variant === 'quarantine';
const spam = variant === 'spam' || held,
  pub = variant === 'pub',
  opaque = variant === 'encrypted';
const category = spam ? 'spam' : pub ? 'publicity' : 'legitimate';
const score = opaque ? null : spam ? 97.8 : pub ? 18.4 : 99.6;
const created = 1792037400;
const reasons = [
  {
    id: 'model_contribution',
    detail:
      'Text and semantic model summary. This is already included in the index.',
    weight: 3.8,
  },
  {
    id: spam ? 'dmarc_fail' : 'authenticated_sender',
    detail: spam
      ? 'Neither DKIM nor SPF aligns with the visible sender.'
      : 'The visible sender has an aligned DKIM signature.',
    weight: spam ? 2.1 : -0.4,
  },
  {
    id: spam ? 'suspicious_url' : 'completed_payment_receipt',
    detail: spam
      ? 'The destination hostname differs from the brand claimed in the message.'
      : 'The message confirms a completed payment and does not ask for credentials.',
    weight: spam ? 0.8 : 0,
  },
  {
    id: 'urgency',
    detail:
      'Time pressure appears in the message text. Context is considered separately.',
    weight: 0.3,
  },
  {
    id: 'smtp_policy_unavailable',
    detail:
      'SMTP / DNS consistency exceeded its time budget. Missing data is not a spam finding.',
    weight: 0,
  },
  {
    id: 'known_correspondence',
    detail: 'Previous correspondence contributes a limited contextual signal.',
    weight: -0.2,
  },
];
const decision = {
  source: 'legacy',
  outcome: spam ? 'unwanted' : 'legitimate',
  score,
  model: 'content-example-v1',
};
const action = {
  requested: spam ? 'quarantine' : 'deliver',
  effective: held ? 'quarantine' : 'deliver',
  reason: held ? 'policy' : 'observation',
  quarantine_days: 7,
};
const assessment = {
  version: 1,
  category,
  classification_source: 'recorded_decision',
  decision,
  decision_recorded: true,
  complete: !opaque,
  incomplete_reasons: opaque ? ['encrypted_content'] : [],
  supplementary_gaps: ['virustotal'],
  content_threshold: 95,
  mode: held ? 'enforce' : 'observe',
  policy_version: 'decision-policy-12',
  action,
  subject_tag: 'none',
  score: {
    value: score,
    raw: score,
    decision: score,
    kind: opaque ? 'unavailable' : 'content',
    source: opaque ? 'unavailable' : 'raw',
    model: 'content-example-v1',
    scale: 100,
  },
  score_resolution: {
    version: 'score-resolution-1',
    threshold: 95,
    score,
    partial: opaque,
    projected: false,
    guard: variant === 'ham' ? 'authenticated_benign_conflict' : null,
    previous: { outcome: 'undetermined' },
    decision: { outcome: decision.outcome },
  },
};
const mail = {
  ...(params.has('contacts') ? { identity_correlation: {protocol:'identity-correlation-1',policy_sha256:'c'.repeat(64),mode:'observation',status:'complete',content_available:true,recurrence_available:true,authentication:spam?'failed':'aligned',signals:spam?['recurring_reply_changed','sensitive_request','authentication_failed']:[],corroborated:spam,proposed_weight:spam?1:0,applied_weight:0}, contact_learning: {status:'regular',observation_only:true,learning_eligible:!spam,dkim_alignment:spam?'not_verified':'verified',regular:true,campaigns:8,observed_days:6,last_seen_at:created-86400,retention_days:30,minimum_campaigns:5,minimum_days:3,blocked_by_feedback:false,content_comparison_available:true,changes:[...(spam?['dkim_alignment']:[]),'reply_destination','sensitive_request']} } : {}),
  ...(params.has('identity') ? { protection: {
    version:'protection-demo', observation_only:true,local_status:'complete',feed_status:'not_configured',campaign_status:'not_run',campaign_match:false,campaign_conflict:false,authenticated_sender:false,
    crdf:{status:'not_configured',checked:0,malicious:0,suspicious:0,unknown:0,cache_hits:0,elapsed_ms:0},
    virustotal:{status:'not_configured',checked:0,malicious:0,suspicious:0,unknown:0,cache_hits:0,elapsed_ms:0},
    findings:[{id:'protected_display_name',family:'identity',indicator:'unexpected.example.test',sources:['headers'],detail:'A protected display name was observed with a different registrable sending domain.'}],families:['identity'],elapsed_ms:3,
  }} : {}),
  ...(params.has('identity') ? {identity:{catalog_sha256:'d'.repeat(64),relationships_available:false,sensitive_requests_available:false,observation:{protocol:'identity-detection-1',status:'complete',observation_only:true,fresh_sources:1,applicable_sources:1,authentication:'failed',directory_address_match:false,ambiguous_identity:false,signals:['protected_name_mismatch'],corroborated:true}}} : {}),
  id: '00000000-0000-4000-8000-000000000001',
  created,
  sender: 'notifications@example.test',
  subject: spam
    ? 'Action required: verify your account'
    : pub
      ? 'Your monthly product newsletter'
      : opaque
        ? 'Encrypted message'
        : 'Payment received — thank you',
  score,
  category,
  complete: !opaque,
  model: 'content-example-v1',
  decision,
  assessment,
  recipient_decision: {
    version: 2,
    recorded_at: created,
    policy_sha256: 'a'.repeat(64),
    profile: 'balanced',
    rule_ids: [],
    classification: category,
    coverage: opaque ? 'unavailable' : 'complete',
    assessment,
  },
  action,
  tagged: false,
  pub_tagged: false,
  feedback: null,
  feedback_category: null,
  reasons,
  recipients: [
    {
      address: 'alex@example.test',
      status: held ? 'quarantined' : 'delivered',
      delivery_id: 1,
      held_until: held ? Math.floor(Date.now()/1000) + (params.get('quarantine')==='expired' ? -1 : 7*86400) : null,
    },
  ],
  node_id: 'mx1',
  node_updated_at: created,
  antivirus: { status: 'clean', elapsed_ms: 42, signature: null },
  signatures: { status: 'clean', elapsed_ms: 8, signature: null },
  llm: { status: 'pricing_expired', model: 'local-fixture', elapsed_ms: 0 },
  smtp_policy: {
    status: 'unavailable',
    elapsed_ms: 500,
    scoring_enabled: true,
  },
  semantic: { status: 'complete', elapsed_ms: 23 },
  vision: {
    status: 'complete',
    parts: 0,
    pages: 0,
    text_chars: 0,
    qr_codes: 0,
    other_codes: 0,
    link_domains: 0,
    elapsed_ms: 2,
  },
};
const observation = (
  id,
  family,
  state,
  value = null,
  role = 'decision_input',
  kind = 'reputation',
) => ({
  id,
  family,
  state,
  role,
  scope: 'message',
  version: null,
  elapsed_ms: 24,
  result: value == null ? null : { kind, value },
  measurements: {},
  exclusion: null,
  group: id,
});
const observations = [
  observation('content', 'content', 'complete'),
  observation('semantic', 'content', 'complete'),
  observation(
    'spf',
    'authentication',
    'complete',
    [spam ? 'fail' : 'pass'],
    'decision_input',
    'authentication',
  ),
  observation(
    'dkim',
    'authentication',
    'complete',
    [spam ? 'fail' : 'pass'],
    'decision_input',
    'authentication',
  ),
  observation(
    'dmarc',
    'authentication',
    'complete',
    [spam ? 'fail' : 'pass'],
    'decision_input',
    'authentication',
  ),
  observation(
    'crdf.0',
    'url_threat',
    'complete',
    spam ? 'suspicious' : 'unknown',
  ),
  observation('virustotal', 'url_threat', 'unavailable'),
  observation('smtp_dns', 'sender_reputation', 'unavailable'),
  observation(
    'antivirus',
    'malware',
    'complete',
    'clean',
    'safety',
    'antivirus',
  ),
  observation('llm', 'content', 'disabled'),
  observation(
    'mail_kind',
    'context',
    'complete',
    pub ? 'newsletter' : 'transactional',
    'advisory',
    'mail_kind',
  ),
];
const scoring = {
  version: 'scoring-1',
  baseline: 0,
  lexical: 3.8,
  semantic: 0,
  contributions: reasons
    .filter((r) => r.id !== 'model_contribution')
    .map((r) => ({
      id: r.id,
      family: 'content',
      occurrences: 1,
      proposed: r.weight,
      retained: r.weight,
      adjustment: 'none',
    })),
  invalid_inputs: 0,
  rules_total: 3,
  total_logit: 4,
  score,
};
const rspamd = {
  status: 'complete',
  comparison: 'disagreement',
  score: 4.8,
  required_score: 15,
  action: 'greylist',
  symbols: [
    { name: 'R_DKIM_ALLOW', score: -0.2 },
    { name: 'MIME_GOOD', score: -0.1 },
  ],
  elapsed_ms: 717,
  profile: 'example profile',
  settings_sha256: 'b'.repeat(64),
  server: 'rspamd / example',
  noisefence_outcome: decision.outcome,
};
Object.assign(mail, { rspamd });
const recipient = {
  address: 'alex@example.test',
  destination: 'alex@example.test',
  delivery_id: 1,
  status: held ? 'quarantined' : 'delivered',
  attempts: 1,
  next_attempt: 0,
  last_error: null,
  logs_available: 1,
  logs_truncated: false,
  logs: [
    {
      id: 1,
      attempt: 1,
      route: 'destination.example.test',
      peer: '192.0.2.1',
      started: created,
      elapsed_ms: 304,
      outcome: 'delivered',
      truncated: false,
      events: [
        {
          phase: 'data_reply',
          elapsed_ms: 302,
          code: 250,
          enhanced_code: '2.0.0',
          response: 'Message accepted',
          detail: null,
        },
      ],
    },
  ],
};
const diagnostics = {
  message_id: mail.id,
  analysis: {
    assessment,
    scoring,
    rspamd,
    observations: {
      version: 3,
      provenance: 'synthetic',
      observations,
      groups: [],
      omitted: 0,
    },
    elapsed_ms: 485,
    feature_version: 1,
    features_complete: !opaque,
    policy: {
      version: 'decision-policy-12',
      threshold: 95,
      mode: held ? 'enforce' : 'observe',
      require_corroboration: true,
      rule_weights: {},
    },
    lexical_logit: 3.8,
    semantic_contribution: 0,
    rule_weight_total: 3,
    evidence: {
      lexical_state: 'complete',
      semantic_state: 'complete',
      authentication: {
        state: 'complete',
        spf_state: 'complete',
        spf: spam ? 'fail' : 'pass',
        dkim_state: 'complete',
        dkim: [spam ? 'fail' : 'pass'],
        dmarc_state: 'complete',
        dmarc_spf: spam ? 'fail' : 'pass',
        dmarc_dkim: spam ? 'fail' : 'pass',
        arc_state: 'complete',
        arc: 'none',
        arc_can_seal: false,
      },
    },
  },
  recipients: [recipient],
};
const members = [
  {
    id: mail.id,
    created,
    sender: mail.sender,
    subject: mail.subject,
    risk: null,
    kind: null,
    joint_observations: true,
  },
  {
    id: '00000000-0000-4000-8000-000000000003',
    created: created + 60,
    sender: 'newsletter@example.test',
    subject: 'Monthly product news',
    risk: null,
    kind: null,
    joint_observations: true,
  },
];
const metrics = {
  labelled: 0,
  recall: null,
  false_positive_rate: null,
  precision: null,
  abstention: null,
};
const windowData = {
  messages: 2,
  spam: 1,
  review: 0,
  legitimate: 1,
  incomplete: 0,
  disagreements: 1,
  p95_ms: 485,
  detector_status: { llm: { disabled: 2 }, virustotal: { quota: 2 } },
  coverage: {
    providers: {crdf:{messages:2,checked:5,cached:3,omitted:1,requests:3,http_status:{200:2,503:1},failures:{http:1},retry_after_max_seconds:0,timed_messages:2,p95_ms:425,deadline_exceeded:0,phase_ms:{http:800},cancelled_phases:{}}},
    redirect_details: {},
    redirect_categories: {},
    redirect_http_status: {},
    redirects_complete: 0,
    redirects_omitted: 0,
  },
};
const reliability = {
  checked_at: created,
  status: 'complete',
  observations: windowData,
  last_24h: windowData,
  reference: windowData,
  current_build_last_24h: windowData,
  quality_labels: metrics,
  targeted_feedback: metrics,
  unlabelled: 2,
  saturated_scores: 0,
  cohorts: {},
  symbols: {},
  current_build_observations: 2,
  current_protocol_observations: 2,
  invalid_scans: 0,
  cooccurrences: [],
  candidate_comparisons: [],
  alerts: [],
  limitations: [
    'Synthetic demo only. These messages do not measure filtering quality.',
  ],
};
// Keep the synthetic score ledger internally consistent; it is not a learned model.
if (score != null) {
  const rulesTotal = scoring.contributions.reduce(
    (total, c) => total + c.retained,
    0,
  );
  scoring.total_logit = Math.log(score / (100 - score));
  scoring.rules_total = rulesTotal;
  scoring.lexical = scoring.total_logit - rulesTotal;
  diagnostics.analysis.lexical_logit = scoring.lexical;
  diagnostics.analysis.rule_weight_total = rulesTotal;
  reasons[0].weight = scoring.lexical;
}
if(held) {recipient.attempts=0;recipient.logs=[];recipient.logs_available=0;}
const quarantine = quarantineFixture(params, mail, recipient);
const fetchOriginal = window.fetch;
window.fetch = async (input, options) => {
  const url = new URL(
    typeof input === 'string'
      ? input
      : input instanceof Request
        ? input.url
        : input,
    location.href,
  );
  if (url.origin !== location.origin)
    throw new Error('External requests are disabled in the synthetic demo.');
  if (!url.pathname.startsWith('/api/')) return fetchOriginal(input, options);
  const path = url.pathname.replace('/api/v1', '');
  const administrationResponse=administration(path,options,url);
  if(administrationResponse)return administrationResponse;
  const quarantineResponse=quarantine(path,options,url);
  if(quarantineResponse)return quarantineResponse;
  const preferenceResponse=preferences(path,options);
  if(preferenceResponse)return preferenceResponse;
  let data;
  const wanted = members.filter((m) => m.risk === 'legitimate').length,
    unwanted = members.filter((m) => m.risk === 'spam').length,
    uncertain = members.filter((m) => m.risk === 'uncertain').length,
    labelled = wanted + unwanted + uncertain,
    kindCount = members.filter((m) => m.kind).length;
  if (options?.method === 'POST') {
    const body = JSON.parse(options.body || '{}');
    writes.push({ path, body });
    if (path === '/admin/domains/check' && !readonlyUser) {
      const result = body.check === 'configuration' ? {check:'configuration', status:'valid'}
        : body.check === 'dns' ? {check:'dns',status:'available',local_mx_present:false,records:[{priority:10,host:'old.provider.test.'}],truncated:false}
        : {check:'recipient',status:body.recipient.startsWith('missing@') ? 'unknown' : body.recipient.startsWith('busy@') ? 'unavailable' : 'accepted',destination:body.recipient,routes:['inbound.provider.test'],data_sent:false,loopback_test_allowed:false};
      return Response.json({revision:body.revision,domain:body.domain,hostname:'mx.example.test',checked_at:Math.floor(Date.now()/1000),draft:true,result});
    }
    if (path === `/messages/${mail.id}/feedback` || path === `/messages/${mail.id}/adaptive-label`) {
      if(correctionFailures-- > 0) return Response.json({error:'Synthetic save failure. No correction was stored.'},{status:503});
      if(path.endsWith('/feedback')) {
        mail.feedback_category=body.category; mail.feedback=body.category==='spam';
        detailedLabels=detailedLabels.map(d=>({...d,class:null}));
      } else if(body.class) {
        mail.feedback_category=['phishing','scam'].includes(body.class)?'spam':body.class;
        mail.feedback=mail.feedback_category==='spam';
        detailedLabels=detailedLabels.map(d=>({...d,class:d.domain===body.domain?body.class:null}));
      } else detailedLabels=detailedLabels.map(d=>({...d,class:d.domain===body.domain?null:d.class}));
      return Response.json({ok:true});
    }
    if (path.endsWith('/quality-label')) {
      const member=members.find(m=>path===`/messages/${m.id}/quality-label`);
      if(!member)return Response.json({error:'Synthetic member unavailable'},{status:404});
      member.risk=body.risk;member.kind=body.kind;annotationWritten=true;
      return Response.json({ok:true});
    }
    if (path === `/quality/samples/${sampleId}/labels`) {
      let applied = 0,
        skipped = 0;
      for (const member of members.filter((m) => body.ids.includes(m.id))) {
        if (member.risk && !body.overwrite) {
          skipped++;
          continue;
        }
        member.risk = body.risk;
        if (body.kind) member.kind = body.kind;
        applied++;
      }
      annotationWritten=true;
      return Response.json({ applied, skipped });
    }
    return Response.json(
      { error: 'Read-only synthetic demo: no changes were sent to a server.' },
      { status: 403 },
    );
  }
  if (path === '/me')
    data = {
      username: 'Alex',
      admin: !readonlyUser,
      csrf: 'synthetic',
      addresses: ['alex@example.test'],
    };
  else if ((path === '/admin/providers' || path === '/admin/protection') && !readonlyUser) {
    if (new URLSearchParams(location.search).get('providers') === 'unavailable')
      return Response.json({error:'Synthetic status failure'}, {status:503});
    data = {revision:25, checked_at:Math.floor(Date.now()/1000), hostname:'mx.example.test', node_id:'mx-demo',cluster_role:'coordinator', available:true,enabled:true,
      keys:{crdf:true,virustotal:true},loaded_keys:{crdf:true,virustotal:false},pending_keys:{crdf:false,virustotal:true},policy:{crdf:true,virustotal:false,follow_urls:false},
      quotas:{crdf:{minute:0,day:0},virustotal:{minute:4,day:500}},bootstrap_quotas:{crdf:{minute:2,day:200},virustotal:{minute:4,day:500}},
      usage:{crdf:{minute_used:2,day_used:140,minute_resets_at:Math.floor(Date.now()/60000)*60+60,day_resets_at:Math.floor(Date.now()/86400000)*86400+86400,cooldown_until:null},virustotal:null},capacity:{timeout_ms:1200,max_parallel:2,max_indicators:12},
      services:{llm:{installed:true,enabled:true,configuration:setupLlm,budget:{status:'available',month:'2026-10',accounted_micro_eur:2500000,issued_micro_eur:500000,requests:18,worker_wallet:false,ceiling_micro_eur:20000000,remaining_micro_eur:17500000}},rbl:{enabled_lists:0,action:'observe',timeout_ms:1000,max_parallel:4},rspamd:{enabled:true,sample_percent:100,timeout_ms:5000,max_parallel:2}}};
  }
  else if (path === '/admin/config' && !readonlyUser)
    data = {memory_key_id:"d".repeat(64),revision:25,settings:setupSettings,actions:setupSettings.actions,rules:[],native_rules:[],available:setupFilters,hostname:'mx.example.test',version:__NOISEFENCE_CONSOLE__.version,sensitivity_levels:[],threshold_locked:false,sensitivity_locked:false,tag_ready:false,pub_tag_ready:false,mailing_available:false,max_connections:100,processing:4,relay_workers:4,max_message_bytes:26214400};
  else if (path === '/admin/cluster/activation/view' && !readonlyUser)
    data = {coordinator:true,coordinated:false,pending:false,installed_revision:25,committed_revision:null,smtp_ready:true,phase:null,epoch:null,participants:null,abortable:false,recoverable:false,personal_change:null,incident:null};
  else if (path === '/system/version')
    data = {
      version: __NOISEFENCE_CONSOLE__.version,
      engine_build: 'a'.repeat(64),
      node: 'Synthetic preview',
      configuration_revision: 25,
      console: {
        version: __NOISEFENCE_CONSOLE__.version,
        source_sha256: 'b'.repeat(64),
      },
      deployment: { deployed_at: 1792166400 },
      runtime: {
        lexical: { version: 'content-example-v1', sha256: 'c'.repeat(64) },
        semantic: { sha256: 'd'.repeat(64) },
        fusion: null,
        shadow: null,
        policy_sha256: 'e'.repeat(64),
        cohort_sha256: 'f'.repeat(64),
        decision_policy: 'decision-policy-13',
        score_combination: 'scoring-1',
        feature_version: 1,
      },
    };
  else if (path === '/quality/samples')
    data = {
      cohorts: [
        { id: cohort, messages: 2, since: created, until: created + 60 },
      ],
      batches: [
        {
          id: sampleId,
          purpose: params.get('purpose')==='holdout'?'holdout':'development',
          sampling: 'random',
          created,
          since: created,
          until: created + 60,
          domain: 'example.test',
          population: 2,
          selected: 2,
          available: 2,
          labelled: members.filter((m) => m.risk).length,
        },
      ],
      candidate_configured: false,
      observation_start: created,
    };
  else if (path === `/quality/samples/${sampleId}`) {
    if(annotationWritten&&failQualityRefresh){failQualityRefresh=false;return Response.json({error:'Synthetic refresh failure'},{status:503});}
    data = members;
  }
  else if (path === `/quality/samples/${sampleId}/readiness`)
    data = {
      selected: 2,
      available: 2,
      labelled,
      risk_labels: labelled,
      kind_labels: kindCount,
      risk_with_observations: labelled,
      kind_with_observations: kindCount,
      missing_or_incompatible_observations: 0,
      detector_cohorts: 1,
      training_validated: false,
      observation_only: true,
    };
  else if (path === '/quality/release-readiness')
    data = {
      schema: 'noisefence-release-readiness-2',
      current_cohort: cohort,
      cohorts: {
        [cohort]: {
          messages: 2,
          usable: 2,
          wanted,
          unwanted,
          uncertain,
          unlabelled: 2 - labelled,
          usable_wanted: wanted,
          usable_unwanted: unwanted,
          usable_uncertain: uncertain,
          usable_unlabelled: 2 - labelled,
          exclusions: {},
        },
      },
      minimum_wanted_test_messages: 10000,
      minimum_unwanted_test_messages: 2000,
      qualification_required: true,
      blockers: ['independent_test_required'],
    };
  else if (path === '/quality/reliability') data = reliability;
  else if (path === '/quality/jobs')
    data = { jobs: [], revision: 1, selection: null, worker: null };
  else if (path === '/domains') data = ['example.test'];
  else if (path.startsWith('/stats'))
    data = {
      received: 1,
      flagged: spam ? 1 : 0,
      publicity: pub ? 1 : 0,
      pending: 0,
      quarantined: held ? 1 : 0,
      mode: held ? 'enforce' : 'observe',
      threshold: 95,
    };
  else if (path.startsWith('/search/messages'))
    data = { messages: [mail], total: 1, has_more: false, comparison: null };
  else if (path.endsWith('/diagnostics')) {
    if (variant === 'error')
      return Response.json(
        { error: 'Synthetic diagnostics failure.' },
        { status: 503 },
      );
    data = diagnostics;
  } else if (path.endsWith('/adaptive-label')) {
    if(params.get('labels')==='unavailable')return Response.json({error:'Synthetic label lookup unavailable'},{status:503});
    data = {domains:detailedLabels};
  }
  else
    return Response.json(
      { error: `No synthetic fixture for ${path}` },
      { status: 404 },
    );
  return Response.json(data);
};
await import('/app/main.tsx');

if (params.get('administration') === 'identity' && !params.has('identity') && params.get('role') !== 'user') {
  let attempts = 0, opened = false;
  const open = setInterval(() => {
    const tab = document.getElementById('filters-tab-identity');
    if (tab) {
      tab.click();
      requestAnimationFrame(() => document.querySelector('.identity-workspace')?.scrollIntoView({block:'start'}));
      clearInterval(open);
    } else if (!opened) {
      const filters = [...document.querySelectorAll('nav[aria-label="Administration"] button')].find(button => button.textContent === 'Filters');
      if (filters) { filters.click(); opened = true; }
    }
    if (++attempts > 30) clearInterval(open);
  }, 100);
} else if (!params.has('view') && params.get('open') !== 'list') {
  let attempts = 0;
  const open = setInterval(() => {
    const button = [...document.querySelectorAll('button')].find((b) =>
      b.textContent.includes(mail.subject),
    );
    if (button) {
      button.click();
      clearInterval(open);
    } else if (++attempts > 30) clearInterval(open);
  }, 100);
}
