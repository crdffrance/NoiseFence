export type HistoricalPolicy = {
  version: string;
  threshold: number;
  mode: 'observe' | 'tag' | 'enforce';
  require_corroboration: boolean;
  rule_weights: Record<string, number>;
};

// Only this projection of src/evidence.rs is displayed. Other evidence remains private.
export type AuthenticationEvidence = {
  state: string;
  spf_state: string;
  spf: string | null;
  dkim_state: string;
  dkim: string[] | null;
  dmarc_state: string;
  dmarc_spf: string | null;
  dmarc_dkim: string | null;
  arc_state: string;
  arc: string | null;
  arc_can_seal: boolean | null;
};

export type SmtpEvent = {
  phase: string;
  elapsed_ms: number;
  code: number | null;
  enhanced_code: string | null;
  response: string | null;
  detail: string | null;
};
export type SmtpLog = {
  id: number;
  attempt: number;
  route: string;
  peer: string | null;
  started: number;
  elapsed_ms: number;
  outcome: 'delivered' | 'temporary' | 'permanent';
  truncated: boolean;
  events: SmtpEvent[];
};
export type DiagnosticRecipient = {
  sender_history?: {
    version: string;
    status: string;
    mode: string;
    distinct_campaigns: number;
    distinct_days: number;
    learned_candidate: boolean;
    manual_match: string;
    contradicted: boolean;
    candidate_credit: boolean;
  } | null;
  delivery_id: number;
  address: string;
  destination: string;
  status: string;
  attempts: number;
  next_attempt: number;
  last_error: string | null;
  logs_available: number;
  logs_truncated: boolean;
  logs: SmtpLog[];
};
export type RecipientHistory = DiagnosticRecipient;
export type MessageDiagnostics = {
  message_id: string;
  analysis: {
    sandbox_pipeline?: {
      version: string;
      status: string;
      disposition: string;
      selected: number;
      skipped: number;
      details: string[];
    } | null;
    research_execution?: {
      version: string;
      status: string;
      elapsed_ms: number;
    } | null;
    heuristics?: {
      version: string;
      pattern_version: string;
      settings_digest: string;
      mode: string;
      status: string;
      candidate_weight: number;
      contribution: number;
      limits_hit: string[];
      findings: {
        id: string;
        label: string;
        family: string;
        scopes: string[];
        matches: number;
        candidate_weight: number;
      }[];
    } | null;
    content_inspection?: {
      version: string;
      status: string;
      advisory: boolean;
      truncated: boolean;
      stats: { images: number; pdfs: number; office_documents: number };
      parts: {
        index: number;
        kind: string;
        bytes: number;
        width: number | null;
        height: number | null;
        complete: boolean;
      }[];
      findings: { id: string; part: number | null }[];
    } | null;
    elapsed_ms: number;
    feature_version: number;
    features_complete: boolean | null;
    policy: HistoricalPolicy | null;
    lexical_logit: number | null;
    semantic_contribution: number | null;
    rule_weight_total: number;
    evidence: {
      authentication?: AuthenticationEvidence;
      lexical_state?: string;
      semantic_state?: string;
    } | null;
  };
  recipients: DiagnosticRecipient[];
  sandbox_results?: {
    part: number;
    state: string;
    detail: string | null;
    result: {
      status: string;
      outcome: string;
      detail: string | null;
      findings: { id: string; severity: number; confidence: number }[];
      findings_truncated: boolean;
      engine_version: string | null;
      isolation_verified: boolean;
    } | null;
  }[];
};
export type DiagnosticReason = { id: string; detail: string; weight: number };

export function recipientHistory(
  data: MessageDiagnostics,
  messageId: string,
  deliveryId: number,
  signal?: AbortSignal,
): RecipientHistory | null {
  if (signal?.aborted) return null;
  const recipient = data.recipients[0];
  if (
    data.message_id !== messageId ||
    data.recipients.length !== 1 ||
    recipient?.delivery_id !== deliveryId
  )
    throw new Error(
      'L’historique reçu ne correspond pas au destinataire sélectionné.',
    );
  // A targeted response must never replace the message's other recipients or analysis.
  return recipient;
}

export function mergeDiagnosticRecipient<T extends { delivery_id?: number }>(
  recipients: T[],
  updated: DiagnosticRecipient,
): T[] {
  return recipients.map((recipient) =>
    recipient.delivery_id === updated.delivery_id
      ? { ...recipient, ...updated }
      : recipient,
  );
}

const decimal = new Intl.NumberFormat('fr-FR', { maximumFractionDigits: 3 });
export function duration(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value) || value < 0)
    return 'Durée non enregistrée';
  return value < 1000
    ? `${decimal.format(value)} ms`
    : `${decimal.format(value / 1000)} s`;
}
export function timestamp(value: number) {
  const date = new Date(value * 1000);
  return value > 0 && Number.isFinite(date.getTime())
    ? date.toLocaleString('fr-FR', { timeZoneName: 'short' })
    : 'Date non enregistrée';
}
export function contribution(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value)) return 'Non enregistrée';
  // Preserve the sign of small nonzero contributions, without displaying +0.
  const formatted =
    Math.abs(value) > 0 && Math.abs(value) < 0.001
      ? Math.abs(value).toExponential(2).replace('.', ',')
      : decimal.format(Math.abs(value));
  return `${value > 0 ? '+' : value < 0 ? '−' : ''}${formatted}`;
}
export function weightEffect(value: number) {
  if (!Number.isFinite(value)) return 'Effet non enregistré';
  if (value > 0) return 'Augmente la suspicion dans le calcul historique';
  if (value < 0) return 'Réduit la suspicion dans le calcul historique';
  return 'Signal consultatif · aucun effet numérique';
}
export function decisionExplanation(source?: string) {
  if (source === 'antivirus')
    return 'Décision antivirus prioritaire : la détection de malware prime sur les poids historiques et la fusion. Ces contributions ne déterminent pas la décision finale.';
  if (source === 'fusion')
    return 'Décision par fusion des détecteurs : les poids du calcul historique ci-dessous ne déterminent pas le score final de fusion.';
  if (source === 'legacy')
    return 'Décision issue du calcul historique : modèle lexical, contribution sémantique et règles, sous réserve de la politique de confirmation enregistrée.';
  return 'Source de décision non enregistrée. Les poids conservés ne permettent pas de reconstituer avec certitude la décision finale.';
}
export function policySummary(policy: HistoricalPolicy | null) {
  if (!policy)
    return 'Politique historique non enregistrée : seuil et mode à la réception inconnus. Les réglages actuels ne sont pas utilisés pour reconstituer cette analyse.';
  const mode =
    {
      observe: 'Observation',
      tag: 'Marquage',
      enforce: 'Application des actions',
    }[policy.mode] ?? 'Mode inconnu';
  return `${mode} · seuil historique ${decimal.format(policy.threshold)} / 100 · confirmation ${policy.require_corroboration ? 'requise' : 'non requise'}`;
}
export function deliveryStatus(status: string) {
  return (
    (
      {
        pending: 'En attente de transmission',
        sending: 'Transmission en cours',
        delivered: 'Accepté par le serveur destinataire',
        failed: 'Échec de transmission',
        notified: 'Échec signalé à l’expéditeur',
        quarantined: 'En quarantaine',
        discarded: 'Supprimé manuellement',
        expired: 'Quarantaine expirée',
      } as Record<string, string>
    )[status] ?? `État inconnu (${status})`
  );
}
export function smtpOutcome(outcome: string) {
  return (
    (
      {
        delivered: 'Accepté par le serveur destinataire',
        temporary: 'Échec temporaire',
        permanent: 'Refus permanent',
      } as Record<string, string>
    )[outcome] ?? `Résultat inconnu (${outcome})`
  );
}
export function nextRetry(
  status: string,
  nextAttempt: number,
  now = Date.now(),
) {
  if (status === 'sending')
    return 'Tentative en cours ; prochaine échéance non connue.';
  if (status !== 'pending')
    return 'Aucune nouvelle tentative planifiée dans cet état.';
  if (
    !Number.isFinite(nextAttempt) ||
    nextAttempt <= 0 ||
    !Number.isFinite(new Date(nextAttempt * 1000).getTime())
  )
    return 'Prochaine tentative : date non enregistrée.';
  return nextAttempt * 1000 <= now
    ? `Nouvelle tentative attendue depuis le ${timestamp(nextAttempt)} ; en attente du relais.`
    : `Prochaine tentative prévue le ${timestamp(nextAttempt)}.`;
}
export function transcriptNotice(
  logCount: number,
  logsAvailable = logCount,
  logsTruncated = false,
) {
  if (logsTruncated || logsAvailable > logCount)
    return `Historique partiel : ${logCount} ${logCount > 1 ? 'journaux chargés' : 'journal chargé'} sur ${logsAvailable} disponible(s). Certains journaux ne sont pas chargés dans cette vue.`;
  if (!logCount)
    return 'Aucune transcription SMTP historique enregistrée. L’absence de journal ne permet pas de déduire les échanges effectués.';
  return `${logCount} ${logCount > 1 ? 'journaux' : 'journal'} SMTP enregistré${logCount > 1 ? 's' : ''}.`;
}
export function smtpPhase(phase: string) {
  return (
    (
      {
        dns: 'Résolution DNS',
        connect: 'Connexion TCP',
        greeting: 'Accueil SMTP',
        ehlo: 'EHLO · capacités du serveur',
        starttls: 'STARTTLS · demande de chiffrement',
        tls: 'TLS · négociation et vérification du certificat',
        tls_verified: 'TLS · certificat vérifié',
        ehlo_tls: 'EHLO après TLS',
        mail: 'MAIL FROM · expéditeur',
        mail_from: 'MAIL FROM · expéditeur',
        rcpt: 'RCPT TO · destinataire',
        rcpt_to: 'RCPT TO · destinataire',
        data: 'DATA · ouverture du transfert',
        data_result: 'Réponse finale après le transfert',
        data_end: 'Réponse finale après le transfert',
        final: 'Réponse finale après le transfert',
        final250: 'Réponse finale après le transfert',
        final_250: 'Réponse finale après le transfert',
        quit: 'QUIT · fermeture de session',
        error: 'Erreur de transmission',
      } as Record<string, string>
    )[phase.toLowerCase()] ?? `Étape ${phase}`
  );
}
export function smtpReply(code: number | null, enhanced: string | null) {
  const kind =
    code == null
      ? 'Sans code SMTP enregistré'
      : code >= 500 && code < 600
        ? `${code} · refus permanent`
        : code >= 400 && code < 500
          ? `${code} · échec temporaire`
          : code >= 300 && code < 400
            ? `${code} · poursuite de l’échange`
            : code >= 200 && code < 300
              ? `${code} · commande acceptée`
              : `${code} · réponse SMTP`;
  return enhanced ? `${kind} · ${enhanced}` : kind;
}
export function evidenceState(state?: string) {
  return (
    (
      {
        disabled: 'Désactivé',
        not_run: 'Non effectué',
        complete: 'Effectué',
        unavailable: 'Indisponible',
        busy: 'Capacité occupée',
        skipped: 'Non sollicité',
        limited: 'Partiel',
      } as Record<string, string>
    )[state ?? ''] ?? 'État non enregistré'
  );
}
export function authenticationResult(value: string | null | undefined) {
  return (
    (
      {
        pass: 'Réussi (pass)',
        fail: 'Échec (fail)',
        soft_fail: 'Échec souple (softfail)',
        neutral: 'Neutre',
        none: 'Aucun résultat d’authentification (none)',
        temp_error: 'Erreur temporaire',
        perm_error: 'Erreur permanente',
      } as Record<string, string>
    )[value ?? ''] ?? 'Résultat non enregistré'
  );
}
