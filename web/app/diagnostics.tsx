'use client';
import { useEffect, useId, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from './client';
import {
  authenticationResult,
  contribution,
  deliveryStatus,
  duration,
  evidenceState,
  nextRetry,
  policySummary,
  smtpOutcome,
  smtpPhase,
  smtpReply,
  timestamp,
  transcriptNotice,
  recipientHistory,
  type AuthenticationEvidence,
  type DiagnosticReason,
  type DiagnosticRecipient,
  type RecipientHistory,
  type MessageDiagnostics,
  type SmtpLog,
} from './diagnostics-formatters';

function AuthenticationDetails({ auth }: { auth?: AuthenticationEvidence }) {
  return (
    <section
      className="diagnostic-section"
      aria-label="Authentification du message"
    >
      <h3>Authentification SPF, DKIM, DMARC et ARC</h3>
      {!auth ? (
        <p className="diagnostic-muted">
          Aucune preuve d’authentification historique enregistrée.
        </p>
      ) : (
        <>
          <p className="diagnostic-muted">
            Contrôles SPF / DKIM / DMARC : {evidenceState(auth.state)}. ARC est
            contrôlé séparément. Un contrôle absent ou indisponible n’est pas un
            résultat réussi.
          </p>
          <dl className="diagnostic-facts diagnostic-auth">
            <div>
              <dt>SPF · {evidenceState(auth.spf_state)}</dt>
              <dd>{authenticationResult(auth.spf)}</dd>
            </div>
            <div>
              <dt>DKIM · {evidenceState(auth.dkim_state)}</dt>
              <dd>
                {auth.dkim == null ? (
                  'Résultat non enregistré'
                ) : auth.dkim.length === 0 ? (
                  'Aucune signature DKIM enregistrée'
                ) : (
                  <ul>
                    {auth.dkim.map((result, index) => (
                      <li key={index}>
                        Signature {index + 1} : {authenticationResult(result)}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </div>
            <div>
              <dt>DMARC · {evidenceState(auth.dmarc_state)}</dt>
              <dd>
                Alignement SPF : {authenticationResult(auth.dmarc_spf)}
                <br />
                Alignement DKIM : {authenticationResult(auth.dmarc_dkim)}
              </dd>
            </div>
            <div>
              <dt>ARC · {evidenceState(auth.arc_state)}</dt>
              <dd>
                {authenticationResult(auth.arc)}
                <br />
                {auth.arc_can_seal == null
                  ? 'Possibilité de scellement non enregistrée'
                  : auth.arc_can_seal
                    ? 'Scellement possible'
                    : 'Scellement non possible'}
              </dd>
            </div>
          </dl>
        </>
      )}
    </section>
  );
}

function AnalysisDetails({
  analysis,
  reasons,
  source,
}: {
  analysis: MessageDiagnostics['analysis'];
  reasons: DiagnosticReason[];
  source?: string;
}) {
  const overrides = Object.entries(analysis.policy?.rule_weights ?? {}).filter(
    ([id]) => reasons.some((reason) => reason.id === id),
  );
  return (
    <section
      className="diagnostic-section"
      aria-label="Analyse enregistrée à la réception"
    >
      <h3>Analyse enregistrée à la réception</h3>
      <dl className="diagnostic-facts">
        <div>
          <dt>Durée totale de l’analyse</dt>
          <dd>{duration(analysis.elapsed_ms)}</dd>
        </div>
        <div>
          <dt>Version d’extraction</dt>
          <dd>{analysis.feature_version}</dd>
        </div>
        <div>
          <dt>Extraction des caractéristiques</dt>
          <dd>
            {analysis.features_complete == null
              ? 'Complétude historique non enregistrée'
              : analysis.features_complete
                ? 'Complète'
                : 'Partielle'}
          </dd>
        </div>
      </dl>
      <p className="diagnostic-callout">{policySummary(analysis.policy)}</p>
      {analysis.policy && (
        <p className="diagnostic-muted">
          Version de politique : <code>{analysis.policy.version}</code>.
          {source === 'fusion' &&
            ' Ce seuil appartient au calcul historique, pas au modèle de fusion.'}
          {source === 'antivirus' &&
            ' La priorité antivirus ne dépend pas de ce seuil.'}
        </p>
      )}
      <dl className="diagnostic-facts">
        <div>
          <dt>Modèle lexical · log-odds</dt>
          <dd>{contribution(analysis.lexical_logit)}</dd>
          <dd className="diagnostic-muted">
            {evidenceState(analysis.evidence?.lexical_state)}
          </dd>
        </div>
        <div>
          <dt>Contribution sémantique · log-odds</dt>
          <dd>{contribution(analysis.semantic_contribution)}</dd>
          <dd className="diagnostic-muted">
            {evidenceState(analysis.evidence?.semantic_state)}
          </dd>
        </div>
        <div>
          <dt>Total des poids de règles · log-odds</dt>
          <dd>{contribution(analysis.rule_weight_total)}</dd>
        </div>
      </dl>
      <p className="diagnostic-muted">
        Valeurs du calcul historique, avant conversion en score : ce ne sont pas
        des pourcentages et elles ne totalisent pas 100. Une contribution non
        enregistrée n’est pas un zéro. Les indices peuvent être corrélés.
      </p>
      {analysis.score_breakdown && <details className="diagnostic-disclosure">
        <summary>Contributions par famille de contrôles</summary>
        <dl className="diagnostic-facts">{Object.entries(analysis.score_breakdown.families).map(([family,value])=><div key={family}>
          <dt>{({lexical:'Texte et structure',semantic:'Analyse sémantique',content_unseparated:'Contenu, détail historique absent',heuristics:'Règles de contenu',authentication:'Authentification',reputation:'Réputation',smtp:'Contrôles SMTP',llm:'Second avis',other_rules:'Autres règles'} as Record<string,string>)[family] ?? 'Autres contributions'}</dt><dd>{contribution(value)}</dd>
        </div>)}</dl>
        <p className="diagnostic-muted">{analysis.score_breakdown.matches_recorded_score ? 'La somme reproduit le score historique enregistré.' : 'Les observations conservées ne suffisent pas à reproduire exactement le score historique.'}
          {analysis.score_breakdown.saturated && ' L’indice est proche d’une extrémité ; ce n’est pas une preuve de certitude.'}</p>
      </details>}
      {analysis.native_filter && <details className="diagnostic-disclosure">
        <summary>Moteur Rust : règles composites, campagnes et Bayes</summary>
        <p className="diagnostic-muted">Observation comparative sans effet sur la livraison. Les points et le résultat Bayes ne sont pas des probabilités calibrées.</p>
        <dl className="diagnostic-facts">
          <div><dt>Analyse locale</dt><dd>{evidenceState(analysis.native_filter.status)} · {duration(analysis.native_filter.elapsed_ms)}</dd></div>
          <div><dt>Points après plafonds</dt><dd>{contribution(analysis.native_filter.score?.total)}</dd></div>
          <div><dt>Classifieur OSB Bayes</dt><dd>{({untrained:'Aucun modèle entraîné',complete:'Analyse disponible',scope_mismatch:'Domaine hors du modèle',expired:'Modèle expiré',insufficient_features:'Indices insuffisants',incompatible:'Protocole incompatible'} as Record<string,string>)[analysis.native_filter.bayes.status] ?? 'Analyse indisponible'}</dd></div>
          <div><dt>Mémoire de campagnes</dt><dd>{evidenceState(analysis.native_filter.fuzzy.status)} · {analysis.native_filter.fuzzy.matches} correspondance(s) textuelle(s)
            {analysis.native_filter.fuzzy.conflict && ' · corrections contradictoires, aucun renforcement'}</dd></div>
        </dl>
        {analysis.native_filter.score && <>
          <table className="diagnostic-table"><caption>Contributions regroupées</caption><thead><tr><th>Famille</th><th>Brute</th><th>Retenue</th></tr></thead>
            <tbody>{Object.entries(analysis.native_filter.score.families).map(([family,weight])=><tr key={family}><td>{({lexical:'Texte et structure',semantic:'Sémantique',content:'Règles de contenu',authentication:'Authentification',reputation:'Réputation',smtp:'SMTP',llm:'Second avis',campaign:'Campagnes',bayes:'OSB Bayes',other:'Autres'} as Record<string,string>)[family] ?? family}</td><td>{contribution(weight.raw)}</td><td>{contribution(weight.effective)}{weight.capped && ' · plafonnée'}</td></tr>)}</tbody>
          </table>
          <ul>{analysis.native_filter.score.symbols.map(symbol=><li key={symbol.id}><code>{symbol.id}</code> · {symbol.label} · {contribution(symbol.weight)}
            {symbol.absorbed_by.length>0 && ` · regroupé dans ${symbol.absorbed_by.join(', ')}`}</li>)}</ul>
        </>}
      </details>}
      {overrides.length > 0 && (
        <details className="diagnostic-disclosure">
          <summary>
            Poids personnalisés enregistrés pour les règles déclenchées
          </summary>
          <dl className="diagnostic-facts">
            {overrides.map(([id, weight]) => (
              <div key={id}>
                <dt>
                  <code>{id}</code>
                </dt>
                <dd>{contribution(weight)} log-odds</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </section>
  );
}

function SmtpAttempt({ log, latest }: { log: SmtpLog; latest: boolean }) {
  return (
    <details
      className="smtp-attempt diagnostic-disclosure"
      open={latest ? true : undefined}
    >
      <summary>
        <span>
          Tentative {log.attempt} · {smtpOutcome(log.outcome)}
        </span>
        <span className="diagnostic-muted">
          {timestamp(log.started)} · {duration(log.elapsed_ms)}
        </span>
      </summary>
      <dl className="diagnostic-facts">
        <div>
          <dt>Route SMTP</dt>
          <dd>{log.route || 'Route non enregistrée'}</dd>
        </div>
        <div>
          <dt>Serveur joint (pair)</dt>
          <dd>{log.peer || 'Pair non enregistré'}</dd>
        </div>
      </dl>
      {log.truncated && (
        <p className="diagnostic-callout">
          Journal tronqué : des étapes ou réponses peuvent manquer.
        </p>
      )}
      {log.events.length ? (
        <ol
          className="smtp-timeline"
          aria-label={`Échanges SMTP de la tentative ${log.attempt}`}
        >
          {log.events.map((event, index) => (
            <li key={index}>
              <div className="smtp-event-heading">
                <strong>{smtpPhase(event.phase)}</strong>
                <span className="diagnostic-muted">
                  + {duration(event.elapsed_ms)} depuis le début
                </span>
              </div>
              {(event.code != null || event.enhanced_code) && (
                <p className="smtp-reply-code">
                  {smtpReply(event.code, event.enhanced_code)}
                </p>
              )}
              {event.response && (
                <p className="smtp-response">{event.response}</p>
              )}
              {event.detail && (
                <p className="smtp-response diagnostic-muted">{event.detail}</p>
              )}
              {event.code == null && !event.response && !event.detail && (
                <p className="diagnostic-muted">
                  Aucune réponse détaillée enregistrée.
                </p>
              )}
            </li>
          ))}
        </ol>
      ) : (
        <p className="diagnostic-muted">
          Aucune étape SMTP détaillée enregistrée pour cette tentative.
        </p>
      )}
    </details>
  );
}

function RecipientDetails({
  recipient,
  messageId,
  refreshing,
  refreshSignal,
  onRecipientLoaded,
}: {
  recipient: DiagnosticRecipient;
  messageId: string;
  refreshing: boolean;
  refreshSignal: AbortSignal;
  onRecipientLoaded: (
    messageId: string,
    recipient: DiagnosticRecipient,
  ) => void;
}) {
  const headingId = useId();
  const historyRequest = useRef<AbortController | null>(null);
  const [history, setHistory] = useState<{
    data: RecipientHistory | null;
    loading: boolean;
    error: string;
  }>({ data: null, loading: false, error: '' });
  useEffect(() => () => historyRequest.current?.abort(), []);
  async function loadHistory() {
    if (refreshing || refreshSignal.aborted) return;
    historyRequest.current?.abort();
    const controller = new AbortController();
    historyRequest.current = controller;
    const abort = () => controller.abort();
    refreshSignal.addEventListener('abort', abort, { once: true });
    setHistory((previous) => ({ ...previous, loading: true, error: '' }));
    try {
      const data = await api<MessageDiagnostics>(
        `/messages/${encodeURIComponent(messageId)}/diagnostics?delivery_id=${encodeURIComponent(recipient.delivery_id)}`,
        undefined,
        undefined,
        { signal: controller.signal, cache: 'no-store' },
      );
      const updated = recipientHistory(
        data,
        messageId,
        recipient.delivery_id,
        controller.signal,
      );
      if (!updated) return;
      setHistory({
        data: updated,
        loading: false,
        error: '',
      });
      onRecipientLoaded(messageId, updated);
    } catch (error: unknown) {
      if (controller.signal.aborted) return;
      setHistory((previous) => ({
        ...previous,
        loading: false,
        error:
          error instanceof Error
            ? error.message
            : 'Le chargement de l’historique a échoué.',
      }));
    } finally {
      refreshSignal.removeEventListener('abort', abort);
    }
  }
  const displayedHistory = history.data ?? recipient;
  // The API caps logs per recipient. Preserve event order inside each attempt.
  const logs = [...displayedHistory.logs].sort(
    (a, b) => b.started - a.started || b.id - a.id,
  );
  return (
    <section className="diagnostic-recipient" aria-labelledby={headingId}>
      <h4 id={headingId}>{recipient.address}</h4>
      <p className="diagnostic-delivery-state">
        {deliveryStatus(displayedHistory.status)}
      </p>
      <dl className="diagnostic-facts">
        <div>
          <dt>Destination de transmission</dt>
          <dd>{displayedHistory.destination || 'Non enregistrée'}</dd>
        </div>
        <div>
          <dt>Tentatives effectuées</dt>
          <dd>{displayedHistory.attempts}</dd>
        </div>
      </dl>
      <p>{nextRetry(displayedHistory.status, displayedHistory.next_attempt)}</p>
      {displayedHistory.last_error && (
        <div className="diagnostic-callout">
          <strong>Dernière erreur enregistrée</strong>
          <p className="smtp-response">{displayedHistory.last_error}</p>
        </div>
      )}
      <p className="diagnostic-muted">
        {transcriptNotice(
          logs.length,
          displayedHistory.logs_available,
          displayedHistory.logs_truncated,
        )}
      </p>
      {(recipient.logs_truncated ||
        recipient.logs_available > recipient.logs.length ||
        history.data) && (
        <div className="diagnostic-history-controls">
          <Button
            variant="outline"
            disabled={history.loading || refreshing}
            onClick={() => void loadHistory()}
            aria-label={`${history.error ? 'Réessayer le chargement de' : history.data ? 'Actualiser' : 'Charger'} l’historique SMTP de ${recipient.address}`}
          >
            <RefreshCw
              size={16}
              aria-hidden="true"
              className={history.loading ? 'spin' : ''}
            />
            {history.loading
              ? 'Chargement de l’historique…'
              : history.error
                ? 'Réessayer'
                : history.data
                  ? 'Actualiser l’historique SMTP'
                  : 'Charger l’historique SMTP'}
          </Button>
          <p className="diagnostic-muted">
            Les 50 journaux les plus récents de ce destinataire au maximum.
            L’actualisation globale recharge la vue limitée de tous les
            destinataires.
          </p>
        </div>
      )}
      <output className="diagnostic-muted diagnostic-loading-status">
        {history.loading
          ? 'Chargement des journaux de ce destinataire…'
          : history.data && !history.error
            ? 'Historique de ce destinataire actualisé.'
            : ''}
      </output>
      {history.error && (
        <div className="diagnostic-callout" role="alert">
          <p>Historique indisponible : {history.error}</p>
          <p>Les journaux déjà reçus restent affichés.</p>
        </div>
      )}
      <div aria-busy={history.loading}>
        {logs.map((log, index) => (
          <SmtpAttempt key={log.id} log={log} latest={index === 0} />
        ))}
      </div>
    </section>
  );
}

export default function Diagnostics({
  messageId,
  reasons,
  source,
  revision,
  onLoaded,
  onRecipientLoaded,
}: {
  messageId: string;
  reasons: DiagnosticReason[];
  source?: string;
  revision: number;
  onLoaded: (diagnostics: MessageDiagnostics) => void;
  onRecipientLoaded: (
    messageId: string,
    recipient: DiagnosticRecipient,
  ) => void;
}) {
  const titleId = useId();
  // Abort scoped work immediately when global refresh starts, before React's
  // keyed recipient cleanup. Recipient unmounts also cancel their own requests.
  const [{ request, scope: refreshScope }, setRefresh] = useState(() => ({
    request: 0,
    scope: new AbortController(),
  }));
  const [state, setState] = useState<{
    messageId: string;
    data: MessageDiagnostics | null;
    request: number;
    revision: number;
    error: string;
    updated: number | null;
  }>({
    messageId,
    data: null,
    request: -1,
    revision: -1,
    error: '',
    updated: null,
  });
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    api<MessageDiagnostics>(
      `/messages/${encodeURIComponent(messageId)}/diagnostics`,
      undefined,
      undefined,
      { signal: controller.signal, cache: 'no-store' },
    )
      .then((data) => {
        if (!active) return;
        if (data.message_id !== messageId)
          throw new Error(
            'Le diagnostic reçu ne correspond pas au message sélectionné.',
          );
        setState({
          messageId,
          data,
          request,
          revision,
          error: '',
          updated: Date.now() / 1000,
        });
        onLoaded(data);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setState((previous) => ({
          messageId,
          data: previous.messageId === messageId ? previous.data : null,
          updated: previous.messageId === messageId ? previous.updated : null,
          request,
          revision,
          error:
            error instanceof Error
              ? error.message
              : 'Le chargement des diagnostics a échoué.',
        }));
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [messageId, request, revision, onLoaded]);
  // Never show the previous message, even before the new selection's effect runs.
  const visible = state.messageId === messageId ? state : null;
  const loading =
    !visible || visible.request !== request || visible.revision !== revision;
  const error = loading ? '' : visible?.error;
  const data = visible?.data;
  return (
    <section className="panel message-diagnostics" aria-labelledby={titleId}>
      <div className="diagnostic-heading">
        <h2 id={titleId}>Diagnostics du message</h2>
        <Button
          variant="outline"
          disabled={loading}
          onClick={() => {
            refreshScope.abort();
            setRefresh((previous) => ({
              request: previous.request + 1,
              scope: new AbortController(),
            }));
          }}
        >
          <RefreshCw
            size={16}
            aria-hidden="true"
            className={loading ? 'spin' : ''}
          />
          {loading
            ? 'Chargement…'
            : error
              ? 'Réessayer'
              : 'Actualiser les diagnostics'}
        </Button>
      </div>
      <p className="diagnostic-queue-id">
        <span className="diagnostic-muted">Identifiant de file : </span>
        <code>{messageId}</code>
      </p>
      <output className="diagnostic-muted diagnostic-loading-status">
        {loading
          ? data
            ? 'Actualisation des tentatives SMTP… Les dernières données reçues restent affichées.'
            : 'Chargement de l’analyse et des journaux SMTP…'
          : visible?.updated
            ? `Dernière lecture : ${timestamp(visible.updated)}.`
            : ''}
      </output>
      {error && (
        <div className="diagnostic-callout" role="alert">
          <p>Diagnostics indisponibles : {error}</p>
          {data && (
            <p>
              Les données affichées datent de la dernière lecture réussie ; la
              livraison a pu évoluer.
            </p>
          )}
        </div>
      )}
      <div aria-busy={loading}>
        {data && (
          <>
            <AnalysisDetails
              analysis={data.analysis}
              reasons={reasons}
              source={source}
            />
            <AuthenticationDetails
              auth={data.analysis.evidence?.authentication}
            />
            <section
              className="diagnostic-section"
              aria-label="Transmission SMTP par destinataire"
            >
              <h3>Transmission SMTP par destinataire</h3>
              <p className="diagnostic-callout">
                « Accepté » signifie que le serveur destinataire a accepté le
                message après son transfert. Cela ne garantit pas son arrivée
                dans la boîte de réception : le fournisseur peut encore le
                filtrer ou le classer.
              </p>
              <p className="diagnostic-muted">
                Seuls les destinataires autorisés sont affichés. Actualisez pour
                suivre les nouvelles tentatives.
              </p>
              {data.recipients.length ? (
                data.recipients.map((recipient) => (
                  <RecipientDetails
                    // A global refresh discards scoped histories and cancels their in-flight requests.
                    key={`${messageId}:${recipient.delivery_id}:${request}:${revision}`}
                    recipient={recipient}
                    messageId={messageId}
                    refreshing={loading}
                    refreshSignal={refreshScope.signal}
                    onRecipientLoaded={onRecipientLoaded}
                  />
                ))
              ) : (
                <p>Aucun destinataire autorisé disponible pour ce message.</p>
              )}
            </section>
          </>
        )}
      </div>
    </section>
  );
}
