'use client';
import { OnboardingGate } from './onboarding';
import { AdaptiveDetails } from './adaptive';
import type { AdaptiveReport, AdaptiveClass } from './adaptive-types';
import { EarlyRblDetails } from './rbl';
import type { EarlyRbl } from './rbl-types';
import { FilteringDetails, type FilteringAssessment } from './custom-filtering';
import { actionLabel, type DeliveryAction } from './actions';
import { ConfirmDialog } from './console-ui';
import { MyAccount } from './account';
import { BrandMark, LoginStory, ScoreMeter } from './brand';
import {
  classification,
  deliverySummary,
  checkFailure,
  publicitySignal,
  arbitrationExplanation,
  type Arbitration,
} from './presentation';
import {
  deliveryStatus,
  mergeDiagnosticRecipient,
  type DiagnosticRecipient,
  type MessageDiagnostics,
} from './diagnostics-formatters';
import { RuleDetails } from './rule-details';
import {
  MailingDetails,
  type MailingReport,
  type FeedbackCategory,
} from './mailing';
import { ProtectionDetails, type ProtectionReport } from './protection';
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import {
  ShieldCheck,
  Search,
  LogOut,
  ArrowLeft,
  Check,
  Flag,
  Inbox,
  Archive,
  UserRound,
  RefreshCw,
  X,
  ChevronRight,
  Menu,
  Clock3,
  ArrowUpRight,
  LockKeyhole,
  Eye,
  EyeOff,
  Globe2,
  SlidersHorizontal,
  Rows3,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { api, type User } from './client';
import { AdminConsole, navigation, type Section } from './admin';
import { QualityConsole, QualityDetails } from './quality';
import { ReliabilityConsole } from './reliability';
import type { QualityReport } from './quality-types';
import { registerFeedbackTool } from './webmcp';
const Diagnostics = lazy(() => import('./diagnostics'));
type Mail = {
  arbitration?: Arbitration | null;
  delivery_classification?: string | null;
  action?: {
    requested: DeliveryAction;
    effective: DeliveryAction;
    reason: string;
    quarantine_days: number;
  } | null;
  quality?: QualityReport | null;
  protection?: ProtectionReport;
  mailing?: MailingReport;
  category: FeedbackCategory | 'undetermined';
  pub_tagged: boolean;
  feedback_category: FeedbackCategory | null;
  id: string;
  created: number;
  sender: string;
  subject: string;
  score: number;
  tagged: boolean;
  complete: boolean;
  model: string;
  decision?: {
    source: 'legacy' | 'fusion' | 'antivirus';
    outcome: 'legitimate' | 'unwanted' | 'undetermined';
    score: number | null;
    model: string;
  };
  fusion?: {
    mode: 'observe' | 'decision';
    status:
      | 'disabled'
      | 'not_run'
      | 'complete'
      | 'unavailable'
      | 'unsupported_profile'
      | 'validation_expired';
    model: string;
    prediction: {
      probability: number;
      tag_eligible: boolean;
      profile_supported: boolean;
      above_threshold: boolean;
      contributions: { feature: string; contribution: number }[];
    } | null;
  };
  reasons: { id: string; detail: string; weight: number }[];
  recipients: {
    filtering?: FilteringAssessment | null;
    delivery_id?: number;
    address: string;
    status: string;
    held_until?: number | null;
    released_at?: number | null;
  }[];
  feedback: boolean | null;
  antivirus?: {
    status:
      | 'disabled'
      | 'clean'
      | 'malware'
      | 'suspicious'
      | 'unscannable'
      | 'unavailable';
    signature: string | null;
    elapsed_ms: number;
  };
  signatures?: {
    status:
      | 'disabled'
      | 'clean'
      | 'malware'
      | 'suspicious'
      | 'unscannable'
      | 'unavailable';
    signature: string | null;
    elapsed_ms: number;
  };
  llm?: {
    failure?: string | null;
    status:
      | 'disabled'
      | 'not_needed'
      | 'busy'
      | 'budget_limited'
      | 'pricing_expired'
      | 'unavailable'
      | 'complete';
    model: string;
    prompt_version: string;
    elapsed_ms: number;
  };
  smtp_policy?: {
    status: 'disabled' | 'complete' | 'busy' | 'unavailable';
    elapsed_ms: number;
    candidate_weight: number;
    applied_weight: number;
    scoring_enabled: boolean;
  };
  early_rbl?: EarlyRbl;
  adaptive?: AdaptiveReport;
  semantic?: {
    status: 'disabled' | 'complete' | 'busy' | 'unavailable';
    model: string;
    encoder: string;
    elapsed_ms: number;
  };
  vision?: {
    status: 'disabled' | 'complete' | 'limited' | 'unavailable' | 'busy';
    parts: number;
    pages: number;
    text_chars: number;
    qr_codes: number;
    other_codes: number;
    link_domains: number;
    elapsed_ms: number;
  };
};
type Stats = {
  received: number;
  flagged: number;
  publicity: number;
  pending: number;
  quarantined: number;
  mode: string;
  threshold: number;
  decision_source?: 'legacy' | 'fusion';
};
function displayedScore(mail: Mail) {
  return mail.decision
    ? mail.decision.score
    : mail.complete
      ? mail.score
      : null;
}
const fusionFamilies: Record<string, string> = {
  lexical: 'Contenu textuel',
  semantic: 'Sens du message',
  auth: 'Authentification',
  reputation: 'Réputation',
  smtp_policy: 'Cohérence SMTP et DNS',
  antivirus: 'Antivirus',
  signatures: 'Signatures complémentaires',
  llm: 'Analyse complémentaire',
};
function fusionReason(feature: string) {
  const family =
    fusionFamilies[feature.split('.')[0]] ?? 'Observations combinées';
  if (feature.includes('unavailable'))
    return `${family} : contrôle indisponible`;
  if (feature.includes('busy')) return `${family} : capacité occupée`;
  if (feature.includes('not_run')) return `${family} : contrôle non effectué`;
  if (feature.includes('disabled')) return `${family} : contrôle désactivé`;
  if (feature.includes('limited')) return `${family} : analyse limitée`;
  return family;
}
export default function Page() {
  return (
    <OnboardingGate>
      <Home />
    </OnboardingGate>
  );
}
function Home() {
  const [showPassword, setShowPassword] = useState(false);
  const searchInput = useRef<HTMLInputElement>(null);
  const [section, setSection] = useState<
    Section | 'account' | 'quality' | 'reliability'
  >('messages');
  const [mobileMenu, setMobileMenu] = useState(false);
  const [loading, setLoading] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [confirmation, setConfirmation] = useState<{
    recipient: string;
    action: 'release' | 'delete';
  } | null>(null);
  const [confirmationError, setConfirmationError] = useState('');
  const [domain, setDomain] = useState('');
  const [domains, setDomains] = useState<string[]>([]);
  const [configDirty, setConfigDirty] = useState(false);
  const [user, setUser] = useState<User | null>(null),
    [ready, setReady] = useState(false),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false);
  const [username, setUsername] = useState(''),
    [password, setPassword] = useState('');
  const [search, setSearch] = useState(''),
    [filter, setFilter] = useState('all'),
    [offset, setOffset] = useState(0);
  const [compact, setCompact] = useState(false);
  const [mails, setMails] = useState<Mail[]>([]),
    [selected, setSelected] = useState<Mail | null>(null),
    [stats, setStats] = useState<Stats | null>(null),
    [notice, setNotice] = useState('');
  const [diagnosticsRevision, setDiagnosticsRevision] = useState(0);
  const [historicalThreshold, setHistoricalThreshold] = useState<{
    messageId: string;
    threshold: number | undefined;
  } | null>(null);
  const activeUser = useRef<User | null>(null);
  const latestRequest = useRef(0);
  const changeSession = useCallback((next: User | null) => {
    activeUser.current = next;
    latestRequest.current += 1;
    setUser(next);
    setMails([]);
    setStats(null);
    setSelected(null);
    setHistoricalThreshold(null);
    setNotice('');
    setPassword('');
    setShowPassword(false);
    setConfirmation(null);
    setConfirmationError('');
    setMobileMenu(false);
    setUpdatedAt(null);
    setLoading(!!next);
    setBusy(false);
    setSearch('');
    setFilter('all');
    setOffset(0);
    setSection('messages');
    setDomain('');
    setDomains([]);
    setConfigDirty(false);
  }, []);
  const diagnosticsLoaded = useCallback(
    (data: MessageDiagnostics) => {
      if (!user || user !== activeUser.current) return;
      setHistoricalThreshold({
        messageId: data.message_id,
        threshold: data.analysis.policy?.threshold,
      });
      setSelected((previous) =>
        previous?.id === data.message_id
          ? {
              ...previous,
              recipients: data.recipients.map((recipient) => ({
                ...previous.recipients.find(
                  (existing) => existing.address === recipient.address,
                ),
                address: recipient.address,
                delivery_id: recipient.delivery_id,
                status: recipient.status,
              })),
            }
          : previous,
      );
    },
    [user],
  );
  const recipientLoaded = useCallback(
    (messageId: string, recipient: DiagnosticRecipient) => {
      if (!user || user !== activeUser.current) return;
      setSelected((previous) =>
        previous?.id === messageId
          ? {
              ...previous,
              recipients: mergeDiagnosticRecipient(
                previous.recipients,
                recipient,
              ),
            }
          : previous,
      );
    },
    [user],
  );
  useEffect(() => {
    const expired = () => changeSession(null);
    window.addEventListener('session-expired', expired);
    return () => window.removeEventListener('session-expired', expired);
  }, [changeSession]);
  useEffect(() => {
    api<User>('/me')
      .then(changeSession)
      .catch(() => {})
      .finally(() => setReady(true));
  }, [changeSession]);
  const refresh = useCallback(async () => {
    if (!user || user !== activeUser.current) return;
    const requestId = ++latestRequest.current;
    setLoading(true);
    try {
      const [messages, totals, scope] = await Promise.all([
        api<Mail[]>(
          `/messages?q=${encodeURIComponent(search)}&filter=${filter}&offset=${offset}&domain=${encodeURIComponent(domain)}`,
        ),
        api<Stats>(`/stats?domain=${encodeURIComponent(domain)}`),
        api<string[]>('/domains'),
      ]);
      if (user !== activeUser.current || requestId !== latestRequest.current)
        return;
      setMails(messages);
      setStats(totals);
      setDomains(scope);
      setUpdatedAt(new Date());
      setError('');
    } catch (e) {
      if (user === activeUser.current && requestId === latestRequest.current)
        setError((e as Error).message);
    } finally {
      if (user === activeUser.current && requestId === latestRequest.current)
        setLoading(false);
    }
  }, [user, search, filter, offset, domain]);
  useEffect(() => {
    const timer = setTimeout(refresh, 200);
    return () => clearTimeout(timer);
  }, [refresh]);
  useEffect(() => {
    if (!user || section !== 'messages' || selected || confirmation || busy)
      return;
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') void refresh();
    }, 30000);
    return () => clearInterval(timer);
  }, [user, section, selected, confirmation, busy, refresh]);
  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      if (
        user &&
        section === 'messages' &&
        !selected &&
        !confirmation &&
        (event.metaKey || event.ctrlKey) &&
        event.key.toLowerCase() === 'k'
      ) {
        event.preventDefault();
        searchInput.current?.focus();
      }
    };
    window.addEventListener('keydown', focusSearch);
    return () => window.removeEventListener('keydown', focusSearch);
  }, [user, section, selected, confirmation]);
  function navigate(
    next: Section | 'account' | 'quality' | 'reliability',
    nextFilter = 'all',
  ) {
    setSection(next);
    setFilter(nextFilter);
    setOffset(0);
    setSelected(null);
    setNotice('');
    setMobileMenu(false);
  }
  const [feedbackRevision, setFeedbackRevision] = useState(0);
  function adaptiveCorrect(id: string, value: AdaptiveClass | null) {
    if (value) {
      const category =
        value === 'phishing' || value === 'scam' ? 'spam' : value;
      setSelected((previous) =>
        previous?.id === id
          ? {
              ...previous,
              feedback: category === 'spam',
              feedback_category: category,
            }
          : previous,
      );
    }
    void refresh();
  }
  const recordFeedback = useCallback(
    async (id: string, category: FeedbackCategory) => {
      if (!user) throw new Error('Connexion requise.');
      await api(`/messages/${id}/feedback`, { category }, user.csrf);
      setFeedbackRevision((r) => r + 1);
      if (user !== activeUser.current) return;
      setSelected((previous) =>
        previous?.id === id
          ? {
              ...previous,
              feedback: category === 'spam',
              feedback_category: category,
            }
          : previous,
      );
      setNotice(
        'Correction enregistrée. Le message déjà livré dans Proton reste inchangé.',
      );
      await refresh();
    },
    [user, refresh],
  );
  useEffect(
    () => (user ? registerFeedbackTool(recordFeedback) : undefined),
    [user, recordFeedback],
  );
  async function feedback(category: FeedbackCategory) {
    if (!selected || !user) return;
    setBusy(true);
    try {
      await recordFeedback(selected.id, category);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function quarantineAction(
    recipient: string,
    action: 'release' | 'delete',
  ) {
    if (!selected || !user) return;
    const id = selected.id;
    setBusy(true);
    setError('');
    setNotice('');
    setConfirmationError('');
    try {
      const result = await api<{ status: string }>(
        `/messages/${id}/quarantine`,
        { recipient, action },
        user.csrf,
      );
      if (user !== activeUser.current) return;
      setSelected((previous) =>
        previous?.id === id
          ? {
              ...previous,
              recipients: previous.recipients.map((r) =>
                r.address === recipient ? { ...r, status: result.status } : r,
              ),
            }
          : previous,
      );
      setConfirmation(null);
      setDiagnosticsRevision((value) => value + 1);
      setNotice(
        action === 'release'
          ? 'Message libéré : livraison en attente pour ce destinataire.'
          : 'Livraison retenue supprimée pour ce destinataire.',
      );
      await refresh();
    } catch (e) {
      if (user === activeUser.current)
        setConfirmationError((e as Error).message);
    } finally {
      if (user === activeUser.current) setBusy(false);
    }
  }
  if (!ready)
    return (
      <main className="connection-screen">
        <BrandMark />
        <output>
          <RefreshCw size={16} className="spin" /> Connexion à votre espace…
        </output>
      </main>
    );
  if (!user)
    return (
      <main className="login">
        <LoginStory />
        <div className="login-form-side">
          <div className="login-mobile-brand">
            <BrandMark /> NoiseFence
          </div>
          <form
            className="login-card"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError('');
              try {
                changeSession(
                  await api<User>('/login', { username, password }),
                );
                setPassword('');
              } catch (e) {
                setError((e as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <span className="login-lock">
              <LockKeyhole size={22} />
            </span>
            <p className="eyebrow">BIENVENUE DANS VOTRE ESPACE</p>
            <h1>Content de vous retrouver.</h1>
            <p className="muted">
              Connectez-vous pour retrouver vos messages et les décisions du
              filtre.
            </p>
            <label htmlFor="username">Identifiant</label>
            <Input
              id="username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              maxLength={100}
              placeholder="Votre identifiant"
            />
            <label htmlFor="password">Mot de passe</label>
            <div className="password-input">
              <Input
                id="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                maxLength={128}
                placeholder="Votre mot de passe"
              />
              <button
                type="button"
                aria-label={
                  showPassword
                    ? 'Masquer le mot de passe'
                    : 'Afficher le mot de passe'
                }
                aria-pressed={showPassword}
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            <Button className="login-submit" disabled={busy} type="submit">
              {busy ? (
                <>
                  <RefreshCw size={17} className="spin" /> Connexion…
                </>
              ) : (
                <>
                  Se connecter <ArrowUpRight size={18} />
                </>
              )}
            </Button>
            <p className="login-help">
              Besoin d’un accès ? Contactez votre administrateur.
            </p>
          </form>
          <p className="login-footnote">
            <LockKeyhole size={13} /> Un espace réservé à votre organisation.
          </p>
        </div>
      </main>
    );
  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">
        Aller au contenu
      </a>
      <aside className={`rail ${mobileMenu ? 'menu-open' : ''}`}>
        <div className="rail-brand">
          <div className="wordmark">
            <span className="brand-symbol">
              <BrandMark />
            </span>
            <div>
              NoiseFence<small>LA CLARTÉ DANS VOS MESSAGES</small>
            </div>
          </div>
          <button
            className="mobile-menu"
            aria-label={mobileMenu ? 'Fermer le menu' : 'Ouvrir le menu'}
            aria-expanded={mobileMenu}
            aria-controls="console-navigation"
            onClick={() => setMobileMenu(!mobileMenu)}
          >
            {mobileMenu ? <X size={21} /> : <Menu size={21} />}
          </button>
        </div>
        <div id="console-navigation" className="rail-navigation">
          <div className="workspace-identity">
            <span className="workspace-monogram">{user.admin ? 'A' : 'M'}</span>
            <div>
              <strong>{user.admin ? 'Mon organisation' : 'Mon espace'}</strong>
              <small>
                {user.admin ? 'Espace administrateur' : 'Espace personnel'}
              </small>
            </div>
            <LockKeyhole size={13} />
          </div>
          <div className="rail-label">MESSAGERIE</div>
          <nav className="navigation" aria-label="Messagerie">
            <button
              className={`nav-item ${section === 'messages' && filter !== 'quarantined' ? 'nav-active' : ''}`}
              aria-current={
                section === 'messages' && filter !== 'quarantined'
                  ? 'page'
                  : undefined
              }
              onClick={() => navigate('messages')}
            >
              <Inbox size={18} />
              {user.admin ? 'Tous les messages' : 'Mes messages'}
            </button>
            <button
              className={`nav-item ${section === 'messages' && filter === 'quarantined' ? 'nav-active' : ''}`}
              aria-current={
                section === 'messages' && filter === 'quarantined'
                  ? 'page'
                  : undefined
              }
              onClick={() => navigate('messages', 'quarantined')}
            >
              <Archive size={18} />
              Quarantaine
              {stats && (
                <span
                  className="nav-count"
                  title="Dans le périmètre sélectionné"
                >
                  {stats.quarantined}
                </span>
              )}
            </button>
          </nav>
          {user.admin && (
            <>
              <div className="rail-label admin-label">ADMINISTRATION</div>
              <nav className="navigation" aria-label="Administration">
                {navigation
                  .filter((n) => n.id !== 'messages')
                  .map((n) => (
                    <button
                      key={n.id}
                      className={`nav-item ${section === n.id ? 'nav-active' : ''}`}
                      aria-current={section === n.id ? 'page' : undefined}
                      onClick={() => navigate(n.id)}
                    >
                      <n.icon size={18} />
                      {n.label}
                      {configDirty &&
                        ['domains', 'gateways', 'filters'].includes(n.id) && (
                          <span
                            className="draft-dot"
                            aria-label="Brouillon non enregistré"
                          />
                        )}
                    </button>
                  ))}
              </nav>
            </>
          )}
          <div className="rail-label admin-label">ESPACE PERSONNEL</div>
          <nav className="navigation" aria-label="Espace personnel">
            <Button
              variant="ghost"
              className={`nav-item ${section === 'reliability' ? 'nav-active' : ''}`}
              aria-current={section === 'reliability' ? 'page' : undefined}
              onClick={() => navigate('reliability')}
            >
              <ShieldCheck size={18} /> Fiabilité
            </Button>
            <Button
              variant="ghost"
              className={`nav-item ${section === 'quality' ? 'nav-active' : ''}`}
              aria-current={section === 'quality' ? 'page' : undefined}
              onClick={() => navigate('quality')}
            >
              <ShieldCheck size={18} /> Qualité du filtre
            </Button>
            <button
              className={`nav-item ${section === 'account' ? 'nav-active' : ''}`}
              aria-current={section === 'account' ? 'page' : undefined}
              onClick={() => navigate('account')}
            >
              <UserRound size={18} />
              Mon compte
            </button>
          </nav>
        </div>
        <div className="rail-footer">
          <div className="signed-in-user">
            <span className="user-avatar">
              {Array.from(user.username).slice(0, 2).join('').toUpperCase()}
            </span>
            <div>
              <strong>{user.username}</strong>
              <span>
                {user.admin
                  ? 'Administrateur · Tous les domaines'
                  : user.addresses.join(', ') || 'Aucune adresse attribuée'}
              </span>
            </div>
          </div>
          <Button
            variant="ghost"
            onClick={async () => {
              if (
                configDirty &&
                !window.confirm(
                  'Des réglages ne sont pas appliqués. Quitter et les abandonner ?',
                )
              )
                return;
              try {
                await api('/logout', {}, user.csrf);
                changeSession(null);
                setSelected(null);
                setMails([]);
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            <LogOut size={16} /> Déconnexion
          </Button>
        </div>
      </aside>
      <main id="main-content" className="workspace" tabIndex={-1}>
        <header className="topline">
          <span className="breadcrumbs">
            <span>Espace de travail</span>
            <ChevronRight size={14} />
            <strong>
              {selected
                ? 'Décision du filtre'
                : section === 'reliability'
                  ? 'Fiabilité'
                  : section === 'quality'
                    ? 'Qualité du filtre'
                    : section === 'account'
                      ? 'Mon compte'
                      : section === 'messages' && filter === 'quarantined'
                        ? 'Quarantaine'
                        : navigation.find((n) => n.id === section)?.label}
            </strong>
          </span>
          <span
            className={`mode ${stats && stats.mode !== 'observe' ? 'mode-active' : ''}`}
          >
            <i />
            {stats
              ? stats.mode !== 'observe'
                ? 'Actions actives'
                : 'Mode observation'
              : 'Chargement du mode…'}
          </span>
        </header>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        {notice && <output className="notice">{notice}</output>}
        {user.admin && (
          <div
            hidden={
              section === 'messages' ||
              section === 'account' ||
              section === 'quality' ||
              section === 'reliability'
            }
          >
            <AdminConsole
              user={user}
              section={
                section === 'account' ||
                section === 'quality' ||
                section === 'reliability'
                  ? 'messages'
                  : section
              }
              onDirty={setConfigDirty}
              onApplied={refresh}
              onDomain={(name) => {
                setDomain(name);
                setOffset(0);
                setSection('messages');
                setSelected(null);
              }}
            />
          </div>
        )}
        {section === 'quality' && <QualityConsole user={user} />}
        {section === 'reliability' && (
          <ReliabilityConsole key={user.username} />
        )}
        {section === 'account' && (
          <MyAccount
            key={user.username}
            user={user}
            onPasswordChanged={() => changeSession(null)}
          />
        )}
        {section === 'messages' && (
          <>
            {selected ? (
              <>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setSelected(null);
                    setNotice('');
                  }}
                >
                  <ArrowLeft size={17} /> Retour aux messages
                </Button>
                <div className="detail-heading">
                  <p className="eyebrow">DÉCISION DU FILTRE</p>
                  <div className="detail-badges">
                    <span
                      className={`status ${classification(selected, historicalThreshold?.messageId === selected.id ? historicalThreshold.threshold : undefined).tone}`}
                    >
                      {
                        classification(
                          selected,
                          historicalThreshold?.messageId === selected.id
                            ? historicalThreshold.threshold
                            : undefined,
                        ).label
                      }
                    </span>
                    {publicitySignal(selected.mailing) &&
                      selected.category !== 'publicity' && (
                        <span className="status publicity">Indices PUB</span>
                      )}
                    <span
                      className={`status ${deliverySummary(selected.recipients).tone}`}
                    >
                      {deliverySummary(selected.recipients).label}
                    </span>
                    {selected.feedback_category && (
                      <span className="status">
                        Correction :{' '}
                        {selected.feedback_category === 'legitimate'
                          ? 'Légitime'
                          : selected.feedback_category === 'publicity'
                            ? 'PUB'
                            : 'Spam'}
                      </span>
                    )}
                  </div>
                  <h1>{selected.subject || '(Sans objet)'}</h1>
                  <p className="muted">
                    {selected.sender || 'Expéditeur d’enveloppe vide'} ·{' '}
                    {new Date(selected.created * 1000).toLocaleString('fr-FR')}
                  </p>
                </div>
                <div className="detail-grid">
                  <section className="panel analysis-panel">
                    <h2>Pourquoi ce classement ?</h2>
                    <div className="score-large">
                      {selected.decision?.source === 'antivirus'
                        ? 'Malware'
                        : (displayedScore(selected)?.toFixed(1) ?? '—')}
                      {displayedScore(selected) !== null &&
                        selected.decision?.source !== 'antivirus' && (
                          <span>/ 100</span>
                        )}
                    </div>
                    <p className="muted">
                      {selected.decision?.source === 'antivirus'
                        ? 'Malware détecté · décision antivirus, sans score probabiliste'
                        : selected.decision?.outcome === 'undetermined'
                          ? selected.complete
                            ? `À vérifier · ${selected.arbitration && ['disagreement', 'ambiguous'].includes(selected.arbitration.resolution) ? arbitrationExplanation(selected.arbitration)?.title : 'confirmation insuffisante'}`
                            : 'Décision indéterminée'
                          : selected.decision?.source === 'fusion'
                            ? 'Estimation calibrée'
                            : 'Indice de suspicion'}
                      {' · '}
                      {selected.decision?.model ?? selected.model}
                    </p>
                    {selected.arbitration && (
                      <p className="notice">
                        {arbitrationExplanation(selected.arbitration)?.detail}{' '}
                        Indice historique :{' '}
                        {selected.arbitration.baseline.score?.toFixed(1) ?? '—'}{' '}
                        / 100.
                      </p>
                    )}
                    {selected.decision?.source === 'antivirus' && (
                      <p className="notice">
                        Le résultat antivirus prime sur l’indice de suspicion (
                        {selected.score.toFixed(1)} / 100) et sur la détection
                        de publicité.
                      </p>
                    )}
                    {!selected.complete && (
                      <p className="notice">
                        Certains contrôles n’ont pas abouti. Les détections
                        obtenues restent visibles ; aucun préfixe n’est ajouté à
                        l’objet.
                      </p>
                    )}
                    <details className="analysis-details">
                      <summary>Contrôles et détails de l’analyse</summary>
                      {selected.fusion &&
                        selected.fusion.status !== 'disabled' && (
                          <div className="notice">
                            <strong>
                              {selected.fusion.mode === 'observe'
                                ? 'Fusion en observation'
                                : 'Décision commune'}
                            </strong>
                            <p>
                              {
                                {
                                  not_run:
                                    'Contexte insuffisant pour combiner les détecteurs.',
                                  complete: selected.fusion.prediction
                                    ?.tag_eligible
                                    ? `Estimation : ${((selected.fusion.prediction?.probability ?? 0) * 100).toFixed(1)} / 100.`
                                    : 'Contrôles incomplets : estimation inutilisable pour le marquage.',
                                  unavailable:
                                    'Fusion indisponible pour ce message.',
                                  unsupported_profile:
                                    'Cette combinaison de contrôles n’a pas encore été validée.',
                                  validation_expired:
                                    'Validation du modèle expirée : aucun préfixe ajouté.',
                                }[selected.fusion.status]
                              }
                            </p>
                            {selected.fusion.mode === 'observe' && (
                              <p>
                                Résultat de recherche, sans effet sur le
                                classement.
                              </p>
                            )}
                            <small>{selected.fusion.model}</small>
                            {selected.fusion.status === 'complete' &&
                              selected.fusion.prediction?.tag_eligible && (
                                <ul className="reasons">
                                  {selected.fusion.prediction.contributions
                                    .filter((c) => c.contribution !== 0)
                                    .map((c, i) => (
                                      <li key={`${c.feature}-${i}`}>
                                        <span>{fusionReason(c.feature)}</span>
                                        <small>
                                          {c.contribution > 0
                                            ? 'Augmente'
                                            : 'Réduit'}{' '}
                                          l’estimation
                                        </small>
                                      </li>
                                    ))}
                                </ul>
                              )}
                          </div>
                        )}
                      {selected.early_rbl && (
                        <EarlyRblDetails report={selected.early_rbl} />
                      )}
                      {selected.smtp_policy &&
                        selected.smtp_policy.status !== 'disabled' && (
                          <p className="muted">
                            Cohérence SMTP et DNS :{' '}
                            {
                              {
                                complete: 'contrôlée',
                                busy: 'capacité occupée, contrôle incomplet',
                                unavailable: 'indisponible ou délai dépassé',
                              }[selected.smtp_policy.status]
                            }{' '}
                            · {selected.smtp_policy.elapsed_ms} ms
                            {selected.smtp_policy.status === 'complete' &&
                              !selected.smtp_policy.scoring_enabled &&
                              ' · observation sans effet sur le score'}
                          </p>
                        )}
                      {selected.semantic &&
                        selected.semantic.status !== 'disabled' && (
                          <p className="muted">
                            Analyse multilingue locale :{' '}
                            {
                              {
                                complete: 'effectuée',
                                busy: 'capacité occupée, analyse incomplète',
                                unavailable: 'indisponible ou délai dépassé',
                              }[selected.semantic.status]
                            }{' '}
                            · {selected.semantic.elapsed_ms} ms
                          </p>
                        )}
                      {selected.vision &&
                        selected.vision.status !== 'disabled' && (
                          <div className="notice">
                            <strong>
                              Lecture des images et PDF :{' '}
                              {
                                {
                                  complete: selected.vision.parts
                                    ? 'effectuée'
                                    : 'aucun contenu visuel local',
                                  limited:
                                    'partielle, limites atteintes ou document illisible',
                                  busy: 'capacité occupée, analyse incomplète',
                                  unavailable: 'indisponible ou délai dépassé',
                                }[selected.vision.status]
                              }
                            </strong>
                            {selected.vision.pages > 0 && (
                              <p>
                                {selected.vision.pages} page(s) ·{' '}
                                {selected.vision.text_chars} caractères ·{' '}
                                {selected.vision.qr_codes} QR code(s) ·{' '}
                                {selected.vision.other_codes} autre(s) code(s) ·{' '}
                                {selected.vision.link_domains} domaine(s) dans
                                les liens
                              </p>
                            )}
                            <small>
                              Traitement local · {selected.vision.elapsed_ms} ms
                              · Les liens décodés ne sont pas ouverts.
                            </small>
                          </div>
                        )}
                      {selected.llm && selected.llm.status !== 'disabled' && (
                        <p className="muted">
                          Analyse complémentaire Scaleway :{' '}
                          {
                            {
                              not_needed: 'non sollicitée pour ce message',
                              busy: 'capacité occupée, analyse incomplète',
                              budget_limited:
                                'plafond atteint, analyse locale conservée',
                              pricing_expired:
                                'tarifs à revalider, analyse locale conservée',
                              unavailable: 'indisponible',
                              complete: 'effectuée',
                            }[selected.llm.status]
                          }
                          {selected.llm.status === 'complete' &&
                            ` · ${selected.llm.model} · ${selected.llm.elapsed_ms} ms`}
                          {selected.llm.failure &&
                            ` · ${checkFailure(selected.llm.failure)} · ${selected.llm.elapsed_ms} ms`}
                        </p>
                      )}
                      {selected.antivirus &&
                        selected.antivirus.status !== 'disabled' && (
                          <div className="notice">
                            <strong>
                              Antivirus :{' '}
                              {
                                {
                                  clean: 'aucune détection',
                                  malware: 'fichier malveillant détecté',
                                  suspicious: 'signal suspect à examiner',
                                  unscannable:
                                    'analyse limitée ou contenu chiffré',
                                  unavailable: 'service indisponible',
                                }[selected.antivirus.status]
                              }
                            </strong>
                            {selected.antivirus.signature && (
                              <p>{selected.antivirus.signature}</p>
                            )}
                            <small>
                              ClamAV · {selected.antivirus.elapsed_ms} ms
                            </small>
                          </div>
                        )}
                      {selected.signatures &&
                        selected.signatures.status !== 'disabled' && (
                          <p className="muted">
                            Signatures complémentaires :{' '}
                            {
                              {
                                clean: 'aucune détection',
                                malware: 'signal consultatif à examiner',
                                suspicious: 'signal consultatif à examiner',
                                unscannable: 'analyse limitée',
                                unavailable: 'service indisponible',
                              }[selected.signatures.status]
                            }{' '}
                            · {selected.signatures.elapsed_ms} ms
                          </p>
                        )}
                    </details>
                    <RuleDetails
                      reasons={selected.reasons}
                      source={selected.decision?.source}
                    />
                  </section>
                  <Suspense
                    fallback={
                      <section className="panel message-diagnostics">
                        <output>Chargement des diagnostics du message…</output>
                      </section>
                    }
                  >
                    <Diagnostics
                      key={selected.id}
                      messageId={selected.id}
                      reasons={selected.reasons}
                      source={selected.decision?.source}
                      revision={diagnosticsRevision}
                      onLoaded={diagnosticsLoaded}
                      onRecipientLoaded={recipientLoaded}
                    />
                  </Suspense>
                  {selected.mailing && (
                    <MailingDetails
                      report={selected.mailing}
                      category={selected.category}
                      tagged={selected.pub_tagged}
                    />
                  )}
                  {selected.quality && (
                    <QualityDetails report={selected.quality} />
                  )}
                  {selected.protection && (
                    <ProtectionDetails report={selected.protection} />
                  )}
                  <section className="panel message-actions-panel">
                    <h2>Corriger le classement</h2>
                    <p className="muted">
                      Corrigez la décision pour améliorer les prochains
                      classements.
                    </p>
                    <div className="feedback-actions">
                      <Button
                        disabled={busy}
                        variant={
                          selected.feedback_category === 'legitimate'
                            ? 'default'
                            : 'outline'
                        }
                        onClick={() => feedback('legitimate')}
                      >
                        <Check size={17} /> Légitime
                      </Button>
                      <Button
                        disabled={busy}
                        variant={
                          selected.feedback === true ? 'default' : 'outline'
                        }
                        onClick={() => feedback('spam')}
                      >
                        <Flag size={17} /> Spam
                      </Button>
                      <Button
                        disabled={busy}
                        variant={
                          selected.feedback_category === 'publicity'
                            ? 'default'
                            : 'outline'
                        }
                        onClick={() => feedback('publicity')}
                      >
                        PUB
                      </Button>
                    </div>
                    <p className="muted small">
                      PUB désigne une publicité ou une newsletter légitime. Une
                      publicité frauduleuse doit être signalée comme spam.
                    </p>
                    <AdaptiveDetails
                      key={`${user.username}-${selected.id}`}
                      id={selected.id}
                      csrf={user.csrf}
                      report={selected.adaptive}
                      feedbackRevision={feedbackRevision}
                      onCorrect={(value) => adaptiveCorrect(selected.id, value)}
                      blocked={busy}
                      onBusy={setBusy}
                    />
                    <h2 className="subheading">Livraison</h2>
                    {selected.action && (
                      <p className="small muted">
                        Action à la réception :{' '}
                        {actionLabel[selected.action.effective]}.
                        {selected.action.reason === 'observation' &&
                          ` Observation active ; action prévue : ${actionLabel[selected.action.requested]}.`}
                        {selected.action.reason === 'incomplete' &&
                          ' Analyse incomplète : transmission sans préfixe.'}
                      </p>
                    )}
                    {selected.recipients.map((r) => (
                      <div className="quarantine-recipient" key={r.address}>
                        <p className="recipient">
                          {r.address}
                          <span>{deliveryStatus(r.status)}</span>
                        </p>
                        {r.filtering && (
                          <FilteringDetails value={r.filtering} />
                        )}
                        {r.status === 'quarantined' && (
                          <>
                            <p className="small muted">
                              {r.held_until
                                ? `Suppression prévue le ${new Date(r.held_until * 1000).toLocaleString('fr-FR')}.`
                                : 'Message retenu sur la passerelle.'}
                            </p>
                            <div className="feedback-actions">
                              <Button
                                disabled={busy}
                                onClick={() => (
                                  setConfirmationError(''),
                                  setConfirmation({
                                    recipient: r.address,
                                    action: 'release',
                                  })
                                )}
                              >
                                Libérer et transmettre
                              </Button>
                              <Button
                                variant="outline"
                                className="danger"
                                disabled={busy}
                                onClick={() => (
                                  setConfirmationError(''),
                                  setConfirmation({
                                    recipient: r.address,
                                    action: 'delete',
                                  })
                                )}
                              >
                                Supprimer
                              </Button>
                            </div>
                          </>
                        )}
                      </div>
                    ))}
                    <p className="small muted">
                      L’acceptation par le serveur destinataire ne garantit pas
                      l’arrivée dans la boîte de réception.
                    </p>
                    <p className="small muted">
                      Le corps et les pièces jointes restent sur la passerelle
                      tant qu’une livraison est en attente ou en quarantaine.
                      Ils sont supprimés lorsque tous les destinataires sont
                      résolus.
                    </p>
                  </section>
                </div>
              </>
            ) : (
              <>
                <div className="page-heading">
                  <div>
                    <p className="eyebrow">
                      {user.admin
                        ? 'VUE DE L’ORGANISATION'
                        : 'VOTRE MESSAGERIE'}
                    </p>
                    <h1>
                      {filter === 'quarantined'
                        ? 'Quarantaine'
                        : user.admin
                          ? 'Tous les messages'
                          : 'Mes messages'}
                    </h1>
                    <p className="muted">
                      {filter === 'quarantined'
                        ? 'Examinez les messages retenus et choisissez leur traitement.'
                        : 'Suivez chaque message, de son analyse à sa livraison.'}
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    onClick={() => void refresh()}
                    disabled={loading}
                    aria-label={
                      loading
                        ? 'Actualisation des messages en cours'
                        : 'Actualiser les messages'
                    }
                  >
                    <RefreshCw size={16} className={loading ? 'spin' : ''} />
                    {loading ? 'Actualisation…' : 'Actualiser'}
                  </Button>
                </div>
                <div className="scope-bar">
                  <Globe2 size={16} />
                  <label htmlFor="domain-scope">Périmètre</label>
                  <select
                    id="domain-scope"
                    value={domain}
                    onChange={(e) => {
                      setDomain(e.target.value);
                      setOffset(0);
                    }}
                  >
                    <option value="">
                      {user.admin ? 'Tous les domaines' : 'Tous mes accès'}
                    </option>
                    {domains.map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </select>
                  <span className="small muted">
                    {user.admin
                      ? 'Visibilité complète des destinataires'
                      : 'Destinataires autorisés uniquement'}
                  </span>
                </div>
                <div className="stats message-stats">
                  {[
                    {
                      id: 'all',
                      label: 'Messages reçus',
                      count: stats?.received,
                      icon: Inbox,
                      tone: 'blue',
                      detail: 'Historique disponible',
                    },
                    {
                      id: 'spam',
                      label: 'Spam détecté',
                      count: stats?.flagged,
                      icon: ShieldCheck,
                      tone: 'orange',
                      detail: 'Classés indésirables',
                    },
                    {
                      id: 'publicity',
                      label: 'Publicités · PUB',
                      count: stats?.publicity,
                      icon: Flag,
                      tone: 'purple',
                      detail: 'Publicités et newsletters',
                    },
                    {
                      id: 'quarantined',
                      label: 'En quarantaine',
                      count: stats?.quarantined,
                      icon: Archive,
                      tone: 'amber',
                      detail: 'Messages retenus',
                    },
                  ].map((card) => (
                    <button
                      key={card.id}
                      className={`stat-card ${filter === card.id ? 'stat-active' : ''}`}
                      aria-pressed={filter === card.id}
                      onClick={() => {
                        setFilter(card.id);
                        setOffset(0);
                      }}
                    >
                      <span className={`stat-icon ${card.tone}`}>
                        <card.icon size={19} />
                      </span>
                      <span>{card.label}</span>
                      <strong>
                        {card.count?.toLocaleString('fr-FR') ?? '—'}
                      </strong>
                      <small className="stat-detail">{card.detail}</small>
                      <ArrowUpRight className="stat-arrow" size={16} />
                    </button>
                  ))}
                </div>
                {stats?.mode === 'observe' && (
                  <div className="observation-banner">
                    <ShieldCheck size={18} />
                    <p>
                      <strong>Observation active</strong> Les messages sont
                      analysés et transmis. Les actions de marquage et de
                      quarantaine ne sont pas appliquées.
                      {user.admin && ' Vous pouvez les activer dans Filtres.'}
                    </p>
                    {user.admin && (
                      <Button
                        variant="ghost"
                        onClick={() => navigate('filters')}
                      >
                        Voir les actions <ChevronRight size={15} />
                      </Button>
                    )}
                  </div>
                )}
                <section
                  className={`messages ${compact ? 'messages-compact' : ''}`}
                  aria-busy={loading}
                >
                  <div className="journal-heading">
                    <div>
                      <h2>
                        {filter === 'quarantined'
                          ? 'Messages en quarantaine'
                          : 'Journal des messages'}
                      </h2>
                      <p>Les décisions et la livraison, au même endroit.</p>
                    </div>
                    <Button
                      variant="outline"
                      className="density-toggle"
                      aria-pressed={compact}
                      onClick={() => setCompact((v) => !v)}
                    >
                      <Rows3 size={16} /> Vue compacte
                    </Button>
                  </div>
                  <div className="toolbar">
                    <fieldset
                      className="tabs"
                      aria-label="Filtrer les messages"
                    >
                      {[
                        ['all', 'Tous'],
                        ['spam', 'Spam détecté'],
                        ['publicity', 'PUB'],
                        ['legitimate', 'Légitime'],
                        [
                          'quarantined',
                          `Quarantaine (${stats?.quarantined ?? 0})`,
                        ],
                      ].map(([value, label]) => (
                        <Button
                          key={value}
                          variant={filter === value ? 'default' : 'ghost'}
                          aria-pressed={filter === value}
                          onClick={() => {
                            setFilter(value);
                            setOffset(0);
                          }}
                        >
                          {label}
                        </Button>
                      ))}
                      <label
                        className={`more-filters ${['pending', 'review', 'publicity_signal', 'incomplete'].includes(filter) ? 'has-filter' : ''}`}
                      >
                        <SlidersHorizontal size={14} />
                        <select
                          aria-label="Autres filtres de messages"
                          value={
                            [
                              'pending',
                              'review',
                              'publicity_signal',
                              'incomplete',
                            ].includes(filter)
                              ? filter
                              : ''
                          }
                          onChange={(event) => {
                            if (event.target.value) {
                              setFilter(event.target.value);
                              setOffset(0);
                            }
                          }}
                        >
                          <option value="" disabled>
                            Plus de filtres
                          </option>
                          <option value="pending">En attente</option>
                          <option value="review">À vérifier</option>
                          <option value="publicity_signal">
                            Indices PUB, tous classements
                          </option>
                          <option value="incomplete">Analyse incomplète</option>
                        </select>
                      </label>
                    </fieldset>
                    <div className="search message-search">
                      <Search size={18} />
                      <Input
                        ref={searchInput}
                        aria-label="Rechercher par objet, expéditeur ou destinataire"
                        placeholder="Rechercher un message…"
                        value={search}
                        onChange={(e) => {
                          setSearch(e.target.value);
                          setOffset(0);
                        }}
                        maxLength={150}
                      />
                      {!search && (
                        <kbd
                          className="search-shortcut"
                          title="Ctrl ou ⌘ + K"
                          aria-hidden="true"
                        >
                          ⌘ K
                        </kbd>
                      )}
                      {search && (
                        <button
                          className="clear-search"
                          aria-label="Effacer la recherche"
                          onClick={() => {
                            setSearch('');
                            setOffset(0);
                          }}
                        >
                          <X size={16} />
                        </button>
                      )}
                    </div>
                  </div>
                  {(search || domain || filter !== 'all') && (
                    <div
                      className="search-context"
                      aria-label="Critères actifs"
                    >
                      <span>Affichage</span>
                      {domain && (
                        <span className="filter-chip">
                          <Globe2 size={13} />
                          {domain}
                        </span>
                      )}
                      {filter !== 'all' && (
                        <span className="filter-chip">
                          {{
                            spam: 'Spam détecté',
                            publicity: 'Publicités',
                            legitimate: 'Légitimes',
                            quarantined: 'Quarantaine',
                            pending: 'En attente',
                            review: 'À vérifier',
                            publicity_signal: 'Indices PUB',
                            incomplete: 'Analyse incomplète',
                          }[filter] ?? filter}
                        </span>
                      )}
                      {search && (
                        <span className="filter-chip search-term">
                          <Search size={13} />
                          {search}
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          setSearch('');
                          setFilter('all');
                          setDomain('');
                          setOffset(0);
                        }}
                      >
                        <X size={13} />
                        Réinitialiser
                      </button>
                    </div>
                  )}
                  <div className="results-meta">
                    <span>
                      {loading
                        ? 'Actualisation des messages…'
                        : `${mails.length} message${mails.length > 1 ? 's' : ''} sur cette page`}
                      {domain && ` · ${domain}`}
                    </span>
                    <span>
                      <Clock3 size={13} />
                      {updatedAt
                        ? `Actualisé à ${updatedAt.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })}`
                        : 'Chargement…'}
                    </span>
                  </div>
                  {loading && !mails.length && (
                    <div className="message-skeleton" aria-hidden="true">
                      {[0, 1, 2, 3].map((n) => (
                        <div key={n}>
                          <i />
                          <span>
                            <b />
                            <b />
                          </span>
                          <em />
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="desktop-messages">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Message</TableHead>
                          <TableHead>Destinataires</TableHead>
                          <TableHead>Classement</TableHead>
                          <TableHead>Livraison</TableHead>
                          <TableHead>Indice spam</TableHead>
                          <TableHead>Reçu le</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {mails.map((m) => (
                          <TableRow
                            key={m.id}
                            data-classification={
                              classification(m, stats?.threshold ?? 95).tone
                            }
                          >
                            <TableCell>
                              <button
                                className="message-link"
                                onClick={() => {
                                  setSelected(m);
                                  setNotice('');
                                }}
                              >
                                <span
                                  className="sender-avatar"
                                  aria-hidden="true"
                                >
                                  {Array.from(m.sender || 'NF')
                                    .slice(0, 2)
                                    .join('')
                                    .toUpperCase()}
                                </span>
                                <span className="message-copy">
                                  <strong>{m.subject || '(Sans objet)'}</strong>
                                  <span>
                                    {m.sender || 'Notification de livraison'}
                                  </span>
                                </span>
                              </button>
                            </TableCell>
                            <TableCell>
                              <span className="small recipient-list">
                                {m.recipients.map((r) => r.address).join(', ')}
                              </span>
                            </TableCell>
                            <TableCell>
                              <span
                                className={`status ${classification(m, stats?.threshold ?? 95).tone}`}
                              >
                                {
                                  classification(m, stats?.threshold ?? 95)
                                    .label
                                }
                              </span>
                              {publicitySignal(m.mailing) &&
                                m.category !== 'publicity' && (
                                  <small className="tag-note">
                                    Indices PUB · décision de sécurité
                                    prioritaire
                                  </small>
                                )}
                              {(m.tagged || m.pub_tagged) && (
                                <small className="tag-note">
                                  {m.tagged ? '[SPAM]' : '[PUB]'} ajouté
                                </small>
                              )}
                              {m.feedback_category && (
                                <small className="tag-note">
                                  Correction enregistrée
                                </small>
                              )}
                            </TableCell>
                            <TableCell>
                              <span
                                className={`status delivery-status ${deliverySummary(m.recipients).tone}`}
                              >
                                {deliverySummary(m.recipients).label}
                              </span>
                            </TableCell>
                            <TableCell>
                              <ScoreMeter
                                score={displayedScore(m)}
                                tone={
                                  classification(m, stats?.threshold ?? 95).tone
                                }
                              />
                            </TableCell>
                            <TableCell className="muted">
                              <time
                                className="message-date"
                                dateTime={new Date(
                                  m.created * 1000,
                                ).toISOString()}
                              >
                                <strong>
                                  {new Date(
                                    m.created * 1000,
                                  ).toLocaleTimeString('fr-FR', {
                                    hour: '2-digit',
                                    minute: '2-digit',
                                  })}
                                </strong>
                                <span>
                                  {new Date(
                                    m.created * 1000,
                                  ).toLocaleDateString('fr-FR', {
                                    day: 'numeric',
                                    month: 'short',
                                  })}
                                </span>
                              </time>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  <div className="mobile-messages">
                    {mails.map((m) => (
                      <button
                        key={m.id}
                        className="mobile-message"
                        data-classification={
                          classification(m, stats?.threshold ?? 95).tone
                        }
                        onClick={() => {
                          setSelected(m);
                          setNotice('');
                        }}
                      >
                        <span className="mobile-message-top">
                          <span
                            className={`status ${classification(m, stats?.threshold ?? 95).tone}`}
                          >
                            {classification(m, stats?.threshold ?? 95).label}
                          </span>
                          {publicitySignal(m.mailing) &&
                            m.category !== 'publicity' && (
                              <span className="status publicity">
                                Indices PUB
                              </span>
                            )}
                          <time
                            dateTime={new Date(m.created * 1000).toISOString()}
                          >
                            {new Date(m.created * 1000).toLocaleString(
                              'fr-FR',
                              {
                                day: 'numeric',
                                month: 'short',
                                hour: '2-digit',
                                minute: '2-digit',
                              },
                            )}
                          </time>
                        </span>
                        <strong>{m.subject || '(Sans objet)'}</strong>
                        <small>{m.sender || 'Notification de livraison'}</small>
                        <small>
                          À : {m.recipients.map((r) => r.address).join(', ')}
                        </small>
                        <span className="delivery-line">
                          <span
                            className={`status ${deliverySummary(m.recipients).tone}`}
                          >
                            {deliverySummary(m.recipients).label}
                          </span>
                          {(m.tagged || m.pub_tagged) && (
                            <span>{m.tagged ? '[SPAM]' : '[PUB]'} ajouté</span>
                          )}
                          <ChevronRight size={15} />
                        </span>
                      </button>
                    ))}
                  </div>
                  {!mails.length && !loading && (
                    <div className="empty">
                      <ShieldCheck size={32} />
                      <h2>
                        {filter === 'quarantined'
                          ? 'Aucun message en quarantaine'
                          : search || domain || filter !== 'all'
                            ? 'Aucun résultat pour ces critères'
                            : 'Votre historique est prêt'}
                      </h2>
                      <p>
                        {filter === 'quarantined'
                          ? 'Les messages retenus pour vos destinataires apparaîtront ici.'
                          : search || domain || filter !== 'all'
                            ? 'Modifiez la recherche ou affichez tous les messages.'
                            : 'Les prochains messages traités pour vos adresses apparaîtront ici.'}
                      </p>
                      {(search || domain || filter !== 'all') && (
                        <Button
                          variant="outline"
                          onClick={() => {
                            setSearch('');
                            setFilter('all');
                            setDomain('');
                            setOffset(0);
                          }}
                        >
                          Afficher tous les messages
                        </Button>
                      )}
                    </div>
                  )}
                  <div className="pagination">
                    <Button
                      variant="ghost"
                      disabled={loading || offset === 0}
                      onClick={() => setOffset(Math.max(0, offset - 50))}
                    >
                      Précédent
                    </Button>
                    <span>Page {Math.floor(offset / 50) + 1}</span>
                    <Button
                      variant="ghost"
                      disabled={loading || mails.length < 50}
                      onClick={() => setOffset(offset + 50)}
                    >
                      Suivant
                    </Button>
                  </div>
                </section>
              </>
            )}
          </>
        )}
      </main>
      {confirmation && selected && (
        <ConfirmDialog
          title={
            confirmation.action === 'release'
              ? 'Libérer ce message ?'
              : 'Supprimer cette livraison ?'
          }
          confirmLabel={
            confirmation.action === 'release'
              ? 'Libérer et transmettre'
              : 'Supprimer définitivement'
          }
          danger={confirmation.action === 'delete'}
          busy={busy}
          onCancel={() => {
            setConfirmation(null);
            setConfirmationError('');
          }}
          onConfirm={() =>
            void quarantineAction(confirmation.recipient, confirmation.action)
          }
        >
          <p className="confirmation-subject">
            {selected.subject || '(Sans objet)'}
          </p>
          <p>
            Destinataire : <strong>{confirmation.recipient}</strong>
          </p>
          <p>
            {confirmation.action === 'release'
              ? 'Le message sera transmis sans préfixe. Son classement et les autres destinataires restent inchangés.'
              : 'Cette livraison sera supprimée sans envoi. Cette action est définitive pour ce destinataire.'}
          </p>
          {confirmationError && (
            <p className="error" role="alert">
              {confirmationError}
            </p>
          )}
        </ConfirmDialog>
      )}
    </div>
  );
}
