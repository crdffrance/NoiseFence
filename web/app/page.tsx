'use client';
import {groundingSummary, responseIssueLabel, type LlmGrounding} from './llm-evidence';
import { RspamdComparison, RspamdOverview, RspamdResult } from './rspamd-comparison';
import type { RspamdReport, ComparisonSummary } from './rspamd-format';
import type { Assessment, RecipientDecision } from './assessment';
import { MyFilters } from './preferences';
import { ClusterConsole } from './cluster';
import { OnboardingGate } from './onboarding';
import { MessageCorrection } from './message-correction';
import type { AdaptiveReport } from './adaptive-types';
import { EarlyRblDetails } from './rbl';
import {TrafficDetails,type TrafficReport} from './traffic';
import { AdmissionDetails, type AdmissionDecision } from './smtp-admission';
import type { EarlyRbl } from './rbl-types';
import { FilteringDetails, type FilteringAssessment } from './custom-filtering';
import { actionLabel, type DeliveryAction } from './actions';
import { actionReason } from './action-coverage';
import { ConfirmDialog } from './console-ui';
import { MyAccount } from './account';
import { RecoveryCodes } from './mfa';
import { BrandMark, LoginStory } from './brand';
import { MessageScore, MessageScoreDetails } from './message-score';
import { MessageSearchControls } from './message-search-controls';
import {
  emptySearch,
  searchFilterCount,
  searchParameters,
} from './message-search';
import {
  classification,
  classificationDetail,
  classificationQualification,
  deliverySummary,
  checkFailure,
  publicitySignal,
  type Arbitration,
} from './presentation';
import {
  deliveryStatus,
  mergeDiagnosticRecipient,
  type DiagnosticRecipient,
  type MessageDiagnostics,
} from './diagnostics-formatters';
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
import { researchDestination, researchSearch, researchTabFor } from './quality-link';
import { QualityNavigation } from './quality-navigation';
import { SoftwareStatus } from './software';
import { ReliabilityConsole } from './reliability';
import type { QualityReport } from './quality-types';
import { registerFeedbackTool } from './webmcp';
const Diagnostics = lazy(() => import('./diagnostics'));
type ConsoleDestination = {section: Section | 'account' | 'quality' | 'reliability' | 'preferences'; filter: string; domain?: string};
type Mail = {
  recipient_decision?: RecipientDecision | null;
  rspamd?: RspamdReport | null;
  assessment?: Assessment;
  node_id?: string | null;
  node_updated_at?: number | null;
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
  evidence?: { lexical_state?: string } | null;
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
  scoring?: import('./scoring-format').ScoringReport | null;
  reasons: { id: string; detail: string; weight: number }[];
  recipients: {
    filtering?: FilteringAssessment | null;
    delivery_id?: number;
    pending_command?: string | null;
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
    coherent?: boolean | null;
    grounding?: LlmGrounding | null;
    response_issue?: string | null;
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
  traffic?:TrafficReport;
  smtp_admission?: AdmissionDecision[];
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
  resolve_uncertain_by_score?: boolean;
  received: number;
  flagged: number;
  publicity: number;
  pending: number;
  quarantined: number;
  mode: string;
  threshold: number;
  decision_source?: 'legacy' | 'fusion';
};
const fusionFamilies: Record<string, string> = {
  lexical: "Text content",
  semantic: "Message meaning",
  auth: "Authentication",
  reputation: "Reputation",
  smtp_policy: "SMTP and DNS consistency",
  antivirus: 'Antivirus',
  signatures: "Additional signatures",
  llm: "Further analysis",
};
function fusionReason(feature: string) {
  const family =
    fusionFamilies[feature.split('.')[0]] ?? "Combined observations";
  if (feature.includes('unavailable'))
    return `${family} : check not available`;
  if (feature.includes('busy')) return `${family} : capacity occupied`;
  if (feature.includes('not_run')) return `${family} : check not run`;
  if (feature.includes('disabled')) return `${family} : check disabled`;
  if (feature.includes('limited')) return `${family} : limited analysis`;
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
  const detailTitle = useRef<HTMLHeadingElement>(null);
  const [showPassword, setShowPassword] = useState(false);
  const searchInput = useRef<HTMLInputElement>(null);
  const [section, setSection] = useState<
    Section | 'account' | 'quality' | 'reliability' | 'preferences'
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
  const [adminDirty, setAdminDirty] = useState(false);
  const [adminDraftEpoch, setAdminDraftEpoch] = useState(0);
  const [pendingNavigation, setPendingNavigation] = useState<ConsoleDestination | null>(null);
  const [clusterDirty, setClusterDirty] = useState(false);
  const [preferenceDirty, setPreferenceDirty] = useState(false);
  const [preferenceDraftEpoch,setPreferenceDraftEpoch] = useState(0);
  const [correctionDirty, setCorrectionDirty] = useState(false);
  const [qualityDirty, setQualityDirty] = useState(false);
  const [qualityDraftEpoch, setQualityDraftEpoch] = useState(0);
  const configDirty = adminDirty || clusterDirty || preferenceDirty || correctionDirty || qualityDirty;
  const [user, setUser] = useState<User | null>(null),
    [ready, setReady] = useState(false),
    [error, setError] = useState(''),
    [busy, setBusy] = useState(false);
  const [username, setUsername] = useState(''),
    [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [search, setSearch] = useState(''),
    [filter, setFilter] = useState('all'),
    [offset, setOffset] = useState(0);
  const [searchFilters, setSearchFilters] = useState(emptySearch);
  const [searchTotal, setSearchTotal] = useState<number | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [comparisonSummary, setComparisonSummary] = useState<ComparisonSummary | null>(null);
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
  const selectedMessageId = selected?.id;
  useEffect(() => {
    if (!selectedMessageId) return;
    detailTitle.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'instant' });
  }, [selectedMessageId]);
  const latestRequest = useRef(0);
  const changeSession = useCallback((next: User | null) => {
    activeUser.current = next;
    latestRequest.current += 1;
    setUser(next);
    setMails([]);
    setStats(null);
    setSelected(null);
    setFeedbackFocusId(null);
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
    setSearchFilters(emptySearch);
    setSearchTotal(null);
    setComparisonSummary(null);
    setHasMore(false);
    const destination = next ? researchDestination(window.location.search) : null;
    setFilter(destination === 'comparison' ? 'rspamd_all' : 'all');
    setOffset(0);
    setSection(destination === 'samples' ? 'quality' : destination === 'reliability' ? 'reliability' : 'messages');
    setDomain('');
    setDomains([]);
    setAdminDirty(false);
    setClusterDirty(false);
    setPreferenceDirty(false);
    setCorrectionDirty(false);
    setQualityDirty(false);
    setPendingNavigation(null);
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
              rspamd: data.analysis.rspamd,
              scoring: data.analysis.scoring,
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
        api<{ messages: Mail[]; total: number; has_more: boolean; comparison: ComparisonSummary | null }>(
          `/search/messages?${searchParameters(search, filter, domain, offset, searchFilters)}`,
        ),
        api<Stats>(`/stats?domain=${encodeURIComponent(domain)}`),
        api<string[]>('/domains'),
      ]);
      if (user !== activeUser.current || requestId !== latestRequest.current)
        return;
      setMails(messages.messages);
      setSearchTotal(messages.total);
      setComparisonSummary(messages.comparison);
      setHasMore(messages.has_more);
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
  }, [user, search, filter, offset, domain, searchFilters]);
  useEffect(() => {
    latestRequest.current += 1;
    const timer = setTimeout(() => {
      setMails([]);
      setSearchTotal(null);
      setHasMore(false);
      void refresh();
    }, 250);
    return () => clearTimeout(timer);
  }, [refresh, user]);
  useEffect(() => {
    if (!user || section !== 'messages' || selected || confirmation || pendingNavigation || busy)
      return;
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') void refresh();
    }, 30000);
    return () => clearInterval(timer);
  }, [user, section, selected, confirmation, pendingNavigation, busy, refresh]);
  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      if (
        user &&
        section === 'messages' &&
        !selected &&
        !confirmation &&
        !pendingNavigation &&
        (event.metaKey || event.ctrlKey) &&
        event.key.toLowerCase() === 'k'
      ) {
        event.preventDefault();
        searchInput.current?.focus();
      }
    };
    window.addEventListener('keydown', focusSearch);
    return () => window.removeEventListener('keydown', focusSearch);
  }, [user, section, selected, confirmation, pendingNavigation]);
  const researchTab = researchTabFor(section, filter);
  const MessagesHeading = researchTab === 'comparison' ? 'h2' : 'h1';
  useEffect(() => {
    if (!user) return;
    const url = new URL(window.location.href);
    url.search = researchSearch(url.search, researchTab);
    window.history.replaceState(null, '', url);
  }, [user, researchTab]);
  function navigate(next: ConsoleDestination['section'], nextFilter = 'all', nextDomain?: string) {
    if (busy) return;
    const destination = {section: next, filter: nextFilter, domain: nextDomain};
    if (configDirty) { setPendingNavigation(destination); return; }
    completeNavigation(destination);
  }
  function completeNavigation(destination: ConsoleDestination) {
    if (adminDirty) setAdminDraftEpoch(epoch => epoch + 1);
    if (qualityDirty) setQualityDraftEpoch(epoch => epoch + 1);
    if (preferenceDirty) setPreferenceDraftEpoch(epoch => epoch + 1);
    setAdminDirty(false);
    setClusterDirty(false);
    setPreferenceDirty(false);
    setCorrectionDirty(false);
    setQualityDirty(false);
    setPendingNavigation(null);
    setSection(destination.section);
    setFilter(destination.filter);
    if (destination.domain !== undefined) setDomain(destination.domain);
    setOffset(0);
    setSelected(null);
    setFeedbackFocusId(null);
    setNotice('');
    setMobileMenu(false);
  }
  const [feedbackRevision, setFeedbackRevision] = useState(0);
  const [feedbackFocusId,setFeedbackFocusId] = useState<string|null>(null);
  const correctionSaved = useCallback((id: string, category: FeedbackCategory | undefined, notice: string) => {
    if (!user || user !== activeUser.current) return;
    setFeedbackRevision(r => r + 1);
    setFeedbackFocusId(id);
    if (category) setSelected(previous => previous?.id === id ? {...previous,
      feedback: category === 'spam', feedback_category: category} : previous);
    setCorrectionDirty(false);
    setNotice(notice);
    void refresh();
  }, [user, refresh]);
  const recordFeedback = useCallback(async (id: string, category: FeedbackCategory) => {
    if (!user) throw new Error('Sign in required.');
    await api(`/messages/${id}/feedback`, {category}, user.csrf);
    correctionSaved(id, category, 'Correction saved. The recorded verdict, delivery and evaluation annotations remain unchanged.');
  }, [user, correctionSaved]);
  useEffect(() => (user ? registerFeedbackTool(recordFeedback) : undefined), [user, recordFeedback]);
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
      const result = await api<{ status: string; command_id?: string }>(
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
                r.address === recipient
                  ? {
                      ...r,
                      status:
                        result.status === 'queued' ? r.status : result.status,
                      pending_command: result.command_id ?? null,
                    }
                  : r,
              ),
            }
          : previous,
      );
      setConfirmation(null);
      setDiagnosticsRevision((value) => value + 1);
      setNotice(
        result.status === 'queued'
          ? "Command transmitted to the owner server: execution pending."
          : action === 'release'
            ? "Released message: delivery pending for this recipient."
            : "Delivery discarded for this recipient.",
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
          <RefreshCw size={16} className="spin" /> Connect to your space...
        </output>
      </main>
    );
  if (recoveryCodes.length)
    return (
      <RecoveryCodes
        codes={recoveryCodes}
        onDone={() => setRecoveryCodes([])}
      />
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
                  await api<User>('/login', {
                    username,
                    password,
                    code: mfaCode,
                  }),
                );
                setPassword('');
                setMfaCode('');
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
            <p className="eyebrow">WELCOME TO YOUR WORKSPACE</p>
            <h1>Good to meet you.</h1>
            <p className="muted">
              Log in to find your messages and filter decisions.
            </p>
            <label htmlFor="username">Username</label>
            <Input
              id="username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              maxLength={100}
              placeholder="Username"
            />
            <label htmlFor="password">Password</label>
            <div className="password-input">
              <Input
                id="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                maxLength={128}
                placeholder="Your password"
              />
              <button
                type="button"
                aria-label={
                  showPassword
                    ? "Hide password"
                    : "Show Password"
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
            <label htmlFor="login-mfa">
              Security code <span className="small muted">if activated</span>
            </label>
            <Input
              id="login-mfa"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value.trim())}
              autoComplete="one-time-code"
              maxLength={32}
              placeholder="Temporary code or emergency code"
            />
            <Button className="login-submit" disabled={busy} type="submit">
              {busy ? (
                <>
                  <RefreshCw size={17} className="spin" /> Signing in…
                </>
              ) : (
                <>
                  Sign in <ArrowUpRight size={18} />
                </>
              )}
            </Button>
            <p className="login-help">
              Need access? Contact your administrator.
            </p>
          </form>
          <p className="login-footnote">
            <LockKeyhole size={13} /> A space reserved for your organization.
          </p>
        </div>
      </main>
    );
  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className={`rail ${mobileMenu ? 'menu-open' : ''}`}>
        <div className="rail-brand">
          <div className="wordmark">
            <span className="brand-symbol">
              <BrandMark />
            </span>
            <div>
              NoiseFence<small>CLARITY IN YOUR MAIL</small>
            </div>
          </div>
          <button
            className="mobile-menu"
            aria-label={mobileMenu ? "Close Menu" : "Open menu"}
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
              <strong>{user.admin ? "My organization" : "My space"}</strong>
              <small>
                {user.admin ? "Administrator space" : "Personal space"}
              </small>
            </div>
            <LockKeyhole size={13} />
          </div>
          <div className="rail-label">MAIL</div>
          <nav className="navigation" aria-label="Mail settings">
            <button
              className={`nav-item ${section === 'messages' && filter !== 'quarantined' && !filter.startsWith('rspamd_') ? 'nav-active' : ''}`}
              aria-current={
                section === 'messages' && filter !== 'quarantined' && !filter.startsWith('rspamd_')
                  ? 'page'
                  : undefined
              }
              onClick={() => navigate('messages')}
            >
              <Inbox size={18} />
              {user.admin ? "All messages" : "My messages"}
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
              Quarantined
              {stats && (
                <span
                  className="nav-count"
                  title="Within the selected scope"
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
                      {((adminDirty &&
                        ['domains', 'gateways', 'filters'].includes(n.id)) ||
                        (clusterDirty && n.id === 'cluster')) && (
                        <span
                          className="draft-dot"
                          aria-label="Unrecorded draft"
                        />
                      )}
                    </button>
                  ))}
              </nav>
            </>
          )}
          <div className="rail-label admin-label">PERSONAL SPACE</div>
          <nav className="navigation" aria-label="Personal space">
            <Button
              variant="ghost"
              className={`nav-item ${section === 'preferences' ? 'nav-active' : ''}`}
              aria-current={section === 'preferences' ? 'page' : undefined}
              onClick={() => navigate('preferences')}
            >
              <ShieldCheck size={18} /> My filters
            </Button>
            <Button
              variant="ghost"
              className={`nav-item ${researchTab ? 'nav-active' : ''}`}
              aria-current={researchTab ? 'page' : undefined}
              onClick={() => navigate('quality')}
            >
              <SlidersHorizontal size={18} /> Quality & research
            </Button>
            <button
              className={`nav-item ${section === 'account' ? 'nav-active' : ''}`}
              aria-current={section === 'account' ? 'page' : undefined}
              onClick={() => navigate('account')}
            >
              <UserRound size={18} />
              My account
            </button>
          </nav>
        </div>
        <div className="rail-footer">
          <SoftwareStatus key={user.username} user={user} />
          <div className="signed-in-user">
            <span className="user-avatar">
              {Array.from(user.username).slice(0, 2).join('').toUpperCase()}
            </span>
            <div>
              <strong>{user.username}</strong>
              <span>
                {user.admin
                  ? "Administrator · All domains"
                  : user.addresses.join(', ') || "No address assigned"}
              </span>
            </div>
          </div>
          <Button
            variant="ghost"
            disabled={busy}
            onClick={async () => {
              if (
                configDirty &&
                !window.confirm(
                  (correctionDirty || qualityDirty) ? "Discard your unsaved annotations and sign out?" : "No adjustments are applied. Leave and abandon them?",
                )
              )
                return;
              try {
                await api('/logout', {}, user.csrf);
                changeSession(null);
                setSelected(null);
                setFeedbackFocusId(null);
                setMails([]);
              } catch (e) {
                setError((e as Error).message);
              }
            }}
          >
            <LogOut size={16} /> Sign out
          </Button>
        </div>
      </aside>
      <main id="main-content" className="workspace" tabIndex={-1}>
        <header className="topline">
          <span className="breadcrumbs">
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>
              {selected
                ? "Filter decision"
                : section === 'preferences'
                  ? "My filters"
                  : researchTab
                    ? "Quality & research"
                      : section === 'account'
                        ? "My account"
                        : section === 'messages' && filter === 'quarantined'
                          ? "Quarantined"
                          : navigation.find((n) => n.id === section)?.label}
            </strong>
          </span>
          <span
            className={`mode ${stats && stats.mode !== 'observe' ? 'mode-active' : ''}`}
          >
            <i />
            {stats
              ? stats.mode !== 'observe'
                ? "Actions enabled"
                : "Observation mode"
              : "Loading Mode..."}
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
              section === 'cluster' ||
              section === 'preferences' ||
              section === 'account' ||
              section === 'quality' ||
              section === 'reliability'
            }
          >
            <AdminConsole
              key={`${user.username}:${adminDraftEpoch}`}
              user={user}
              section={
                section === 'cluster' ||
                section === 'preferences' ||
                section === 'account' ||
                section === 'quality' ||
                section === 'reliability'
                  ? 'messages'
                  : section
              }
              onDirty={setAdminDirty}
              onApplied={refresh}
              onDomain={(name) => {
                navigate('messages', 'all', name);
              }}
            />
          </div>
        )}
        {section === 'cluster' && user.admin && (
          <ClusterConsole
            key={user.username}
            user={user}
            onDirty={setClusterDirty}
          />
        )}
        {section === 'preferences' && (
          <MyFilters key={`${user.username}:${preferenceDraftEpoch}`} user={user} onDirty={setPreferenceDirty} onBusy={setBusy} />
        )}
        <QualityNavigation
          tab={selected ? null : researchTab}
          onChange={tab => navigate(tab === 'samples' ? 'quality' : tab === 'reliability' ? 'reliability' : 'messages', tab === 'comparison' ? 'rspamd_all' : 'all')}
        >
        {section === 'quality' && <QualityConsole key={`${user.username}:${qualityDraftEpoch}`} user={user} onDirty={setQualityDirty} onBusy={setBusy} />}
        {section === 'reliability' && (
          <ReliabilityConsole key={user.username} />
        )}
        {section === 'account' && (
          <MyAccount
            key={user.username}
            user={user}
            onPasswordChanged={() => changeSession(null)}
            onMfaEnabled={(codes) => {
              setRecoveryCodes(codes);
              changeSession(null);
            }}
          />
        )}
        {section === 'messages' && (
          <>
            {selected ? (
              <>
                <Button
                  variant="ghost"
                  disabled={busy}
                  onClick={() => {
                    if (correctionDirty) { setPendingNavigation({section: 'messages', filter, domain}); return; }
                    setSelected(null);
                    setFeedbackFocusId(null);
                    setNotice('');
                  }}
                >
                  <ArrowLeft size={17} /> {researchTab === 'comparison' ? 'Back to comparison' : 'Back to messages'}
                </Button>
                <div className="detail-heading">
                  <p className="eyebrow">MESSAGE DETAILS</p>
                  <h1 ref={detailTitle} tabIndex={-1}>{selected.subject || "(No subject)"}</h1>
                  <div className="detail-badges">
                    {publicitySignal(selected.mailing) &&
                      selected.category !== 'publicity' && (
                        <span className="status publicity">Marketing signals</span>
                      )}
                    <span
                      className={`status ${deliverySummary(selected.recipients).tone}`}
                    >
                      {deliverySummary(selected.recipients).label}
                    </span>
                    {selected.feedback_category && (
                      <span className="status">
                        Your correction:{' '}
                        {selected.feedback_category === 'legitimate'
                          ? "Ham"
                          : selected.feedback_category === 'publicity'
                            ? "Pub"
                            : 'Spam'}
                      </span>
                    )}
                  </div>
                  <p className="muted">
                    {selected.sender || "Empty envelope sender"} ·{' '}
                    {new Date(selected.created * 1000).toLocaleString("en-GB")}
                    {selected.node_id && <span title={selected.node_updated_at ? `Last received status: ${new Date(selected.node_updated_at * 1000).toLocaleString("en-GB")}` : "Last received status unknown"}> · {selected.node_id}</span>}
                  </p>
                </div>
                <section
                  className="panel analysis-summary-panel"
                  aria-label="Message analysis summary"
                >
                  <div className="analysis-section-heading">
                    <div>
                      <p className="eyebrow">FILTER ANALYSIS</p>
                      <h2>Message analysis</h2>
                    </div>
                    <span className="small muted">
                      Verdict · action · delivery · evidence
                    </span>
                  </div>
                  <MessageScoreDetails
                    mail={selected}
                    recipients={selected.recipients}
                    verdict={classification(
                      selected,
                      historicalThreshold?.messageId === selected.id
                        ? historicalThreshold.threshold
                        : undefined,
                    )}
                  />
                </section>
                <div className="detail-grid">
                  <section className="panel message-actions-panel">
                    <p className="eyebrow">DELIVERY</p>
                    <h2>Recipient status</h2>
                    {selected.action && (
                      <p className="small muted">
                        Recorded action:{' '}
                        {actionLabel[selected.action.effective]}.
                        {' '}{actionReason(selected.action.reason)}. Planned action: {actionLabel[selected.action.requested]}.
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
                        {r.pending_command && (
                          <p className="notice">
                            Command sent; waiting for confirmation from the MX server.
                          </p>
                        )}
                        {r.status === 'quarantined' && (
                          <>
                            <p className="small muted">
                              {r.held_until
                                ? `Deletion scheduled on ${new Date(r.held_until * 1000).toLocaleString("en-GB")}.`
                                : "Message held on the gateway."}
                            </p>
                            <div className="feedback-actions">
                              <Button
                                disabled={busy || !!r.pending_command}
                                onClick={() => (
                                  setConfirmationError(''),
                                  setConfirmation({
                                    recipient: r.address,
                                    action: 'release',
                                  })
                                )}
                              >
                                Release and transmit
                              </Button>
                              <Button
                                variant="outline"
                                className="danger"
                                disabled={busy || !!r.pending_command}
                                onClick={() => (
                                  setConfirmationError(''),
                                  setConfirmation({
                                    recipient: r.address,
                                    action: 'delete',
                                  })
                                )}
                              >
                                Delete
                              </Button>
                            </div>
                          </>
                        )}
                      </div>
                    ))}
                    <p className="small muted">
                      Acceptance by the recipient server does not guarantee arrival in the inbox.
                    </p>
                    <p className="small muted">
                      The body and attachments remain on the gateway while any delivery is pending or quarantined. Deletion follows resolution of all recipients and required replica acknowledgements.
                    </p>
                    <MessageCorrection
                      key={`${user.username}:${selected.id}:${feedbackRevision}`}
                      id={selected.id} csrf={user.csrf} saved={selected.feedback_category ?? (selected.feedback === true ? 'spam' : null)}
                      report={selected.adaptive} focusAfterSave={feedbackFocusId===selected.id} blocked={busy} onBusy={setBusy} onDirty={setCorrectionDirty}
                      onSaved={(category, notice) => correctionSaved(selected.id, category, notice)}
                    />
                  </section>
                  <Suspense
                    fallback={
                      <section className="panel message-diagnostics">
                        <output>Loading diagnostics of the message...</output>
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
                  <details className="panel engine-details-panel">
                    <summary>Additional engine details</summary>
                    <div className="engine-execution-details">
                      {selected.fusion &&
                        selected.fusion.status !== 'disabled' && (
                          <div className="notice">
                            <strong>
                              {selected.fusion.mode === 'observe'
                                ? "Fusion in observation"
                                : "Joint Decision"}
                            </strong>
                            <p>
                              {
                                {
                                  not_run:
                                    "Not enough context to combine detectors.",
                                  complete: selected.fusion.prediction
                                    ?.tag_eligible
                                    ? `Estimate: ${((selected.fusion.prediction?.probability ?? 0) * 100).toFixed(1)} / 100.`
                                    : "Incomplete checks: Unusable estimate for marking.",
                                  unavailable:
                                    "Fusion unavailable for this message.",
                                  unsupported_profile:
                                    "This combination of controls has not yet been validated.",
                                  validation_expired:
                                    "Validating the expired model: no prefix added.",
                                }[selected.fusion.status]
                              }
                            </p>
                            {selected.fusion.mode === 'observe' && (
                              <p>
                                Research result; this model did not determine delivery.
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
                                            ? "Increases"
                                            : "Reduces"}{' '}
                                          the estimate
                                        </small>
                                      </li>
                                    ))}
                                </ul>
                              )}
                          </div>
                        )}
                      {selected.traffic && <TrafficDetails report={selected.traffic}/>}
                      {!!selected.smtp_admission?.length && (
                        <AdmissionDetails reports={selected.smtp_admission} />
                      )}
                      {selected.early_rbl && (
                        <EarlyRblDetails report={selected.early_rbl} />
                      )}
                      {selected.smtp_policy &&
                        selected.smtp_policy.status !== 'disabled' && (
                          <p className="muted">
                            SMTP and DNS consistency:{' '}
                            {
                              {
                                complete: "Controlled",
                                busy: "occupied capacity, incomplete control",
                                unavailable: "unavailable or exceeded",
                              }[selected.smtp_policy.status]
                            }{' '}
                            · {selected.smtp_policy.elapsed_ms} ms
                            {selected.smtp_policy.status === 'complete' &&
                              !selected.smtp_policy.scoring_enabled &&
                              "· observation without effect on score"}
                          </p>
                        )}
                      {selected.semantic &&
                        selected.semantic.status !== 'disabled' && (
                          <p className="muted">
                            Local multilingual analysis:{' '}
                            {
                              {
                                complete: "completed",
                                busy: "occupied capacity, incomplete analysis",
                                unavailable: "unavailable or exceeded",
                              }[selected.semantic.status]
                            }{' '}
                            · {selected.semantic.elapsed_ms} ms
                          </p>
                        )}
                      {selected.vision &&
                        selected.vision.status !== 'disabled' && (
                          <div className="notice">
                            <strong>
                              Reading images and PDF:{' '}
                              {
                                {
                                  complete: selected.vision.parts
                                    ? "completed"
                                    : "no local visual content",
                                  limited:
                                    "partial, reached limits or unreadable document",
                                  busy: "occupied capacity, incomplete analysis",
                                  unavailable: "unavailable or exceeded",
                                }[selected.vision.status]
                              }
                            </strong>
                            {selected.vision.pages > 0 && (
                              <p>
                                {selected.vision.pages} page(s) ·{' '}
                                {selected.vision.text_chars} characters ·{' '}
                                {selected.vision.qr_codes} QR code(s) ·{' '}
                                {selected.vision.other_codes} Other code(s) ·{' '}
                                {selected.vision.link_domains} domain(s) in links
                              </p>
                            )}
                            <small>
                              Local processing · {selected.vision.elapsed_ms} ms · Decoding does not fetch links; URL checks are reported separately.
                            </small>
                          </div>
                        )}
                      {selected.llm && selected.llm.status !== 'disabled' && (
                        <p className="muted">
                          Scaleway second opinion:{' '}
                          {
                            {
                              not_needed: "not selected for this message",
                              busy: "occupied capacity, incomplete analysis",
                              budget_limited:
                                "ceiling reached, local analysis preserved",
                              pricing_expired:
                                "rates to be revalidated, local analysis retained",
                              unavailable: "not available",
                              complete: "completed",
                            }[selected.llm.status]
                          }
                          {selected.llm.response_issue && <> · {responseIssueLabel(selected.llm.response_issue)}</>}
                          {selected.llm.grounding && <> · <strong>{groundingSummary(selected.llm.grounding)?.label}</strong>: {groundingSummary(selected.llm.grounding)?.detail}</>}
                          {selected.llm.coherent === false &&
                            ' · Inconsistent category and risk estimate; no scoring weight'}
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
                                  clean: "no detection",
                                  malware: "malicious file detected",
                                  suspicious: "suspicious signal to be examined",
                                  unscannable:
                                    "limited analysis or encrypted content",
                                  unavailable: "service unavailable",
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
                            Additional signatures:{' '}
                            {
                              {
                                clean: "no detection",
                                malware: "advisory signal to be considered",
                                suspicious: "advisory signal to be considered",
                                unscannable: "Limited analysis",
                                unavailable: "service unavailable",
                              }[selected.signatures.status]
                            }{' '}
                            · {selected.signatures.elapsed_ms} ms
                          </p>
                        )}
                    </div>
                  </details>
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

                </div>
                <RspamdComparison report={selected.rspamd} mail={selected} onRefresh={() => setDiagnosticsRevision(value => value + 1)} />
              </>
            ) : (
              <>
                <div className="page-heading">
                  <div>
                    <p className="eyebrow">
                      {user.admin
                        ? "ORGANIZATION VIEW"
                        : "YOUR MAIL"}
                    </p>
                    <MessagesHeading>
                      {filter.startsWith('rspamd_') ? 'Engine comparison' : filter === 'quarantined'
                        ? "Quarantined"
                        : user.admin
                          ? "All messages"
                          : "My messages"}
                    </MessagesHeading>
                    <p className="muted">
                      {filter === 'quarantined'
                        ? "Review the selected messages and choose their processing."
                        : researchTab === 'comparison'
                          ? 'Rspamd provides an independent recorded opinion. Agreement and disagreement are not ground truth.'
                          : "Follow each message, from analysis to delivery."}
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    onClick={() => void refresh()}
                    disabled={loading}
                    aria-label={
                      loading
                        ? "Updating of current messages"
                        : "Update Messages"
                    }
                  >
                    <RefreshCw size={16} className={loading ? 'spin' : ''} />
                    {loading ? "Refreshing…" : "Refresh"}
                  </Button>
                </div>
                <div className="scope-bar">
                  <Globe2 size={16} />
                  <label htmlFor="domain-scope">Scope</label>
                  <select
                    id="domain-scope"
                    value={domain}
                    onChange={(e) => {
                      setDomain(e.target.value);
                      setOffset(0);
                    }}
                  >
                    <option value="">
                      {user.admin ? "All domains" : "All my accesses"}
                    </option>
                    {domains.map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </select>
                  <span className="small muted">
                    {user.admin
                      ? "Full visibility of recipients"
                      : "Authorized recipients only"}
                  </span>
                </div>
                {researchTab !== 'comparison' && <div className="message-stat stats">
                  {[
                    {
                      id: 'all',
                      label: "Messages received",
                      count: stats?.received,
                      icon: Inbox,
                      tone: 'blue',
                      detail: "History available",
                    },
                    {
                      id: 'spam',
                      label: "Spam detected",
                      count: stats?.flagged,
                      icon: ShieldCheck,
                      tone: 'orange',
                      detail: "Spam classifications",
                    },
                    {
                      id: 'publicity',
                      label: "Pub",
                      count: stats?.publicity,
                      icon: Flag,
                      tone: 'purple',
                      detail: "Marketing and newsletters",
                    },
                    {
                      id: 'quarantined',
                      label: "Quarantine",
                      count: stats?.quarantined,
                      icon: Archive,
                      tone: 'amber',
                      detail: "Held messages",
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
                        {card.count?.toLocaleString("en-GB") ?? '—'}
                      </strong>
                      <small className="stat-detail">{card.detail}</small>
                      <ArrowUpRight className="stat-arrow" size={16} />
                    </button>
                  ))}
                </div>}
                {researchTab !== 'comparison' && stats?.mode === 'observe' && (
                  <div className="observation-banner">
                    <ShieldCheck size={18} />
                    <p>
                      <strong>Observation active</strong> Messages are analyzed and transmitted. Marking and quarantine actions are not applied.
                      {user.admin && "You can activate them in Filters."}
                    </p>
                    {user.admin && (
                      <Button
                        variant="ghost"
                        onClick={() => navigate('filters')}
                      >
                        See actions <ChevronRight size={15} />
                      </Button>
                    )}
                  </div>
                )}
                <section
                  className={`messages ${compact ? 'messages-compact' : ''} ${researchTab === 'comparison' ? 'messages-comparison' : ''}`}
                  aria-busy={loading}
                >
                  <div className="journal-heading">
                    <div>
                      <h2>
                        {filter === 'quarantined'
                          ? "Quarantine messages"
                          : "Message log"}
                      </h2>
                      <p>Decisions and delivery, same place.</p>
                    </div>
                    <Button
                      variant="outline"
                      className="density-toggle"
                      aria-pressed={compact}
                      onClick={() => setCompact((v) => !v)}
                    >
                      <Rows3 size={16} /> Compact view
                    </Button>
                  </div>
                  {filter.startsWith('rspamd_') && comparisonSummary && <RspamdOverview summary={comparisonSummary} />}
                  <div className="toolbar">
                    <fieldset
                      className="tabs"
                      aria-label="Filter Messages"
                    >
                      {(researchTab === 'comparison' ? [
                        ['rspamd_all', 'All comparisons'],
                        ['rspamd_disagreement', 'Disagreements'],
                        ['rspamd_inconclusive', 'Deferral / inconclusive'],
                        ['rspamd_unavailable', 'Unavailable'],
                      ] : [
                        ['all', "All"],
                        ['spam', "Spam detected"],
                        ['publicity', "Pub"],
                        ['legitimate', "Ham"],
                        [
                          'quarantined',
                          `Quarantine (${stats?.quarantined ?? 0})`,
                        ],
                      ]).map(([value, label]) => (
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
                      {researchTab !== 'comparison' && <label
                        className={`more-filters ${['pending', 'review', 'publicity_signal', 'incomplete', 'rspamd_all', 'rspamd_disagreement', 'rspamd_inconclusive', 'rspamd_unavailable'].includes(filter) ? 'has-filter' : ''}`}
                      >
                        <SlidersHorizontal size={14} />
                        <select
                          aria-label="Other message filters"
                          value={
                            [
                              'pending',
                              'review',
                              'publicity_signal',
                              'incomplete', 'rspamd_all', 'rspamd_disagreement', 'rspamd_inconclusive', 'rspamd_unavailable',
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
                            More filters
                          </option>
                          <option value="pending">Pending</option>
                          <option value="review">Historical unresolved decisions</option>
                          <option value="publicity_signal">
                            Marketing signals, all classifications
                          </option>
                          <option value="incomplete">Partial analysis</option>
                          <optgroup label="Engine comparison">
                            <option value="rspamd_all">All Rspamd comparisons</option>
                            <option value="rspamd_disagreement">Engines disagree</option>
                            <option value="rspamd_inconclusive">No comparable verdict</option>
                            <option value="rspamd_unavailable">Comparison not completed</option>
                          </optgroup>
                        </select>
                      </label>}
                    </fieldset>
                    <div className="search message-search">
                      <Search size={18} />
                      <Input
                        ref={searchInput}
                        aria-label="Search subjects, addresses, rules and identifiers"
                        placeholder="Search for a message..."
                        value={search}
                        onChange={(e) => {
                          setSearch(e.target.value);
                          setOffset(0);
                        }}
                        maxLength={600}
                      />
                      {!search && (
                        <kbd
                          className="search-shortcut"
                          title="Ctrl, or - + K"
                          aria-hidden="true"
                        >
                          ⌘ K
                        </kbd>
                      )}
                      {search && (
                        <button
                          className="clear-search"
                          aria-label="Clear Search"
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
                  <MessageSearchControls
                    value={searchFilters}
                    onChange={(value) => {
                      setSearchFilters(value);
                      setOffset(0);
                    }}
                  />
                  {(search ||
                    domain ||
                    filter !== 'all' ||
                    searchFilterCount(searchFilters) > 0) && (
                    <div
                      className="search-context"
                      aria-label="Active criteria"
                    >
                      <span>View</span>
                      {domain && (
                        <span className="filter-chip">
                          <Globe2 size={13} />
                          {domain}
                        </span>
                      )}
                      {filter !== 'all' && (
                        <span className="filter-chip">
                          {{
                            spam: "Spam detected",
                            publicity: "Pub",
                            legitimate: "Ham",
                            quarantined: "Quarantined",
                            pending: "Pending",
                            review: "Historical unresolved",
                            publicity_signal: "Marketing signals",
                            incomplete: "Partial analysis",
                            rspamd_all: "All Rspamd comparisons",
                            rspamd_disagreement: "Engines disagree",
                            rspamd_inconclusive: "No comparable verdict",
                            rspamd_unavailable: "Comparison not completed",
                          }[filter] ?? filter}
                        </span>
                      )}
                      {search && (
                        <span className="filter-chip search-term">
                          <Search size={13} />
                          {search}
                        </span>
                      )}
                      {searchFilterCount(searchFilters) > 0 && (
                        <span className="filter-chip">
                          {searchFilterCount(searchFilters)} advanced criteria
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          setSearchFilters(emptySearch);
                          setSearch('');
                          setFilter(researchTab === 'comparison' ? 'rspamd_all' : 'all');
                          setDomain('');
                          setOffset(0);
                        }}
                      >
                        <X size={13} />
                        Reset
                      </button>
                    </div>
                  )}
                  <div className="results-meta">
                    <span>
                      {loading
                        ? "Updating messages..."
                        : searchTotal === null
                          ? "Search unavailable"
                          : `${searchTotal} result${searchTotal > 1 ? 's' : ''}${mails.length ? ` · ${offset + 1}–${offset + mails.length}` : ''}`}
                      {domain && ` · ${domain}`}
                    </span>
                    <span>
                      <Clock3 size={13} />
                      {updatedAt
                        ? `Updated to ${updatedAt.toLocaleTimeString("en-GB", { hour: '2-digit', minute: '2-digit' })}`
                        : "Loading…"}
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
                          {researchTab !== 'comparison' && <TableHead>Recipients</TableHead>}
                          <TableHead>{researchTab === 'comparison' ? 'NoiseFence' : 'Classification'}</TableHead>
                          {researchTab === 'comparison' && <TableHead>Rspamd · second opinion</TableHead>}
                          <TableHead>Delivery</TableHead>
                          {researchTab !== 'comparison' && <TableHead>Score / 100</TableHead>}
                          {researchTab !== 'comparison' && <TableHead>Received on</TableHead>}
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
                                  <strong>{m.subject || "(Not applicable)"}</strong>
                                  {m.node_id && (
                                    <span className="mail-node-label">
                                      {m.node_id}
                                    </span>
                                  )}
                                  <span>
                                    {m.sender || "Delivery notification"}
                                  </span>
                                  {researchTab === 'comparison' && <>
                                    <span>To: {m.recipients.map(r => r.address).join(', ')}</span>
                                    <time dateTime={new Date(m.created * 1000).toISOString()}>{new Date(m.created * 1000).toLocaleString('en-GB')}</time>
                                  </>}
                                </span>
                              </button>
                            </TableCell>
                            {researchTab !== 'comparison' && <TableCell>
                              <span className="small recipient-list">
                                {m.recipients.map((r) => r.address).join(', ')}
                              </span>
                            </TableCell>}
                            <TableCell>
                              <span
                                title={classificationDetail(m)}
                                className={`status ${classification(m, stats?.threshold ?? 95).tone}`}
                              >
                                {
                                  classification(m, stats?.threshold ?? 95)
                                    .label
                                }
                              </span>
                              {classificationQualification(m) && (
                                <small className="tag-note">{classificationQualification(m)}</small>
                              )}
                              {publicitySignal(m.mailing) &&
                                m.category !== 'publicity' && (
                                  <small className="tag-note">
                                    Marketing signals · priority safety decision
                                  </small>
                                )}
                              {(m.tagged || m.pub_tagged) && (
                                <small className="tag-note">
                                  {m.tagged ? '[SPAM]' : '[PUB]'} added
                                </small>
                              )}
                              {m.feedback_category && (
                                <small className="tag-note">
                                  Recorded correction
                                </small>
                              )}
                              {researchTab === 'comparison' && <MessageScore mail={m} tone={classification(m).tone} />}
                            </TableCell>
                            {researchTab === 'comparison' && <TableCell><RspamdResult report={m.rspamd} /></TableCell>}
                            <TableCell>
                              <span
                                className={`status delivery-status ${deliverySummary(m.recipients).tone}`}
                              >
                                {deliverySummary(m.recipients).label}
                              </span>
                            </TableCell>
                            {researchTab !== 'comparison' && <TableCell>
                              <MessageScore
                                mail={m}
                                tone={
                                  classification(m, stats?.threshold ?? 95).tone
                                }
                              />
                            </TableCell>}
                            {researchTab !== 'comparison' && <TableCell className="muted">
                              <time
                                className="message-date"
                                dateTime={new Date(
                                  m.created * 1000,
                                ).toISOString()}
                              >
                                <strong>
                                  {new Date(
                                    m.created * 1000,
                                  ).toLocaleTimeString("en-GB", {
                                    hour: '2-digit',
                                    minute: '2-digit',
                                  })}
                                </strong>
                                <span>
                                  {new Date(
                                    m.created * 1000,
                                  ).toLocaleDateString("en-GB", {
                                    day: 'numeric',
                                    month: 'short',
                                  })}
                                </span>
                              </time>
                            </TableCell>}
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
                            title={classificationDetail(m)}
                                className={`status ${classification(m, stats?.threshold ?? 95).tone}`}
                          >
                            {classification(m, stats?.threshold ?? 95).label}
                          </span>
                          {classificationQualification(m) && (
                            <span className="small">{classificationQualification(m)}</span>
                          )}
                          {publicitySignal(m.mailing) &&
                            m.category !== 'publicity' && (
                              <span className="status publicity">
                                Marketing signals
                              </span>
                            )}
                          <time
                            dateTime={new Date(m.created * 1000).toISOString()}
                          >
                            {new Date(m.created * 1000).toLocaleString(
                              "en-GB",
                              {
                                day: 'numeric',
                                month: 'short',
                                hour: '2-digit',
                                minute: '2-digit',
                              },
                            )}
                          </time>
                        </span>
                        <strong>{m.subject || "(Not applicable)"}</strong>
                        {m.node_id && (
                          <span className="mail-node-label">{m.node_id}</span>
                        )}
                        <small>{m.sender || "Delivery notification"}</small>
                        <small>
                          To: {m.recipients.map((r) => r.address).join(', ')}
                        </small>
                        <MessageScore
                          mail={m}
                          tone={classification(m, stats?.threshold ?? 95).tone}
                        />
                        {researchTab === 'comparison' && <RspamdResult report={m.rspamd} />}
                        <span className="delivery-line">
                          <span
                            className={`status ${deliverySummary(m.recipients).tone}`}
                          >
                            {deliverySummary(m.recipients).label}
                          </span>
                          {(m.tagged || m.pub_tagged) && (
                            <span>{m.tagged ? '[SPAM]' : '[PUB]'} added</span>
                          )}
                          <ChevronRight size={15} />
                        </span>
                      </button>
                    ))}
                  </div>
                  {!mails.length && !loading && searchTotal !== null && (
                    <div className="empty">
                      <ShieldCheck size={32} />
                      <h2>
                        {filter === 'quarantined'
                          ? "No quarantine message"
                          : search ||
                              domain ||
                              filter !== 'all' ||
                              searchFilterCount(searchFilters) > 0
                            ? "No results for these criteria"
                            : "Your history is ready"}
                      </h2>
                      <p>
                        {filter === 'quarantined'
                          ? "The messages selected for your recipients will appear here."
                          : search ||
                              domain ||
                              filter !== 'all' ||
                              searchFilterCount(searchFilters) > 0
                            ? "Edit the search or display all messages."
                            : "Next messages processed for your addresses will appear here."}
                      </p>
                      {(search ||
                        domain ||
                        filter !== 'all' ||
                        searchFilterCount(searchFilters) > 0) && (
                        <Button
                          variant="outline"
                          onClick={() => {
                            setSearch('');
                            setSearchFilters(emptySearch);
                            setFilter(researchTab === 'comparison' ? 'rspamd_all' : 'all');
                            setDomain('');
                            setOffset(0);
                          }}
                        >
                          {researchTab === 'comparison' ? 'Show all comparisons' : 'Show all messages'}
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
                      Previous
                    </Button>
                    <span>Page {Math.floor(offset / 50) + 1}</span>
                    <Button
                      variant="ghost"
                      disabled={loading || !hasMore}
                      onClick={() => setOffset(offset + 50)}
                    >
                      Next
                    </Button>
                  </div>
                </section>
              </>
            )}
          </>
        )}
        </QualityNavigation>
      </main>
      {pendingNavigation && <ConfirmDialog title={correctionDirty || qualityDirty ? "Discard unsaved annotations?" : "Discard unsaved settings?"} confirmLabel="Discard and leave" danger busy={false}
        onCancel={() => setPendingNavigation(null)} onConfirm={() => completeNavigation(pendingNavigation)}>
        <p>{correctionDirty || qualityDirty ? "Your unsaved annotations will be discarded. Saved feedback, evaluation annotations and message delivery remain unchanged." : preferenceDirty ? "Your unsaved personal filter changes will be discarded. Installed preferences and accepted messages will remain unchanged." : "The configuration draft and any unfinished domain setup will be discarded. Installed settings and accepted messages will remain unchanged."}</p>
      </ConfirmDialog>}
      {confirmation && selected && (
        <ConfirmDialog
          title={
            confirmation.action === 'release'
              ? "Release this message?"
              : "Delete this delivery?"
          }
          confirmLabel={
            confirmation.action === 'release'
              ? "Release and transmit"
              : "Delete permanently"
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
            {selected.subject || "(Not applicable)"}
          </p>
          <p>
            To: <strong>{confirmation.recipient}</strong>
          </p>
          <p>
            {confirmation.action === 'release'
              ? "Request delivery without a tag for this recipient. Wait for MX confirmation and check the delivery status. The saved classification and other recipients remain unchanged."
              : "This delivery will be deleted without sending. This action is final for this recipient."}
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
