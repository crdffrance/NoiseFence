'use client';
import { useEffect, useState } from 'react';
import { Archive, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from './client';

export type ArchiveSettings = { enabled: boolean; collect_until: number; retention_days: number; quota_mib: number; max_message_bytes: number; domains: string[] };
type ArchiveStatus = { collecting: boolean; collect_until: number; retention_days: number; quota_mib: number; messages: number; stored_bytes: number; pending_observations: number; pending_writes: number; counters: Record<string, number>; checked_at: number };
type Node = { node_id: string; last_seen: number; status: ArchiveStatus | null };
type Overview = { local: Node; workers: Node[] };
const defaults: ArchiveSettings = { enabled: false, collect_until: 0, retention_days: 30, quota_mib: 5120, max_message_bytes: 25 * 1024 * 1024, domains: [] };
function dateInput(value: number) { if (!value) return ''; const d = new Date(value * 1000); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0,16); }
function dateLabel(value: number) { return value ? new Date(value * 1000).toLocaleString() : 'Not scheduled'; }
function size(value: number) { return `${(value / 1024 / 1024).toLocaleString(undefined, { maximumFractionDigits: 1 })} MiB`; }
const reasons: Record<string,string> = { archived: 'Originals archived', expired: 'Originals expired', busy: 'Skipped: archive busy', oversize: 'Skipped: size limit', domain_scope: 'Skipped: domain scope', quota_full: 'Skipped: quota reached', entry_limit: 'Skipped: 100,000-original limit', disk_reserve: 'Skipped: mail storage reserve', stopped_before_write: 'Cancelled after collection stopped', write_error: 'Archive write failures', observation_capacity: 'Observation updates waiting for space', recovered_orphans: 'Interrupted writes cleaned up', exports: 'Local exports' };

export function ResearchArchiveSettings({value,onChange,domains}:{value:ArchiveSettings|null;onChange:(v:ArchiveSettings)=>void;domains:string[]}) {
  const settings=value ?? defaults;
  const [now,setNow]=useState(()=>Math.floor(Date.now()/1000));
  useEffect(()=>{const timer=setInterval(()=>setNow(Math.floor(Date.now()/1000)),30000);return()=>clearInterval(timer);},[]);
  const [overview,setOverview]=useState<Overview|null>(null);
  const [error,setError]=useState('');
  const [loading,setLoading]=useState(false);
  async function refresh() { setLoading(true); try { setOverview(await api<Overview>('/admin/research-archive')); setError(''); } catch(e) { setError((e as Error).message); } finally { setLoading(false); } }
  useEffect(()=>{ let live=true; api<Overview>('/admin/research-archive').then(v=>{if(live)setOverview(v);}).catch(e=>{if(live)setError(e.message);}); return ()=>{live=false;}; },[]);
  const until=settings.collect_until;
  const expired=settings.enabled && until>0 && until<=now;
  return <section className="panel research-archive" aria-label="Temporary research archive">
    <div className="management-toolbar"><div><p className="eyebrow">PRIVATE RESEARCH · TEMPORARY COLLECTION</p><h2><Archive size={21} aria-hidden="true"/> Original message archive</h2></div><Button variant="outline" disabled={loading} onClick={()=>void refresh()}><RefreshCw size={16}/> Refresh counters</Button></div>
    <p>Keep encrypted originals, attachments, SMTP context and engine observations for later R&D. This archive never changes message scores or delivery.</p>
    <div className="research-archive-fields">
      <label><span>Collect new accepted messages</span><input type="checkbox" checked={settings.enabled} onChange={e=>onChange({...settings,enabled:e.target.checked,collect_until:e.target.checked && !until ? Math.floor(Date.now()/1000)+30*86400 : until})}/></label>
      <label>Automatic collection stop<input type="datetime-local" value={dateInput(until)} max={dateInput(now+90*86400)} onChange={e=>{const n=Date.parse(e.target.value);if(Number.isFinite(n))onChange({...settings,collect_until:Math.floor(n/1000)});}}/><small>Your local time. Resaving or restarting never extends this date.</small></label>
      <label>Retention for new originals (days)<input type="number" min={1} max={90} value={settings.retention_days} onChange={e=>onChange({...settings,retention_days:Number(e.target.value)})}/><small>Existing originals keep their recorded expiry. Purging continues after collection stops.</small></label>
      <label>Archive quota per MX (MiB)<input type="number" min={64} max={102400} value={settings.quota_mib} onChange={e=>onChange({...settings,quota_mib:Number(e.target.value)})}/></label>
      <label>Largest original (MiB)<input type="number" min={1/1024} max={25} step="any" value={settings.max_message_bytes/1024/1024} onChange={e=>onChange({...settings,max_message_bytes:Math.round(Number(e.target.value)*1024*1024)})}/><small>Larger messages are skipped whole; originals are never truncated.</small></label>
    </div>
    <fieldset><legend>Domain scope</legend><p className="small muted">No selection includes all configured domains. For mixed-domain messages, every recipient must belong to this scope.</p><div className="management-toolbar">{Array.from(new Set([...domains,...settings.domains])).map(domain=><label key={domain}><input type="checkbox" checked={settings.domains.includes(domain)} onChange={e=>onChange({...settings,domains:e.target.checked ? [...settings.domains,domain] : settings.domains.filter(d=>d!==domain)})}/> {domain}</label>)}</div></fieldset>
    {expired && <output className="status review">Collection has reached its stop date. Set a new future date and save to resume.</output>}
    <p className="small muted">Save the configuration above to apply changes. Collection is bounded and can skip messages under load or storage pressure. Each receiving MX keeps its own private archive; research originals and keys are excluded from built-in operational backups and console replication. The mail queue still follows its configured replication policy.</p>
    {error && <p className="error" role="alert">{error}</p>}
    {overview && <div className="research-archive-nodes">{[overview.local,...overview.workers].map(node=><article key={node.node_id} className="config-card"><h3>{node.node_id}</h3>{node.status ? <>
      <span className="status">{now-node.last_seen>60 ? 'Status is stale' : node.status.collecting && node.status.collect_until>now ? 'Collecting' : 'Collection stopped'}</span>
      <dl><dt>Originals retained</dt><dd>{node.status.messages.toLocaleString()}</dd><dt>Encrypted storage</dt><dd>{size(node.status.stored_bytes)} / {node.status.quota_mib.toLocaleString()} MiB</dd><dt>Automatic stop</dt><dd>{dateLabel(node.status.collect_until)}</dd><dt>Writes in progress</dt><dd>{node.status.pending_writes}</dd><dt>Observations awaiting completion</dt><dd>{node.status.pending_observations}</dd><dt>Last update</dt><dd>{dateLabel(node.status.checked_at)}</dd></dl>
      <details><summary>Collection counters</summary><dl>{Object.entries(node.status.counters).map(([name,count])=><div key={name}><dt>{reasons[name] ?? name}</dt><dd>{count.toLocaleString()}</dd></div>)}</dl></details>
    </> : <p>Archive status is unavailable on this node.</p>}</article>)}</div>}
    <p className="small muted">Originals are available through the local operator export command. The console does not display archived HTML, open links, execute attachments or send this corpus to external analysis services.</p>
  </section>;
}
