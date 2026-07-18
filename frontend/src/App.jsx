// ============================================================
// FILE: App.jsx — PhishGuard AI  |  Advanced Phishing Detection System
// Stack: React 19 + Vanilla CSS
// Features:
//   - Login page with secure auth
//   - VirusTotal-style multi-engine scan results
//   - Vulnerability cards with CVE-style details (type, cause, impact)
//   - Radial threat score + animated bar
//   - URL metadata parsing
//   - Tabbed result view: Summary | Vulnerabilities | Engines | Details
//   - Scan history with re-scan
// ============================================================

import { useState, useEffect, useRef } from 'react';
import './index.css';

// ─── SVG Icon Library ──────────────────────────────────────────
const Icon = {
  Shield: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 20, height: 20 }}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  ),
  Search: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" style={{ width: 18, height: 18 }}>
      <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
    </svg>
  ),
  Check: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  ),
  Warn: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  Danger: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" style={{ width: 16, height: 16 }}>
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  ),
  User: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
    </svg>
  ),
  Lock: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  ),
  Logout: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" /><line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  ),
  Eye: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} style={{ width: 15, height: 15 }}>
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
    </svg>
  ),
  EyeOff: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" style={{ width: 15, height: 15 }}>
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </svg>
  ),
  Globe: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
      <circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  ),
  Bug: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
      <rect x="8" y="6" width="8" height="14" rx="4" />
      <path d="M19 7l-3 2M5 7l3 2M19 12h-3M8 12H5M19 17l-3-2M5 17l3-2" />
      <path d="M12 6V3M9 3l1 3M15 3l-1 3" />
    </svg>
  ),
  Cpu: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16 }}>
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="9" y="9" width="6" height="6" />
      <line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" />
      <line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" />
      <line x1="20" y1="9" x2="23" y2="9" /><line x1="20" y1="14" x2="23" y2="14" />
      <line x1="1" y1="9" x2="4" y2="9" /><line x1="1" y1="14" x2="4" y2="14" />
    </svg>
  ),
  Info: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" style={{ width: 16, height: 16 }}>
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="8" x2="12" y2="8" strokeWidth={3} /><line x1="12" y1="12" x2="12" y2="16" />
    </svg>
  ),
  Clock: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" style={{ width: 14, height: 14 }}>
      <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
    </svg>
  ),
  Refresh: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
      <polyline points="23 4 23 10 17 10" /><polyline points="1 20 1 14 7 14" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  ),
  Copy: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 13, height: 13 }}>
      <rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  ),
  Expand: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
      <polyline points="15 3 21 3 21 9" /><polyline points="9 21 3 21 3 15" />
      <line x1="21" y1="3" x2="14" y2="10" /><line x1="3" y1="21" x2="10" y2="14" />
    </svg>
  ),
};

// ─── Severity Config ───────────────────────────────────────────
const SEV_CONFIG = {
  CRITICAL: { color: '#ff4757', bg: 'rgba(255,71,87,0.12)', border: 'rgba(255,71,87,0.3)', label: '🔴 CRITICAL', dot: '#ff4757' },
  HIGH: { color: '#ff6b35', bg: 'rgba(255,107,53,0.12)', border: 'rgba(255,107,53,0.3)', label: '🟠 HIGH', dot: '#ff6b35' },
  MEDIUM: { color: '#ffa502', bg: 'rgba(255,165,2,0.12)', border: 'rgba(255,165,2,0.3)', label: '🟡 MEDIUM', dot: '#ffa502' },
  LOW: { color: '#2ed573', bg: 'rgba(46,213,115,0.12)', border: 'rgba(46,213,115,0.3)', label: '🟢 LOW', dot: '#2ed573' },
};

// ─── Result Config ─────────────────────────────────────────────
const RESULT_CONFIG = {
  PHISHING: { gradient: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.35)', barColor: '#ef4444', icon: <Icon.Danger />, glow: 'glow-red', accent: '#ef4444' },
  SUSPICIOUS: { gradient: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.35)', barColor: '#f59e0b', icon: <Icon.Warn />, glow: 'glow-amber', accent: '#f59e0b' },
  SAFE: { gradient: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.3)', barColor: '#10b981', icon: <Icon.Check />, glow: 'glow-green', accent: '#10b981' },
};

// ─── Sample URLs ───────────────────────────────────────────────
const SAMPLES = [
  { emoji: '✅', label: 'Safe', url: 'https://google.com', hint: 'HTTPS, clean domain', color: '#10b981' },
  { emoji: '⚠️', label: 'Suspicious', url: 'http://secure-login-update.info', hint: 'HTTP + keywords + TLD', color: '#f59e0b' },
  { emoji: '🚨', label: 'Phishing', url: 'http://paypal.verify-account@banking.xyz', hint: 'Brand spoofing + @ trick', color: '#ef4444' },
];

// ─── Helpers ──────────────────────────────────────────────────
function ScoreRing({ score, label, accent }) {
  const r = 52, circ = 2 * Math.PI * r;
  const dash = circ - (score / 100) * circ;
  return (
    <div className="score-ring" style={{ width: 140, height: 140 }}>
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={r} stroke="rgba(255,255,255,0.07)" strokeWidth="10" fill="none" />
        <circle
          cx="70" cy="70" r={r}
          stroke={accent}
          strokeWidth="10"
          fill="none"
          strokeDasharray={circ}
          strokeDashoffset={dash}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(.22,1,.36,1)', filter: `drop-shadow(0 0 8px ${accent}88)` }}
        />
      </svg>
      <div style={{ position: 'absolute', textAlign: 'center' }}>
        <div className="score-text" style={{ color: accent }}>{score}</div>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 2 }}>/ 100</div>
        <div style={{ fontSize: 10, color: accent, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', marginTop: 2 }}>{label}</div>
      </div>
    </div>
  );
}

function Spinner({ size = 18, color = '#6366f1' }) {
  return (
    <svg className="spin" width={size} height={size} viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="10" stroke={color} strokeOpacity="0.25" strokeWidth="4" />
      <path fill={color} d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

function ScanLoadingGrid() {
  return (
    <div style={{ padding: '24px 0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        <Spinner size={22} />
        <span style={{ color: '#a5b4fc', fontWeight: 600, fontSize: 14 }}>Running multi-engine analysis…</span>
      </div>
      <div className="scanning-grid">
        {Array.from({ length: 16 }).map((_, i) => (
          <div key={i} className="scan-cell" style={{ animationDelay: `${i * 0.08}s` }} />
        ))}
      </div>
      <div style={{ marginTop: 16, display: 'flex', gap: 20, flexWrap: 'wrap' }}>
        {['Checking URL patterns', 'Running heuristics', 'Querying threat DB', 'Analyzing domain intel'].map((s, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'rgba(255,255,255,0.35)' }}>
            <Spinner size={11} color="#6366f1" />{s}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── VulnerabilityCard Component ─────────────────────────────
function VulnerabilityCard({ vuln, index }) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEV_CONFIG[vuln.severity] || SEV_CONFIG.LOW;

  return (
    <div
      className="vuln-card"
      style={{ background: sev.bg, borderColor: sev.border, animationDelay: `${index * 0.1}s` }}
    >
      {/* Header */}
      <div
        style={{ padding: '14px 16px', cursor: 'pointer', userSelect: 'none' }}
        onClick={() => setExpanded(e => !e)}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 8, background: `${sev.color}20`,
            border: `1px solid ${sev.color}40`, display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: sev.color, flexShrink: 0
          }}>
            <Icon.Bug />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
              <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 99, background: `${sev.color}20`, color: sev.color, border: `1px solid ${sev.color}40` }}>
                {vuln.severity}
              </span>
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.35)', fontFamily: 'JetBrains Mono, monospace' }}>{vuln.id}</span>
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginLeft: 'auto' }}>CVSS {vuln.cvss}</span>
            </div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9', lineHeight: 1.4 }}>{vuln.name}</div>
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', marginTop: 2 }}>{vuln.type}</div>
          </div>
          <div style={{ color: 'rgba(255,255,255,0.3)', flexShrink: 0, marginTop: 8 }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} style={{ width: 14, height: 14, transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </div>
        </div>
      </div>

      {/* Expanded Body */}
      {expanded && (
        <div style={{ borderTop: `1px solid ${sev.border}`, padding: '14px 16px' }} className="fade-in">
          <table className="info-table" style={{ marginBottom: 12 }}>
            <tbody>
              <tr>
                <td>Type</td>
                <td style={{ color: '#c4b5fd', fontSize: 13 }}>{vuln.type}</td>
              </tr>
              <tr>
                <td>CWE</td>
                <td style={{ color: 'rgba(255,255,255,0.7)', fontFamily: 'JetBrains Mono, monospace', fontSize: 13 }}>{vuln.cweId}</td>
              </tr>
              <tr>
                <td>Technique</td>
                <td style={{ color: 'rgba(255,255,255,0.7)', fontFamily: 'JetBrains Mono, monospace', fontSize: 13 }}>{vuln.technique}</td>
              </tr>
              <tr>
                <td>CVSS Score</td>
                <td style={{ color: sev.color, fontWeight: 700, fontSize: 13 }}>{vuln.cvss} / 10.0</td>
              </tr>
            </tbody>
          </table>

          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(255,255,255,0.35)', marginBottom: 5 }}>Description</div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.65)', lineHeight: 1.7 }}>{vuln.description}</div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(255,165,2,0.8)', marginBottom: 5 }}>⚡ Root Cause</div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.65)', lineHeight: 1.7 }}>{vuln.cause}</div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(239,68,68,0.8)', marginBottom: 5 }}>💥 Impact</div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.65)', lineHeight: 1.7 }}>{vuln.impact}</div>
          </div>
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(16,185,129,0.8)', marginBottom: 5 }}>🛡 Mitigation</div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.65)', lineHeight: 1.7 }}>{vuln.mitigation}</div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Engine Results Component ─────────────────────────────────
function EngineResults({ engines, summary }) {
  const [filter, setFilter] = useState('all');
  const filtered = filter === 'all' ? engines : filter === 'detected' ? engines.filter(e => e.detected) : engines.filter(e => !e.detected);

  return (
    <div>
      {/* Summary bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: 6 }}>
          {[['all', 'All'], ['detected', 'Flagged'], ['clean', 'Clean']].map(([val, lbl]) => (
            <button key={val} onClick={() => setFilter(val)} style={{
              padding: '5px 12px', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: 'pointer', border: 'none', fontFamily: 'Inter, sans-serif',
              background: filter === val ? 'rgba(99,102,241,0.25)' : 'rgba(255,255,255,0.06)',
              color: filter === val ? '#a5b4fc' : 'rgba(255,255,255,0.4)',
              transition: 'all 0.2s'
            }}>
              {lbl}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 12, fontSize: 12, color: 'rgba(255,255,255,0.5)', marginLeft: 'auto' }}>
          <span>🔴 {summary.detected} flagged</span>
          <span>🟢 {summary.clean} clean</span>
          <span style={{ color: 'rgba(255,255,255,0.3)' }}>{summary.detectionRate}% detection rate</span>
        </div>
      </div>

      {/* Big Detection Bar */}
      <div style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 12, padding: '14px 16px', marginBottom: 16, border: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'rgba(255,255,255,0.4)', marginBottom: 8 }}>
          <span>Detection Rate</span>
          <span style={{ fontWeight: 700, color: summary.detectionRate > 50 ? '#ef4444' : summary.detectionRate > 20 ? '#f59e0b' : '#10b981' }}>
            {summary.detected} / {summary.total} engines
          </span>
        </div>
        <div className="threat-bar-track">
          <div className="threat-bar-fill bar-fill" style={{
            width: `${summary.detectionRate}%`,
            background: summary.detectionRate > 50
              ? 'linear-gradient(90deg, #ef4444, #ff6b6b)'
              : summary.detectionRate > 20
                ? 'linear-gradient(90deg, #f59e0b, #fbbf24)'
                : 'linear-gradient(90deg, #10b981, #34d399)'
          }} />
        </div>
      </div>

      {/* Engine Grid */}
      <div className="engine-grid">
        {filtered.map((engine, i) => (
          <div
            key={engine.name}
            className={`engine-card ${engine.detected ? 'detected' : 'clean'}`}
            style={{ animationDelay: `${i * 0.04}s` }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                background: engine.detected ? '#ef4444' : '#10b981',
                boxShadow: `0 0 6px ${engine.detected ? '#ef444488' : '#10b98188'}`
              }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: engine.detected ? '#fca5a5' : '#6ee7b7', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {engine.name}
              </span>
            </div>
            <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginBottom: 2 }}>{engine.vendor}</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: engine.detected ? '#ef4444' : '#10b981', textTransform: 'uppercase' }}>
                {engine.detected ? engine.result : 'Clean'}
              </span>
              <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.2)', fontFamily: 'JetBrains Mono, monospace' }}>{engine.scanTime}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── URL Details Component ────────────────────────────────────
function URLDetails({ result }) {
  const [copied, setCopied] = useState(false);
  function copyUrl() {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  const meta = result.urlMeta || {};
  const ts = new Date(result.scanTimestamp);

  return (
    <div>
      {/* URL Box */}
      <div style={{ background: 'rgba(0,0,0,0.4)', borderRadius: 12, padding: '12px 14px', marginBottom: 16, border: '1px solid rgba(255,255,255,0.08)', display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ flex: 1, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#a5b4fc', wordBreak: 'break-all', lineHeight: 1.6 }}>
          {result.url}
        </div>
        <button onClick={copyUrl} className="btn-ghost" style={{ flexShrink: 0, padding: '6px 10px', display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon.Copy />
          <span style={{ fontSize: 11 }}>{copied ? 'Copied!' : 'Copy'}</span>
        </button>
      </div>

      {/* Metadata Table */}
      <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 12, padding: '14px 16px', border: '1px solid rgba(255,255,255,0.06)', marginBottom: 16 }}>
        <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(255,255,255,0.35)', marginBottom: 12 }}>URL Metadata</div>
        <table className="info-table">
          <tbody>
            <tr><td>Protocol</td><td style={{ color: meta.protocol === 'https:' ? '#34d399' : '#f87171', fontFamily: 'monospace', fontSize: 13 }}>{meta.protocol || 'N/A'}</td></tr>
            <tr><td>Domain</td><td style={{ color: '#a5b4fc', fontFamily: 'monospace', fontSize: 13 }}>{meta.domain || 'N/A'}</td></tr>
            <tr><td>Port</td><td style={{ color: 'rgba(255,255,255,0.7)', fontFamily: 'monospace', fontSize: 13 }}>{meta.port || 'N/A'}</td></tr>
            <tr><td>Path</td><td style={{ color: 'rgba(255,255,255,0.6)', fontFamily: 'monospace', fontSize: 13, wordBreak: 'break-all' }}>{meta.path || '/'}</td></tr>
            <tr><td>TLD</td><td style={{ color: meta.tld && ['.xyz', '.top', '.click', '.info', '.biz', '.online'].includes(meta.tld) ? '#f87171' : 'rgba(255,255,255,0.7)', fontFamily: 'monospace', fontSize: 13 }}>{meta.tld || 'N/A'}</td></tr>
            <tr><td>URL Length</td><td style={{ color: result.url.length > 75 ? '#fbbf24' : 'rgba(255,255,255,0.7)', fontSize: 13 }}>{result.url.length} characters</td></tr>
          </tbody>
        </table>
      </div>

      {/* Scan Info */}
      <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 12, padding: '14px 16px', border: '1px solid rgba(255,255,255,0.06)' }}>
        <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(255,255,255,0.35)', marginBottom: 12 }}>Scan Information</div>
        <table className="info-table">
          <tbody>
            <tr><td>Scanned At</td><td style={{ color: 'rgba(255,255,255,0.7)', fontSize: 13 }}>{ts.toLocaleString()}</td></tr>
            <tr><td>Scan Duration</td><td style={{ color: 'rgba(255,255,255,0.7)', fontFamily: 'monospace', fontSize: 13 }}>{result.scanDuration}ms</td></tr>
            <tr><td>Engines</td><td style={{ color: '#a5b4fc', fontSize: 13 }}>{result.engineSummary?.total || 16} engines</td></tr>
            <tr><td>Signatures</td><td style={{ color: '#a5b4fc', fontSize: 13 }}>10 vulnerability signatures</td></tr>
            <tr><td>Risk Score</td><td style={{ color: RESULT_CONFIG[result.label]?.accent, fontWeight: 700, fontSize: 13 }}>{result.score} / 100</td></tr>
            <tr><td>Verdict</td><td style={{ color: RESULT_CONFIG[result.label]?.accent, fontWeight: 700, fontSize: 13 }}>{result.label}</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Port Results Component ───────────────────────────────────
const PORT_RISK = {
  21: 'HIGH', 22: 'MEDIUM', 23: 'CRITICAL', 25: 'MEDIUM', 53: 'LOW',
  80: 'LOW', 110: 'LOW', 143: 'LOW', 443: 'LOW', 587: 'LOW',
  993: 'LOW', 995: 'LOW', 3306: 'HIGH', 3389: 'CRITICAL', 5432: 'HIGH',
  6379: 'HIGH', 8080: 'LOW', 8443: 'LOW', 27017: 'HIGH',
};
const PORT_RISK_NOTE = {
  21: 'FTP transfers credentials in plaintext', 23: 'Telnet is unencrypted — critical risk',
  3306: 'Exposed MySQL — severe security risk', 3389: 'Exposed RDP — common ransomware vector',
  5432: 'Exposed PostgreSQL — severe risk', 6379: 'Redis with no auth by default',
  27017: 'MongoDB often has no auth by default',
};
function PortResults({ allPorts, openPorts }) {
  const openCount = openPorts.length;
  return (
    <div>
      {/* Header stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 18 }}>
        {[
          { label: 'Ports Scanned', value: allPorts.length || 19, color: '#a5b4fc' },
          { label: 'Open Ports', value: openCount, color: openCount > 0 ? '#f87171' : '#34d399' },
          { label: 'Closed / Filtered', value: (allPorts.length || 19) - openCount, color: '#94a3b8' },
        ].map(s => (
          <div key={s.label} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 12, padding: '12px 14px', border: '1px solid rgba(255,255,255,0.06)', textAlign: 'center' }}>
            <div style={{ fontSize: 22, fontWeight: 800, color: s.color, marginBottom: 2 }}>{s.value}</div>
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{s.label}</div>
          </div>
        ))}
      </div>

      {openCount === 0 ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(16,185,129,0.1)', borderRadius: 12, padding: '14px 16px', border: '1px solid rgba(16,185,129,0.25)', marginBottom: 14 }}>
          <span style={{ fontSize: 20 }}>🔒</span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#34d399' }}>No open ports detected</div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)', marginTop: 2 }}>All scanned ports appear closed or filtered.</div>
          </div>
        </div>
      ) : (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(255,255,255,0.35)', marginBottom: 8 }}>⚠️ Open Ports Found</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {openPorts.map(p => {
              const sev = PORT_RISK[p.port] || 'LOW';
              const note = PORT_RISK_NOTE[p.port];
              const sevConfig = SEV_CONFIG[sev] || SEV_CONFIG.LOW;
              return (
                <div key={p.port} style={{ display: 'flex', alignItems: 'center', gap: 12, background: `${sevConfig.bg}`, borderRadius: 10, padding: '10px 14px', border: `1px solid ${sevConfig.border}` }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: sevConfig.dot, boxShadow: `0 0 6px ${sevConfig.dot}`, flexShrink: 0 }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, fontSize: 13, color: sevConfig.color }}>{p.port}</span>
                      <span style={{ fontSize: 12, color: '#f1f5f9', fontWeight: 600 }}>{p.service}</span>
                      <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)' }}>{p.description}</span>
                    </div>
                    {note && <div style={{ fontSize: 11, color: sevConfig.color, marginTop: 3, opacity: 0.85 }}>⚡ {note}</div>}
                  </div>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 99, background: `${sevConfig.color}20`, color: sevConfig.color, border: `1px solid ${sevConfig.color}40`, flexShrink: 0 }}>{sev}</span>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 99, background: 'rgba(16,185,129,0.2)', color: '#34d399', border: '1px solid rgba(16,185,129,0.4)', flexShrink: 0 }}>OPEN</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Full port table */}
      <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 12, border: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden' }}>
        <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(255,255,255,0.35)', padding: '10px 14px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          Full Port Scan Results
        </div>
        {allPorts.length === 0 ? (
          <div style={{ padding: '20px', textAlign: 'center', color: 'rgba(255,255,255,0.3)', fontSize: 13 }}>
            Scan in progress or no port data available.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                {['Port', 'Service', 'Description', 'Status'].map(h => (
                  <th key={h} style={{ padding: '8px 14px', textAlign: 'left', color: 'rgba(255,255,255,0.3)', fontWeight: 700, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {allPorts.map((p, i) => (
                <tr key={p.port} style={{ borderBottom: i < allPorts.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none', background: p.open ? 'rgba(239,68,68,0.05)' : 'transparent' }}>
                  <td style={{ padding: '7px 14px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, color: p.open ? (SEV_CONFIG[PORT_RISK[p.port] || 'LOW']?.color || '#34d399') : 'rgba(255,255,255,0.5)' }}>{p.port}</td>
                  <td style={{ padding: '7px 14px', color: 'rgba(255,255,255,0.7)', fontWeight: 600 }}>{p.service}</td>
                  <td style={{ padding: '7px 14px', color: 'rgba(255,255,255,0.4)' }}>{p.description}</td>
                  <td style={{ padding: '7px 14px' }}>
                    <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 99, background: p.open ? 'rgba(16,185,129,0.2)' : 'rgba(255,255,255,0.07)', color: p.open ? '#34d399' : 'rgba(255,255,255,0.35)', border: p.open ? '1px solid rgba(16,185,129,0.4)' : '1px solid rgba(255,255,255,0.1)' }}>
                      {p.open ? 'OPEN' : 'CLOSED'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─── Result Tabs Component ────────────────────────────────────
function ResultView({ result, onRescan }) {
  const [tab, setTab] = useState('summary');
  const rc = RESULT_CONFIG[result.label];
  const vulns = result.vulnerabilities || [];

  return (
    <div className="glass scale-in" style={{ borderRadius: 20, border: `1px solid ${rc.border}`, background: `linear-gradient(180deg, ${rc.gradient} 0%, rgba(0,0,0,0) 100%)`, overflow: 'hidden' }}>

      {/* ── Result Banner ── */}
      <div style={{ padding: '24px 24px 0' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 20, flexWrap: 'wrap' }}>

          {/* Score Ring */}
          <div style={{ flexShrink: 0 }}>
            <ScoreRing score={result.score} label={result.label} accent={rc.accent} />
          </div>

          {/* Verdict Info */}
          <div style={{ flex: 1, minWidth: 200, paddingTop: 8 }}>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
              <span className="badge" style={{ background: `${rc.accent}20`, color: rc.accent, border: `1px solid ${rc.accent}40` }}>
                {result.label === 'SAFE' ? '✅' : result.label === 'SUSPICIOUS' ? '⚠️' : '🚨'} {result.label}
              </span>
              {vulns.length > 0 && (
                <span className="badge" style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.3)' }}>
                  {vulns.length} Vulnerability{vulns.length > 1 ? 'ies' : ''} Found
                </span>
              )}
              {result.engineSummary && (
                <span className="badge" style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
                  {result.engineSummary.detected}/{result.engineSummary.total} Engines Flagged
                </span>
              )}
            </div>

            <h2 style={{ fontSize: 18, fontWeight: 700, color: rc.accent, marginBottom: 6, lineHeight: 1.3 }}>
              {result.message}
            </h2>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'rgba(255,255,255,0.4)' }}>
              <Icon.Clock />
              <span>Scanned {new Date(result.scanTimestamp).toLocaleTimeString()}</span>
              <span style={{ margin: '0 4px' }}>·</span>
              <span>{result.scanDuration}ms</span>
              <button onClick={onRescan} style={{ marginLeft: 8, display: 'flex', alignItems: 'center', gap: 5, background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 7, padding: '4px 8px', color: 'rgba(255,255,255,0.5)', cursor: 'pointer', fontSize: 11, fontFamily: 'Inter, sans-serif' }}>
                <Icon.Refresh /> Rescan
              </button>
            </div>
          </div>
        </div>

        {/* Threat Level Bar */}
        <div style={{ marginTop: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'rgba(255,255,255,0.35)', marginBottom: 6 }}>
            <span style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Threat Level</span>
            <span style={{ fontWeight: 700, color: rc.accent }}>{result.score}%</span>
          </div>
          <div className="threat-bar-track">
            <div className="threat-bar-fill bar-fill" style={{ width: `${Math.max(result.score, 2)}%`, background: `linear-gradient(90deg, ${rc.accent}cc, ${rc.accent})` }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'rgba(255,255,255,0.2)', marginTop: 4 }}>
            <span>Safe · 0%</span><span>Suspicious · 20%</span><span>Phishing · 40%+</span>
          </div>
        </div>

        {/* Tabs */}
        <div style={{ marginTop: 20 }} className="tab-bar">
          {[
            ['summary', '📊 Summary'],
            ['vulns', `🐛 Vulnerabilities (${vulns.length})`],
            ['engines', `⚙️ Engines (${result.engineSummary?.total || 0})`],
            ['ports', `🔌 Ports (${(result.openPorts || []).length} open)`],
            ['details', '🔍 URL Details'],
          ].map(([id, label]) => (
            <button key={id} className={`tab-btn ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Tab Content ── */}
      <div style={{ padding: '20px 24px 24px' }}>

        {/* SUMMARY TAB */}
        {tab === 'summary' && (
          <div className="fade-in">
            {/* High-level stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 16 }}>
              {[
                { label: 'Risk Score', value: `${result.score}%`, color: rc.accent },
                { label: 'Vulns Found', value: vulns.length, color: vulns.length > 0 ? '#f87171' : '#34d399' },
                { label: 'Engines Flagged', value: `${result.engineSummary?.detected || 0}/${result.engineSummary?.total || 0}`, color: '#a5b4fc' },
              ].map(s => (
                <div key={s.label} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 12, padding: '12px 14px', border: '1px solid rgba(255,255,255,0.06)', textAlign: 'center' }}>
                  <div style={{ fontSize: 20, fontWeight: 800, color: s.color, marginBottom: 2 }}>{s.value}</div>
                  <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{s.label}</div>
                </div>
              ))}
            </div>

            {/* Reasons list */}
            {vulns.length > 0 ? (
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(255,255,255,0.35)', marginBottom: 10 }}>Detected Threats</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {vulns.map((v, i) => {
                    const sev = SEV_CONFIG[v.severity] || SEV_CONFIG.LOW;
                    return (
                      <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, background: 'rgba(0,0,0,0.25)', borderRadius: 10, padding: '10px 12px', border: '1px solid rgba(255,255,255,0.05)' }} className="fade-in">
                        <div style={{ width: 8, height: 8, borderRadius: '50%', background: sev.dot, flexShrink: 0, marginTop: 4, boxShadow: `0 0 6px ${sev.dot}` }} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 13, color: '#f1f5f9', fontWeight: 500 }}>{v.name}</div>
                          <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginTop: 2 }}>{v.type} · {v.cweId} · CVSS {v.cvss}</div>
                        </div>
                        <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 99, background: `${sev.color}20`, color: sev.color, border: `1px solid ${sev.color}40`, flexShrink: 0 }}>{v.severity}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(16,185,129,0.1)', borderRadius: 12, padding: '14px 16px', border: '1px solid rgba(16,185,129,0.25)' }}>
                <span style={{ color: '#34d399', fontSize: 20 }}>✅</span>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#34d399' }}>No threats detected</div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)', marginTop: 2 }}>All security checks passed. This URL appears safe.</div>
                </div>
              </div>
            )}

            {/* Severity Distribution */}
            {vulns.length > 0 && (() => {
              const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
              vulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
              return (
                <div style={{ marginTop: 16, background: 'rgba(0,0,0,0.25)', borderRadius: 12, padding: '14px 16px', border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'rgba(255,255,255,0.35)', marginBottom: 10 }}>Severity Breakdown</div>
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    {Object.entries(counts).map(([sev, cnt]) => cnt > 0 && (
                      <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                        <div style={{ width: 8, height: 8, borderRadius: '50%', background: SEV_CONFIG[sev]?.dot }} />
                        <span style={{ color: SEV_CONFIG[sev]?.color, fontWeight: 600 }}>{cnt} {sev}</span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* VULNERABILITIES TAB */}
        {tab === 'vulns' && (
          <div className="fade-in">
            {vulns.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '32px 0', color: 'rgba(255,255,255,0.3)' }}>
                <div style={{ fontSize: 32, marginBottom: 10 }}>🛡️</div>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#34d399' }}>No vulnerabilities detected</div>
                <div style={{ fontSize: 12, marginTop: 4 }}>This URL passed all security checks</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {vulns.map((v, i) => <VulnerabilityCard key={i} vuln={v} index={i} />)}
              </div>
            )}
          </div>
        )}

        {/* ENGINES TAB */}
        {tab === 'engines' && result.engines && (
          <div className="fade-in">
            <EngineResults engines={result.engines} summary={result.engineSummary} />
          </div>
        )}

        {/* DETAILS TAB */}
        {tab === 'details' && (
          <div className="fade-in">
            <URLDetails result={result} />
          </div>
        )}

        {/* PORTS TAB */}
        {tab === 'ports' && (
          <div className="fade-in">
            <PortResults allPorts={result.allPorts || []} openPorts={result.openPorts || []} />
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Login Page ───────────────────────────────────────────────
function LoginPage({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [shake, setShake] = useState(false);

  async function handleLogin(e) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setLoading(true); setError('');
    try {
      const res = await fetch('/api/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        onLoginSuccess(username.trim());
      } else {
        setError(data.error || 'Invalid credentials.'); setShake(true);
        setTimeout(() => setShake(false), 600);
      }
    } catch {
      setError('Cannot reach backend server. Make sure it is running.'); setShake(true);
      setTimeout(() => setShake(false), 600);
    } finally { setLoading(false); }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', overflow: 'hidden' }}>
      <div className="bg-nebula" />
      <div className="grid-overlay" />
      <div className="login-orb-1" />
      <div className="login-orb-2" />

      <div style={{ position: 'relative', zIndex: 10, width: '100%', maxWidth: 380, padding: '0 20px' }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 32 }} className="fade-up">
          <div style={{
            width: 72, height: 72, borderRadius: 22, margin: '0 auto 16px',
            background: 'linear-gradient(135deg, rgba(99,102,241,0.25), rgba(139,92,246,0.25))',
            border: '1px solid rgba(99,102,241,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 40px rgba(99,102,241,0.3)', color: '#a5b4fc'
          }} className="float-anim">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" style={{ width: 32, height: 32 }}>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1 style={{ fontSize: 30, fontWeight: 900, background: 'linear-gradient(135deg, #a5b4fc, #c4b5fd, #67e8f9)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', letterSpacing: '-0.02em', marginBottom: 6 }}>
            PhishGuard AI
          </h1>
          <p style={{ color: 'rgba(255,255,255,0.3)', fontSize: 13 }}>Advanced Phishing Detection System</p>
          <p style={{ color: 'rgba(255,255,255,0.2)', fontSize: 12, marginTop: 4 }}>Sign in to access the security console</p>
        </div>

        {/* Login Card */}
        <div className={`glass ${shake ? 'shake' : ''} fade-up`} style={{ borderRadius: 22, padding: '28px 26px', boxShadow: error ? '0 0 0 1px rgba(239,68,68,0.3), 0 30px 80px rgba(0,0,0,0.6)' : '0 30px 80px rgba(0,0,0,0.6)', animationDelay: '0.1s' }}>
          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* Username */}
            <div>
              <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Username</label>
              <div style={{ position: 'relative' }}>
                <span style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.3)' }}><Icon.User /></span>
                <input
                  id="login-username" type="text" value={username} onChange={e => setUsername(e.target.value)}
                  placeholder="Enter username" autoComplete="username"
                  className="input-field" style={{ padding: '12px 14px 12px 40px' }}
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label style={{ display: 'block', fontSize: 11, fontWeight: 700, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Password</label>
              <div style={{ position: 'relative' }}>
                <span style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.3)' }}><Icon.Lock /></span>
                <input
                  id="login-password" type={showPass ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)}
                  placeholder="Enter password" autoComplete="current-password"
                  className="input-field" style={{ padding: '12px 44px 12px 40px' }}
                />
                <button type="button" onClick={() => setShowPass(v => !v)}
                  style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'rgba(255,255,255,0.3)', cursor: 'pointer', padding: 0, display: 'flex' }}>
                  {showPass ? <Icon.EyeOff /> : <Icon.Eye />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="fade-in" style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 10, padding: '10px 14px', fontSize: 12, color: '#fca5a5', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon.Danger /> {error}
              </div>
            )}

            {/* Submit */}
            <button
              id="login-submit" type="submit"
              disabled={loading || !username.trim() || !password}
              className="btn-primary"
              style={{ padding: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
            >
              {loading ? <><Spinner size={16} color="white" /> Signing in…</> : <><Icon.Lock /> Sign In</>}
            </button>
          </form>

        </div>

        <p style={{ textAlign: 'center', fontSize: 11, color: 'rgba(255,255,255,0.15)', marginTop: 20 }}>
          PhishGuard AI · 16 Detection Engines · Real-time Analysis
        </p>
      </div>
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────
function Dashboard({ username, onLogout }) {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);
  const [serverOnline, setServerOnline] = useState(null);
  const resultRef = useRef(null);

  // Check backend health on mount
  useEffect(() => {
    fetch('/api/health')
      .then(r => r.json())
      .then(() => setServerOnline(true))
      .catch(() => setServerOnline(false));
  }, []);

  async function checkUrl(targetUrl) {
    const scanUrl = targetUrl || url;
    if (!scanUrl.trim()) return;
    setLoading(true); setError(''); setResult(null);
    try {
      const res = await fetch('/api/check', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setResult(data);
      setHistory(prev => [{ url: scanUrl.trim(), label: data.label, score: data.score }, ...prev].slice(0, 8));
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
    } catch {
      setError('Cannot reach backend server. Make sure it is running on port 5000.');
    } finally { setLoading(false); }
  }

  function handleSample(sampleUrl) { setUrl(sampleUrl); }
  function handleRescan() { checkUrl(result?.url); }

  const historyColors = { SAFE: '#10b981', SUSPICIOUS: '#f59e0b', PHISHING: '#ef4444' };

  return (
    <div style={{ minHeight: '100vh', position: 'relative', overflow: 'hidden' }}>
      <div className="bg-nebula" />
      <div className="grid-overlay" />

      <div style={{ position: 'relative', zIndex: 10, maxWidth: 800, margin: '0 auto', padding: '0 16px 80px' }}>

        {/* ── NAV BAR ── */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '20px 0 0' }}>
          {/* Logo */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 10, background: 'rgba(99,102,241,0.2)', border: '1px solid rgba(99,102,241,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#a5b4fc' }}>
              <Icon.Shield />
            </div>
            <span style={{ fontSize: 16, fontWeight: 700, color: '#f1f5f9' }}>PhishGuard AI</span>
          </div>

          {/* Status + User */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'rgba(255,255,255,0.4)', background: 'rgba(0,0,0,0.3)', borderRadius: 99, padding: '5px 12px', border: '1px solid rgba(255,255,255,0.07)' }}>
              <span className="pulse-dot" style={{ width: 7, height: 7, borderRadius: '50%', background: serverOnline === false ? '#ef4444' : '#10b981', display: 'inline-block' }} />
              {serverOnline === false ? 'Offline' : 'Online'}
            </div>
            <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)' }}>{username}</span>
            <button id="logout-btn" onClick={onLogout} className="btn-ghost" style={{ padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon.Logout /> Logout
            </button>
          </div>
        </div>

        {/* ── HERO HEADING ── */}
        <div style={{ textAlign: 'center', padding: '40px 0 28px' }} className="fade-up">
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.25)', borderRadius: 99, padding: '5px 14px', fontSize: 12, color: '#a5b4fc', marginBottom: 18 }}>
            <span className="pulse-dot" style={{ width: 6, height: 6, borderRadius: '50%', background: '#6366f1', display: 'inline-block' }} />
            AI-Powered · 16 Engines · Real-time Detection
          </div>
          <h1 style={{ fontSize: 'clamp(28px, 5vw, 44px)', fontWeight: 900, background: 'linear-gradient(135deg, #a5b4fc 0%, #c4b5fd 50%, #67e8f9 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', letterSpacing: '-0.03em', lineHeight: 1.15, marginBottom: 14 }}>
            Phishing Website<br />Detection System
          </h1>
          <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.4)', maxWidth: 500, margin: '0 auto', lineHeight: 1.6 }}>
            Scan any URL for phishing threats. Get detailed vulnerability reports, CVE intelligence, and multi-engine analysis.
          </p>
        </div>

        {/* ── QUICK TEST SAMPLES ── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 16 }} className="fade-up" style2={{ animationDelay: '0.1s' }}>
          {SAMPLES.map(s => (
            <button
              key={s.url}
              onClick={() => handleSample(s.url)}
              style={{
                background: 'rgba(0,0,0,0.3)', border: `1px solid ${s.color}25`, borderRadius: 12,
                padding: '12px 10px', cursor: 'pointer', transition: 'all 0.2s', textAlign: 'center',
                fontFamily: 'Inter, sans-serif'
              }}
              onMouseEnter={e => { e.currentTarget.style.background = `${s.color}12`; e.currentTarget.style.borderColor = `${s.color}50`; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'rgba(0,0,0,0.3)'; e.currentTarget.style.borderColor = `${s.color}25`; }}
            >
              <div style={{ fontSize: 20, marginBottom: 4 }}>{s.emoji}</div>
              <div style={{ fontSize: 12, fontWeight: 600, color: s.color, marginBottom: 2 }}>{s.label}</div>
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)' }}>{s.hint}</div>
            </button>
          ))}
        </div>

        {/* ── SCAN INPUT CARD ── */}
        <div className="glass fade-up" style={{ borderRadius: 20, padding: '24px', marginBottom: 20, animationDelay: '0.15s' }}>
          <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'rgba(255,255,255,0.3)', marginBottom: 14 }}>
            🔍 Enter URL to Analyze
          </div>
          <form onSubmit={e => { e.preventDefault(); checkUrl(); }} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ position: 'relative' }}>
              <span style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.25)' }}><Icon.Globe /></span>
              <input
                id="url-input" type="text" value={url} onChange={e => setUrl(e.target.value)}
                placeholder="https://example.com — paste any URL to analyze"
                className="input-field" style={{ padding: '14px 14px 14px 42px', fontSize: 14 }}
              />
            </div>
            <button id="analyze-btn" type="submit" disabled={loading || !url.trim()} className="btn-primary" style={{ padding: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
              {loading ? <><Spinner size={17} color="white" /> Running Analysis…</> : <><Icon.Search /> Analyze URL</>}
            </button>
          </form>

          {error && (
            <div className="fade-in" style={{ marginTop: 12, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: 10, padding: '10px 14px', fontSize: 12, color: '#fca5a5', display: 'flex', gap: 8, alignItems: 'center' }}>
              <Icon.Danger /> {error}
            </div>
          )}
        </div>

        {/* ── SCANNING ANIMATION ── */}
        {loading && (
          <div className="glass fade-in" style={{ borderRadius: 20, padding: '20px 24px', marginBottom: 20 }}>
            <ScanLoadingGrid />
          </div>
        )}

        {/* ── RESULT VIEW ── */}
        {result && !loading && (
          <div ref={resultRef} style={{ marginBottom: 20 }}>
            <ResultView result={result} onRescan={handleRescan} />
          </div>
        )}

        {/* ── SCAN HISTORY ── */}
        {history.length > 0 && (
          <div className="glass fade-up" style={{ borderRadius: 20, padding: '20px 24px', marginBottom: 20 }}>
            <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'rgba(255,255,255,0.3)', marginBottom: 14 }}>
              🕐 Recent Scans
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {history.map((h, i) => (
                <div
                  key={i}
                  onClick={() => { setUrl(h.url); checkUrl(h.url); }}
                  style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 12px', borderRadius: 10, cursor: 'pointer', transition: 'background 0.15s' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.04)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: historyColors[h.label], flexShrink: 0, boxShadow: `0 0 6px ${historyColors[h.label]}` }} />
                  <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'JetBrains Mono, monospace' }}>{h.url}</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: historyColors[h.label], flexShrink: 0 }}>{h.score}% · {h.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── HOW IT WORKS ── */}
        <div className="glass" style={{ borderRadius: 20, padding: '20px 24px' }}>
          <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'rgba(255,255,255,0.3)', marginBottom: 16 }}>⚙️ Detection Pipeline</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10 }}>
            {[
              { icon: '🌐', title: 'URL Parsing', desc: 'Protocol, domain, path, TLD analysis' },
              { icon: '🧠', title: 'AI Heuristics', desc: '10 vulnerability signatures checked' },
              { icon: '⚙️', title: '16 Engines', desc: 'Multi-vendor threat intelligence' },
              { icon: '🔬', title: 'CVE Mapping', desc: 'CWE/MITRE ATT&CK correlation' },
              { icon: '📊', title: 'Risk Score', desc: 'CVSS-based 0-100 threat scoring' },
            ].map(item => (
              <div key={item.title} style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 12, padding: '12px', border: '1px solid rgba(255,255,255,0.05)', textAlign: 'center' }}>
                <div style={{ fontSize: 22, marginBottom: 6 }}>{item.icon}</div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,0.7)', marginBottom: 4 }}>{item.title}</div>
                <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', lineHeight: 1.5 }}>{item.desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <p style={{ textAlign: 'center', fontSize: 11, color: 'rgba(255,255,255,0.12)', marginTop: 24 }}>
          PhishGuard AI · Built with React + Node.js · Advanced Threat Intelligence · {new Date().getFullYear()}
        </p>
      </div>
    </div>
  );
}

// ─── Root App ─────────────────────────────────────────────────
export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loggedInUser, setLoggedInUser] = useState('');

  return isLoggedIn
    ? <Dashboard username={loggedInUser} onLogout={() => { setIsLoggedIn(false); setLoggedInUser(''); }} />
    : <LoginPage onLoginSuccess={u => { setLoggedInUser(u); setIsLoggedIn(true); }} />;
}
