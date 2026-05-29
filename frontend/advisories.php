<?php
/**
 * GRID — Advisories Feed
 * Uses server-side pagination: on page-load the total advisory count is fetched
 * from /API/status. Pages are calculated from that total and the chosen page
 * size. Each page change fires a single API request for only that page's data.
 *
 * Stylesheet: GRID/frontend/style/advisories.css
 */

// ─── Status call for header stats only (fast, single request) ─────────────────
define('API_BASE', 'http://localhost:8000');
define('API_TIMEOUT', 6);

function fetch_api(string $url): ?array {
    $ctx = stream_context_create(['http' => ['timeout' => API_TIMEOUT, 'ignore_errors' => true]]);
    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false) return null;
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) return null;
    return $decoded;
}

$status = fetch_api(API_BASE . '/API/status');
$generated_at_iso = (new DateTime('now', new DateTimeZone('UTC')))->format('c');
?>
<!DOCTYPE html>
<html lang="de" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GRID — Security Advisories</title>
    <meta name="description" content="GRID Security Advisories — Browse the latest vulnerability advisories sorted by modification date.">
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 -960 960 960' fill='%23e3e3e3'><path d='M323-160q-11 0-20.5-5.5T288-181l-78-139h58l40 80h92v-40h-68l-40-80H188l-57-100q-2-5-3.5-10t-1.5-10q0-4 5-20l57-100h104l40-80h68v-40h-92l-40 80h-58l78-139q5-10 14.5-15.5T323-800h97q17 0 28.5 11.5T460-760v160h-60l-40 40h100v120h-88l-40-80h-92l-40 40h108l40 80h112v200q0 17-11.5 28.5T420-160h-97Zm180.5-23.5Q480-207 480-240q0-23 11-40.5t29-28.5v-342q-18-11-29-28.5T480-720q0-33 23.5-56.5T560-800q33 0 56.5 23.5T640-720q0 23-11 40.5T600-651v101l80-48q0-34 23.5-58t56.5-24q33 0 56.5 23.5T840-600q0 33-23.5 56.5T760-520q-11 0-20.5-2.5T721-530l-91 55 101 80q7-3 14-4t15-1q33 0 56.5 23.5T840-320q0 33-23.5 56.5T760-240q-37 0-60.5-28T681-332l-81-65v89q18 11 28.5 28.5T639-240q0 33-23 56.5T560-160q-33 0-56.5-23.5Z'/></svg>" />

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">

    <link rel="stylesheet" href="style/advisories.css">
    <style>
        /* ── Skeleton shimmer rows ── */
        .skeleton-row td {
            padding: 14px;
        }
        .skeleton-cell {
            height: 14px;
            border-radius: 4px;
            background: linear-gradient(90deg, var(--bg-card-alt) 25%, var(--border) 50%, var(--bg-card-alt) 75%);
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
        }
        @keyframes shimmer {
            0%   { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }
    </style>
</head>
<body>

<div class="app" id="app">

  <!-- ═══════════════════════════════ SIDEBAR ═══════════════════════════════ -->
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-logo">
      <div class="logo-mark" style="display:flex;align-items:center;gap:.55rem;">
        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 -960 960 960" fill="currentColor" style="opacity:.9;flex-shrink:0;"><path d="M323-160q-11 0-20.5-5.5T288-181l-78-139h58l40 80h92v-40h-68l-40-80H188l-57-100q-2-5-3.5-10t-1.5-10q0-4 5-20l57-100h104l40-80h68v-40h-92l-40 80h-58l78-139q5-10 14.5-15.5T323-800h97q17 0 28.5 11.5T460-760v160h-60l-40 40h100v120h-88l-40-80h-92l-40 40h108l40 80h112v200q0 17-11.5 28.5T420-160h-97Zm180.5-23.5Q480-207 480-240q0-23 11-40.5t29-28.5v-342q-18-11-29-28.5T480-720q0-33 23.5-56.5T560-800q33 0 56.5 23.5T640-720q0 23-11 40.5T600-651v101l80-48q0-34 23.5-58t56.5-24q33 0 56.5 23.5T840-600q0 33-23.5 56.5T760-520q-11 0-20.5-2.5T721-530l-91 55 101 80q7-3 14-4t15-1q33 0 56.5 23.5T840-320q0 33-23.5 56.5T760-240q-37 0-60.5-28T681-332l-81-65v89q18 11 28.5 28.5T639-240q0 33-23 56.5T560-160q-33 0-56.5-23.5Z"/></svg>
        <span class="logo-rid" style="font-size:1.35rem;font-weight:800;letter-spacing:.04em;">GRID</span>
      </div>
      <span class="logo-sub">Global Risk Intelligence</span>
    </div>

    <nav class="sidebar-nav">

      <div class="nav-section">
        <span class="nav-label">Menu</span>
        <a href="index.html" class="nav-item" data-page="dashboard">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
          <span>Dashboard</span>
        </a>
        <a href="#" class="nav-item" data-page="news">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 4h16v2H4z"/><path d="M4 9h10v2H4z"/><path d="M4 14h7v2H4z"/><rect x="13" y="10" width="7" height="9" rx="1"/></svg>
          <span>News</span>
          <span class="nav-badge">12</span>
        </a>
      </div>

      <div class="nav-section">
        <span class="nav-label">Vulnerabilities</span>
        <a href="advisories.php" class="nav-item active" data-page="vuln-all">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 8v5"/><circle cx="12" cy="16.5" r=".5" fill="currentColor"/></svg>
          <span>Alle</span>
          <span class="nav-count" id="navTotalCount"></span>
        </a>
        <a href="#" class="nav-item nav-item--danger" data-page="vuln-high">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v5"/><circle cx="12" cy="17.5" r=".5" fill="currentColor"/></svg>
          <span>High Priority</span>
        </a>
      </div>

      <div class="nav-section">
        <span class="nav-label">Products</span>
        <a href="#" class="nav-item" data-page="prod-all">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>
          <span>Alle</span>
        </a>
        <a href="#" class="nav-item" data-page="prod-stats">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          <span>Statistik</span>
        </a>
      </div>

      <div class="nav-section">
        <span class="nav-label">Vendors</span>
        <a href="#" class="nav-item" data-page="vendor-all">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
          <span>Alle</span>
        </a>
        <a href="#" class="nav-item" data-page="vendor-stats">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
          <span>Statistik</span>
        </a>
      </div>

    </nav>

    <div class="sidebar-footer">
      <a href="#" class="nav-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        <span>Documentation</span>
      </a>
      <a href="https://github.com/jonasfessler/GRID" target="_blank" class="nav-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 00-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0020 4.77 5.07 5.07 0 0019.91 1S18.73.65 16 2.48a13.38 13.38 0 00-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 005 4.77a5.44 5.44 0 00-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 009 18.13V22"/></svg>
        <span>GitHub</span>
      </a>
    </div>
  </aside>

  <!-- ═══════════════════════════════ MAIN ═══════════════════════════════════ -->
  <div class="main-wrapper">

    <!-- TOP BAR -->
    <header class="topbar">
      <div class="topbar-left">
        <button class="btn-icon" id="sidebarToggle" aria-label="Toggle sidebar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
        </button>
        <div class="search-wrap">
          <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" class="search-input" id="searchInput" placeholder="Advisories, CVEs, Vendors suchen…" />
          <span class="search-shortcut">⌘K</span>
        </div>
      </div>
      <div class="topbar-right">
        <?php if ($status): ?>
        <div class="topbar-stats">
          <div class="tstat">
            <span class="tstat-val"><?= number_format((int)($status['advisory_count'] ?? 0)) ?></span>
            <span class="tstat-lbl">Advisories</span>
          </div>
          <div class="tstat-divider"></div>
          <div class="tstat">
            <span class="tstat-val"><?= number_format((int)($status['product_count'] ?? 0)) ?></span>
            <span class="tstat-lbl">Produkte</span>
          </div>
          <div class="tstat-divider"></div>
          <div class="tstat">
            <span class="tstat-val"><?= number_format((int)($status['vendor_count'] ?? 0)) ?></span>
            <span class="tstat-lbl">Vendors</span>
          </div>
        </div>
        <?php endif; ?>
        <button class="btn-icon" id="themeToggle" aria-label="Toggle theme">
          <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
          <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
        </button>
      </div>
    </header>

    <!-- PAGE BODY -->
    <div class="page-body">

      <div class="section-header" style="flex-wrap:wrap;gap:.6rem 1.5rem;align-items:center;">
        <h1 class="section-title" style="margin:0;">Security Advisories</h1>
        <div style="display:flex;flex-direction:column;gap:.35rem;margin-left:auto;align-items:flex-end;">
          <span class="section-meta">
            <span id="pageInfoMeta">…</span>
            &nbsp;·&nbsp;
            <span id="totalCountMeta">…</span> gesamt
            &nbsp;·&nbsp;
            Generiert: <span data-fmt-datetime="<?= htmlspecialchars($generated_at_iso) ?>">…</span>
          </span>
          <div style="display:flex;align-items:center;gap:.5rem;font-size:12px;color:var(--text-muted);">
            <label for="pageSizeSelect" style="white-space:nowrap;">Pro Seite:</label>
            <select id="pageSizeSelect" style="background:var(--bg-card,#151e2d);color:var(--text-primary,#e1e1e1);border:1px solid var(--border,rgba(255,255,255,.1));border-radius:6px;padding:.25rem .5rem;font-size:12px;cursor:pointer;">
              <option value="10">10</option>
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100" selected>100</option>
            </select>
          </div>
        </div>
      </div>

      <div id="errorBanner" class="error-banner" style="display:none;"></div>

      <div class="table-card">
        <div class="table-scroll">
          <table class="adv-table">
            <colgroup>
              <col class="col-num">
              <col class="col-id">
              <col class="col-title">
              <col class="col-cves">
              <col class="col-cvss">
              <col class="col-src">
              <col class="col-mod">
              <col class="col-rem">
            </colgroup>
            <thead>
              <tr>
                <th class="col-num">#</th>
                <th class="col-id">Advisory-ID</th>
                <th class="col-title">Titel</th>
                <th class="col-cves">CVEs</th>
                <th class="col-cvss">CVSS</th>
                <th class="col-src">Quelle</th>
                <th class="col-mod">Aktualisiert</th>
                <th class="col-rem">Remediation</th>
              </tr>
            </thead>
            <tbody id="advisoryTableBody">
              <!-- Skeleton rows shown while loading -->
              <tr class="skeleton-row" id="skeletonRows">
                <td><div class="skeleton-cell" style="width:20px;margin:auto;"></div></td>
                <td><div class="skeleton-cell" style="width:140px;"></div></td>
                <td>
                  <div class="skeleton-cell" style="width:85%;margin-bottom:6px;"></div>
                  <div class="skeleton-cell" style="width:60%;height:10px;"></div>
                </td>
                <td><div class="skeleton-cell" style="width:100px;"></div></td>
                <td><div class="skeleton-cell" style="width:50px;margin:auto;"></div></td>
                <td><div class="skeleton-cell" style="width:45px;"></div></td>
                <td>
                  <div class="skeleton-cell" style="width:80px;margin-bottom:4px;"></div>
                  <div class="skeleton-cell" style="width:55px;height:10px;"></div>
                </td>
                <td><div class="skeleton-cell" style="width:90px;"></div></td>
              </tr>
            </tbody>
          </table>
        </div>
        </div>
      </div>

      <div id="pagination" style="display:flex;align-items:center;justify-content:center;gap:.35rem;padding:1.25rem 2rem .5rem;flex-wrap:wrap;"></div>

      <footer class="page-footer">
        <span>GRID — Global Risk Intelligence Dashboard</span>
        <span>
          Sortierung: <code>timeline.modified_at</code> ↓ &nbsp;·&nbsp; Gruppiert nach Advisory-ID (server-seitig)
          &nbsp;·&nbsp; Seite <span id="footerPage">1</span> / <span id="footerPages">…</span>
        </span>
      </footer>

    </div><!-- /page-body -->
  </div><!-- /main-wrapper -->
</div><!-- /app -->

<script>
/* ════════════════════════════════════════════════════════════════════
   GRID — Advisories: Server-Side Pagination
   ════════════════════════════════════════════════════════════════════ */

const PROXY   = 'api-proxy.php';   // same-origin PHP proxy → localhost:8000
const SORT_BY = '-timeline.modified_at';

/* ── State ── */
let curPage    = 1;
let pageSize   = 100;
let totalRows  = 0;   // total advisories matching current search (from API)
let totalPages = 0;
let loading    = false;
let searchTimer = null;  // debounce timer for search input

/* ── DOM refs ── */
const tbody       = document.getElementById('advisoryTableBody');
const pagerEl     = document.getElementById('pagination');
const pageSel     = document.getElementById('pageSizeSelect');
const searchEl    = document.getElementById('searchInput');
const pageInfoEl  = document.getElementById('pageInfoMeta');
const totalMeta   = document.getElementById('totalCountMeta');
const navCount    = document.getElementById('navTotalCount');
const footerPage  = document.getElementById('footerPage');
const footerPages = document.getElementById('footerPages');
const errorBanner = document.getElementById('errorBanner');
const skeleton    = document.getElementById('skeletonRows');

/* ════════════════════════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════════════════════════ */
const _dateFmt = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: '2-digit', year: 'numeric' });
const _dtFmt   = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });

function fmtDate(iso) {
    if (!iso) return '—';
    try { return _dateFmt.format(new Date(iso)); } catch(e) { return iso; }
}
function fmtDatetime(iso) {
    if (!iso) return '—';
    try { return _dtFmt.format(new Date(iso)); } catch(e) { return iso; }
}
function ago(iso) {
    if (!iso) return '';
    try {
        const d = new Date(iso), now = new Date();
        const dL   = new Date(d.getFullYear(),   d.getMonth(),   d.getDate());
        const nowL = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const days = Math.round((nowL - dL) / 86400000);
        if (days === 0)  return 'Heute';
        if (days === 1)  return 'Gestern';
        if (days < 7)   return `vor ${days} Tagen`;
        if (days < 30)  return 'vor ' + Math.floor(days / 7)  + ' Wochen';
        if (days < 365) return 'vor ' + Math.floor(days / 30) + ' Monaten';
        return 'vor ' + Math.floor(days / 365) + ' Jahren';
    } catch(e) { return ''; }
}
function cvssClass(s) {
    if (s == null) return 'sev-default';
    if (s >= 9.0)  return 'sev-critical';
    if (s >= 7.0)  return 'sev-high';
    if (s >= 4.0)  return 'sev-medium';
    return 'sev-low';
}
function cvssLabel(s) {
    if (s == null) return 'N/A';
    if (s >= 9.0)  return 'CRITICAL';
    if (s >= 7.0)  return 'HIGH';
    if (s >= 4.0)  return 'MEDIUM';
    return 'LOW';
}
function remClass(status) {
    const s = (status || '').toLowerCase();
    if (s.includes('patch') || s.includes('fix') || s.includes('update')) return 'rem-patch';
    if (s.includes('workaround'))                                           return 'rem-workaround';
    if (s.includes('none') || s.includes('kein'))                          return 'rem-none';
    return 'rem-unknown';
}
function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

/* ════════════════════════════════════════════════════════════════════
   MAP API GROUPS — transform pre-grouped API response to row format
   The API now returns advisory groups (grouped by WID/EUVD/CVE-ID
   server-side), so no client-side grouping is needed.
   ════════════════════════════════════════════════════════════════════ */
function mapApiGroups(items) {
    return items.map(item => ({
        key:          item.advisory_key ?? '',
        title:        item.title ?? '(Kein Titel)',
        cves:         item.cves ?? [],
        lead:         item,  // the item itself carries lead fields (metrics, remediation, etc.)
        modified_at:  item?.timeline?.modified_at  ?? '',
        published_at: item?.timeline?.published_at ?? '',
        sources:      item?.metadata?.sources ?? [],
    }));
}

/* ════════════════════════════════════════════════════════════════════
   ROW BUILDER
   ════════════════════════════════════════════════════════════════════ */
function buildRow(grp, rowNum) {
    const lead    = grp.lead;
    const score   = lead?.metrics?.cvss_v3?.base_score ?? null;
    const sev     = cvssClass(score);
    const cves    = grp.cves;
    const extra   = cves.length - 2;
    const rem     = lead?.remediation?.status ?? '';
    const sources = grp.sources ?? [];
    const wid     = lead?.metadata?.raw_source_ids?.cert_bund ?? null;
    const euvd    = lead?.metadata?.raw_source_ids?.euvd      ?? null;
    const rowId   = 'row-' + rowNum;

    let idCell = '';
    if (wid)       idCell = `<span class="adv-id-label">WID</span><span class="adv-id">${esc(wid)}</span>`;
    else if (euvd) idCell = `<span class="adv-id-label">EUVD</span><span class="adv-id">${esc(euvd)}</span>`;
    else           idCell = `<span class="adv-id-label">CVE</span><span class="adv-id">${esc(cves[0] ?? '—')}</span>`;

    let cveTags = cves.slice(0, 2).map(c => `<span class="cve-tag">${esc(c)}</span>`).join('');
    if (extra > 0) {
        const hidden = cves.slice(2).map(c => `<span class="cve-tag cve-hidden" data-row="${rowId}">${esc(c)}</span>`).join('');
        cveTags += hidden + `<span class="cve-more" id="btn-${rowId}" onclick="toggleCves('${rowId}')">+${extra} weitere</span>`;
    }

    const srcBadges = sources.map(s => `<span class="src-badge src-${esc(s)}">${esc(s)}</span>`).join('');
    const remHtml = rem
        ? `<span class="rem-badge ${remClass(rem)}">${esc(rem)}</span>`
        : `<span style="color:var(--text-muted);font-size:11px;font-family:'JetBrains Mono',monospace;">—</span>`;

    const desc = lead.description ? `<div class="adv-desc">${esc(lead.description)}</div>` : '';
    const pub  = grp.published_at ? `<div class="adv-published">Veröffentlicht: <span data-fmt-date="${esc(grp.published_at)}">…</span></div>` : '';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="td-num">${rowNum}</td>
      <td>${idCell}</td>
      <td>
        <div class="adv-title">${esc(grp.title)}</div>
        ${desc}${pub}
      </td>
      <td><div class="cve-list" id="${rowId}">${cveTags}</div></td>
      <td>
        <div class="cvss-wrap ${sev}">
          <span class="cvss-score">${score != null ? score.toFixed(1) : '—'}</span>
          <span class="cvss-badge">${cvssLabel(score)}</span>
        </div>
      </td>
      <td><div class="src-badges">${srcBadges}</div></td>
      <td>
        <span class="mod-date" data-fmt-date="${esc(grp.modified_at)}">…</span>
        <span class="mod-ago"  data-fmt-ago="${esc(grp.modified_at)}">…</span>
      </td>
      <td>${remHtml}</td>
    `;

    tr.querySelectorAll('[data-fmt-date]').forEach(el => el.textContent = fmtDate(el.dataset.fmtDate));
    tr.querySelectorAll('[data-fmt-ago]').forEach(el  => el.textContent = ago(el.dataset.fmtAgo));

    return tr;
}

/* ════════════════════════════════════════════════════════════════════
   RENDER PAGE — clear table and render the groups for this page
   ════════════════════════════════════════════════════════════════════ */
function renderGroups(groups) {
    if (skeleton && skeleton.parentNode) skeleton.remove();
    tbody.innerHTML = '';
    const frag = document.createDocumentFragment();
    const offset = (curPage - 1) * pageSize;
    groups.forEach((grp, i) => {
        frag.appendChild(buildRow(grp, offset + i + 1));
    });
    tbody.appendChild(frag);
}

/* ════════════════════════════════════════════════════════════════════
   STATS UPDATE
   ════════════════════════════════════════════════════════════════════ */
function updateStats() {
    const start    = totalRows === 0 ? 0 : (curPage - 1) * pageSize + 1;
    const end      = Math.min(curPage * pageSize, totalRows);
    const pagesStr = totalPages.toLocaleString();

    pageInfoEl.textContent  = totalRows > 0 ? `${start.toLocaleString()}–${end.toLocaleString()}` : '0–0';
    totalMeta.textContent   = totalRows.toLocaleString();
    navCount.textContent    = totalRows.toLocaleString();
    if (footerPage)  footerPage.textContent  = curPage.toLocaleString();
    if (footerPages) footerPages.textContent = pagesStr;
}

/* ════════════════════════════════════════════════════════════════════
   PAGINATION ENGINE (UI — page buttons trigger API fetch)
   ════════════════════════════════════════════════════════════════════ */
const btnStyle = 'padding:.3rem .7rem;border-radius:6px;border:1px solid var(--border,rgba(255,255,255,.12));' +
    'background:var(--bg-card,#151e2d);color:var(--text-primary,#e1e1e1);cursor:pointer;font-size:13px;' +
    'transition:background .15s,border-color .15s;min-width:2.2rem;text-align:center;';

function buildPager(pages) {
    pagerEl.innerHTML = '';
    if (pages <= 1) return;

    const mk = (txt, page, active, disabled) => {
        const b = document.createElement('button');
        b.textContent = txt;
        b.style.cssText = btnStyle;
        if (active)   { b.style.background = 'var(--accent,#1a8fd1)'; b.style.borderColor = 'var(--accent,#1a8fd1)'; b.style.color = '#fff'; }
        if (disabled) { b.style.opacity = '.35'; b.style.cursor = 'not-allowed'; }
        else b.addEventListener('click', () => { goToPage(page); pagerEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); });
        pagerEl.appendChild(b);
    };
    const dot = () => {
        const sp = document.createElement('span');
        sp.textContent = '…';
        sp.style.cssText = 'color:var(--text-muted,rgba(255,255,255,.35));padding:0 .15rem;font-size:13px;';
        pagerEl.appendChild(sp);
    };

    mk('←', curPage - 1, false, curPage === 1);
    const d = 2, lo = Math.max(2, curPage - d), hi = Math.min(pages - 1, curPage + d);
    mk(1, 1, curPage === 1, false);
    if (lo > 2)        dot();
    for (let p = lo; p <= hi; p++) mk(p, p, p === curPage, false);
    if (hi < pages - 1) dot();
    if (pages > 1)     mk(pages, pages, curPage === pages, false);
    mk('→', curPage + 1, false, curPage === pages);

    const start = (curPage - 1) * pageSize + 1;
    const end   = Math.min(curPage * pageSize, totalRows);
    const info  = document.createElement('span');
    info.style.cssText = 'color:var(--text-muted,rgba(255,255,255,.38));font-size:12px;margin-left:.5rem;white-space:nowrap;';
    info.textContent = `${start.toLocaleString()}–${end.toLocaleString()} / ${totalRows.toLocaleString()}`;
    pagerEl.appendChild(info);
}

/* ════════════════════════════════════════════════════════════════════
   CORE FETCH — load a single page from the API
   ════════════════════════════════════════════════════════════════════ */
async function loadPage(page) {
    if (loading) return;
    loading = true;
    errorBanner.style.display = 'none';

    /* Show skeleton while fetching */
    tbody.innerHTML = `
      <tr class="skeleton-row">
        <td><div class="skeleton-cell" style="width:20px;margin:auto;"></div></td>
        <td><div class="skeleton-cell" style="width:140px;"></div></td>
        <td>
          <div class="skeleton-cell" style="width:85%;margin-bottom:6px;"></div>
          <div class="skeleton-cell" style="width:60%;height:10px;"></div>
        </td>
        <td><div class="skeleton-cell" style="width:100px;"></div></td>
        <td><div class="skeleton-cell" style="width:50px;margin:auto;"></div></td>
        <td><div class="skeleton-cell" style="width:45px;"></div></td>
        <td>
          <div class="skeleton-cell" style="width:80px;margin-bottom:4px;"></div>
          <div class="skeleton-cell" style="width:55px;height:10px;"></div>
        </td>
        <td><div class="skeleton-cell" style="width:90px;"></div></td>
      </tr>`;

    try {
        const q = (searchEl?.value || '').trim();
        const params = new URLSearchParams({
            path:      '/API/advisories/',
            page_size: pageSize,
            page:      page,
            sort_by:   SORT_BY,
        });
        if (q) params.set('search', q);

        const resp = await fetch(`${PROXY}?${params}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const json = await resp.json();
        if (json.error) throw new Error(json.error);

        const items = json.data ?? [];
        totalRows  = json.pagination?.total      ?? 0;
        totalPages = json.pagination?.total_pages ?? 0;
        curPage    = page;

        const groups = mapApiGroups(items);
        renderGroups(groups);
        buildPager(totalPages);
        updateStats();

    } catch (err) {
        console.error('Advisory fetch error:', err);
        tbody.innerHTML = '';
        errorBanner.style.display = '';
        errorBanner.innerHTML = `<strong>⚠ API-Fehler:</strong> ${esc(err.message)} — Stelle sicher, dass der GRID-Server auf dem Host unter Port 8000 läuft.`;
    } finally {
        loading = false;
    }
}

/* ════════════════════════════════════════════════════════════════════
   NAVIGATE TO PAGE
   ════════════════════════════════════════════════════════════════════ */
function goToPage(page) {
    page = Math.max(1, Math.min(page, totalPages || 1));
    loadPage(page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ════════════════════════════════════════════════════════════════════
   SIDEBAR / THEME TOGGLES
   ════════════════════════════════════════════════════════════════════ */
document.getElementById('sidebarToggle').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('collapsed');
    document.getElementById('app').classList.toggle('sidebar-collapsed');
});

document.getElementById('themeToggle').addEventListener('click', () => {
    const html = document.documentElement;
    const next = html.dataset.theme === 'dark' ? 'light' : 'dark';
    html.dataset.theme = next;
    localStorage.setItem('grid-theme', next);
});

(function () {
    const saved = localStorage.getItem('grid-theme');
    if (saved) document.documentElement.dataset.theme = saved;
})();

/* ── Date formatting for static elements ── */
document.querySelectorAll('[data-fmt-datetime]').forEach(el => el.textContent = fmtDatetime(el.dataset.fmtDatetime));

/* ── CVE toggle ── */
function toggleCves(rowId) {
    const hidden  = document.querySelectorAll('[data-row="' + rowId + '"]');
    const moreBtn = document.getElementById('btn-' + rowId);
    if (!moreBtn) return;
    const isOpen  = moreBtn.classList.contains('open');
    hidden.forEach(el => el.classList.toggle('visible', !isOpen));
    moreBtn.classList.toggle('open', !isOpen);
    moreBtn.textContent = isOpen ? '+' + hidden.length + ' weitere' : 'Weniger ▲';
}

/* ── Page-size selector: reset to page 1 and reload ── */
pageSel.addEventListener('change', () => {
    pageSize = +pageSel.value;
    curPage  = 1;
    loadPage(1);
});

/* ── Search: debounce 350 ms, then reload from page 1 ── */
if (searchEl) {
    searchEl.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            curPage = 1;
            loadPage(1);
        }, 350);
    });
}

/* ════════════════════════════════════════════════════════════════════
   BOOT — load page 1 immediately
   ════════════════════════════════════════════════════════════════════ */
loadPage(1);
</script>

</body>
</html>
