<?php
/**
 * GRID — Dashboard
 * Pulls live data from the GRID API for stats, newest advisories,
 * newest vendors, and newest products.
 *
 * Pattern mirrors advisories.php: server-side fetch via file_get_contents.
 */

// ─── Konfiguration ────────────────────────────────────────────────────────────
define('API_BASE',   'http://localhost:8000');
define('API_TIMEOUT', 10);

// ─── API-Helper ───────────────────────────────────────────────────────────────
function fetch_api(string $url): ?array {
    $ctx = stream_context_create([
        'http' => [
            'timeout'       => API_TIMEOUT,
            'ignore_errors' => true,
        ]
    ]);
    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false) return null;
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) return null;
    return $decoded;
}

// ─── Daten laden ──────────────────────────────────────────────────────────────

// Status (advisory_count, product_count, vendor_count)
$status = fetch_api(API_BASE . '/API/status');

$advisory_count = (int)($status['advisory_count'] ?? 0);
$product_count  = (int)($status['product_count']  ?? 0);
$vendor_count   = (int)($status['vendor_count']   ?? 0);

// High-priority: advisories with CVSS >= 7.0  (sort by score desc, grab first page)
$high_resp      = fetch_api(API_BASE . '/API/advisories/?page_size=1&min_cvss=7.0');
$high_count     = (int)($high_resp['pagination']['total'] ?? 0);

// High-prio share (percentage)
$high_prio_pct  = $advisory_count > 0
    ? round(($high_count / $advisory_count) * 100, 1)
    : 0.0;

// Newest advisories (6 entries, sorted by modified_at desc)
$newest_adv_resp = fetch_api(
    API_BASE . '/API/advisories/?page_size=6&sort_by=-timeline.modified_at'
);
$newest_advisories = $newest_adv_resp['data'] ?? [];

// Newest vendors (6 entries, sorted alphabetically – API default)
$vendors_resp   = fetch_api(API_BASE . '/API/vendors/?page_size=6');
$newest_vendors = $vendors_resp['data'] ?? [];

// Newest products (6 entries)
$products_resp   = fetch_api(API_BASE . '/API/products/?page_size=6');
$newest_products = $products_resp['data'] ?? [];

// ─── Hilfsfunktionen ──────────────────────────────────────────────────────────
function cvss_score_from_adv(array $adv): ?float {
    $s = $adv['metrics']['cvss_v3']['base_score'] ?? null;
    return $s !== null ? (float)$s : null;
}

function vendor_initials(string $name): string {
    $words = preg_split('/\s+/', trim($name));
    if (count($words) >= 2) {
        return strtoupper(mb_substr($words[0], 0, 1) . mb_substr($words[1], 0, 1));
    }
    return strtoupper(mb_substr($name, 0, 1));
}

// Deterministic colour from vendor name (hue wheel)
function vendor_color(string $name): string {
    $hue = crc32($name) % 360;
    if ($hue < 0) $hue += 360;
    return "hsl({$hue}, 65%, 52%)";
}

$api_ok = ($status !== null);
?>
<!DOCTYPE html>
<html lang="de" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>GRID — Global Risk Intelligence Dashboard</title>
  <meta name="description" content="GRID Dashboard — Real-time global vulnerability and risk intelligence overview." />
  <link rel="icon" type="image/svg+xml" href="/media/logo.svg" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="style/index.css" />
</head>
<body>

<div class="app" id="app">

  <!-- ═══════════════════════════════ SIDEBAR ═══════════════════════════════ -->
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-logo">
      <div class="logo-mark">
        <img src="/media/logo.svg" alt="GRID Logo" style="width:32px;height:32px;filter:brightness(0) invert(1);" />
        <span class="logo-rid" style="font-size:1.35rem;font-weight:800;letter-spacing:.04em;">GRID</span>
      </div>
      <span class="logo-sub">Global Risk Intelligence</span>
    </div>

    <nav class="sidebar-nav">

      <div class="nav-section">
        <span class="nav-label">Menu</span>
        <a href="#" class="nav-item active" data-page="dashboard">
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
        <a href="advisories.php" class="nav-item" data-page="vuln-all">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 8v5"/><circle cx="12" cy="16.5" r=".5" fill="currentColor"/></svg>
          <span>Alle</span>
          <?php if ($advisory_count > 0): ?>
          <span class="nav-count"><?= number_format($advisory_count) ?></span>
          <?php endif; ?>
        </a>
        <a href="#" class="nav-item nav-item--danger" data-page="vuln-high">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v5"/><circle cx="12" cy="17.5" r=".5" fill="currentColor"/></svg>
          <span>High Priority</span>
          <?php if ($high_count > 0): ?>
          <span class="nav-count nav-count--danger"><?= number_format($high_count) ?></span>
          <?php endif; ?>
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
          <input type="text" class="search-input" placeholder="Advisories, CVEs, Vendors suchen…" />
          <span class="search-shortcut">⌘K</span>
        </div>
      </div>
      <div class="topbar-right">
        <button class="btn-icon btn-icon--pulse" aria-label="Notifications">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
          <span class="notif-dot"></span>
        </button>
        <button class="btn-icon" id="themeToggle" aria-label="Toggle theme">
          <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
          <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
        </button>
      </div>
    </header>

    <!-- DASHBOARD BODY -->
    <div class="dashboard">

      <!-- ── API ERROR BANNER ── -->
      <?php if (!$api_ok): ?>
      <div style="margin:1.5rem 2rem;padding:1rem 1.25rem;background:rgba(196,64,64,0.12);border:1px solid rgba(196,64,64,0.35);border-radius:8px;color:#c44040;font-size:13px;">
        <strong>⚠ API nicht erreichbar.</strong> Stelle sicher, dass der GRID-Server unter
        <code><?= htmlspecialchars(API_BASE) ?></code> läuft.
        Alle Werte werden als 0 angezeigt.
      </div>
      <?php endif; ?>

      <!-- ── TODAY ── -->
      <section class="section-today">
        <div class="section-header">
          <h2 class="section-title">Today</h2>
          <span class="section-date" id="todayDate"></span>
        </div>
        <div class="today-cards">
          <div class="stat-card stat-card--accent">
            <div class="stat-card__icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">Total Advisories</span>
              <span class="stat-card__value" data-target="<?= $advisory_count ?>">0</span>
              <span class="stat-card__sub">in der Datenbank</span>
            </div>
          </div>

          <div class="stat-card">
            <div class="stat-card__icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v5"/><circle cx="12" cy="17.5" r=".5" fill="currentColor"/></svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">High Priority</span>
              <span class="stat-card__value" data-target="<?= $high_count ?>">0</span>
              <span class="stat-card__sub">CVSS ≥ 7.0</span>
            </div>
            <div class="stat-card__trend stat-card__trend--up"><?= number_format($high_prio_pct, 1) ?>%</div>
          </div>

          <div class="stat-card">
            <div class="stat-card__icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">Produkte</span>
              <span class="stat-card__value" data-target="<?= $product_count ?>">0</span>
              <span class="stat-card__sub">erfasste Softwareprodukte</span>
            </div>
          </div>

          <div class="stat-card">
            <div class="stat-card__icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>
            </div>
            <div class="stat-card__body">
              <span class="stat-card__label">Hersteller</span>
              <span class="stat-card__value" data-target="<?= $vendor_count ?>">0</span>
              <span class="stat-card__sub">bekannte Vendors</span>
            </div>
          </div>
        </div>
      </section>

      <!-- ── ANALYTICS ── -->
      <section class="section-analytics">
        <div class="section-header">
          <h2 class="section-title">Analytics</h2>
          <div class="chart-controls">
            <button class="chart-btn chart-btn--active">30d</button>
            <button class="chart-btn">90d</button>
            <button class="chart-btn">1y</button>
            <button class="chart-btn">All</button>
          </div>
        </div>

        <div class="kpi-strip">
          <div class="kpi">
            <span class="kpi__value" data-target="<?= $advisory_count ?>">0</span>
            <span class="kpi__label">Total Advisories</span>
          </div>
          <div class="kpi-divider"></div>
          <div class="kpi">
            <span class="kpi__value" data-target="<?= $product_count ?>">0</span>
            <span class="kpi__label">Products</span>
          </div>
          <div class="kpi-divider"></div>
          <div class="kpi">
            <span class="kpi__value" data-target="<?= $vendor_count ?>">0</span>
            <span class="kpi__label">Vendors</span>
          </div>
          <div class="kpi-divider"></div>
          <div class="kpi">
            <span class="kpi__value" data-target="<?= $high_count ?>">0</span>
            <span class="kpi__label">High-Priority</span>
            <span class="kpi__accent kpi__accent--danger"></span>
          </div>
          <div class="kpi-divider"></div>
          <div class="kpi">
            <span class="kpi__value kpi__value--pct" data-target="<?= $high_prio_pct ?>">0</span>
            <span class="kpi__label">High-Prio Share</span>
            <span class="kpi__accent kpi__accent--warn"></span>
          </div>
        </div>

        <div class="chart-area">
          <canvas id="mainChart"></canvas>
        </div>
      </section>

      <!-- ── BOTTOM PANELS ── -->
      <section class="section-panels">

        <div class="panel">
          <div class="panel-header">
            <h3 class="panel-title">Newest Advisories</h3>
            <a href="advisories.php" class="panel-link">Alle anzeigen →</a>
          </div>
          <div class="panel-list" id="advisoryList">
            <?php foreach ($newest_advisories as $adv):
                $score = cvss_score_from_adv($adv);
                $cve   = $adv['cve_id'] ?? null;
                $wid   = $adv['metadata']['raw_source_ids']['cert_bund'] ?? null;
                $euvd  = $adv['metadata']['raw_source_ids']['euvd']      ?? null;
                $label = $wid ?? $euvd ?? $cve ?? '—';
                $sub   = htmlspecialchars($adv['title'] ?? '(Kein Titel)');
                $src   = implode(', ', array_keys(array_flip($adv['metadata']['sources'] ?? [])));
                if ($src) $sub .= ' — ' . htmlspecialchars($src);
            ?>
            <div class="panel-row" data-score="<?= $score !== null ? number_format($score, 1) : 'N/A' ?>">
              <span class="score-badge" style="--sc:<?= $score !== null
                  ? ($score >= 9.0 ? 'var(--sev-critical)' : ($score >= 7.0 ? 'var(--sev-high)' : ($score >= 4.0 ? 'var(--sev-medium)' : 'var(--sev-low)')))
                  : 'var(--text-muted)' ?>"><?= $score !== null ? number_format($score, 1) : '—' ?></span>
              <div class="panel-row__text">
                <span class="panel-row__name"><?= htmlspecialchars($label) ?></span>
                <span class="panel-row__sub"><?= $sub ?></span>
              </div>
            </div>
            <?php endforeach; ?>
            <?php if (empty($newest_advisories)): ?>
            <div style="padding:1.5rem;text-align:center;color:var(--text-muted);font-size:13px;">Keine Daten verfügbar</div>
            <?php endif; ?>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <h3 class="panel-title">Newest Affected Vendors</h3>
            <a href="#" class="panel-link">Alle anzeigen →</a>
          </div>
          <div class="panel-list" id="vendorList">
            <?php foreach ($newest_vendors as $v):
                $name    = $v['name'] ?? 'Unknown';
                $initials = vendor_initials($name);
                $color   = vendor_color($name);
                $sources = is_array($v['sources'] ?? null) ? implode(', ', $v['sources']) : ($v['sources'] ?? '');
            ?>
            <div class="panel-row">
              <span class="vendor-icon" style="--vc:<?= htmlspecialchars($color) ?>"><?= htmlspecialchars($initials) ?></span>
              <div class="panel-row__text">
                <span class="panel-row__name"><?= htmlspecialchars($name) ?></span>
                <span class="panel-row__sub"><?= htmlspecialchars($sources ?: 'Vendor') ?></span>
              </div>
            </div>
            <?php endforeach; ?>
            <?php if (empty($newest_vendors)): ?>
            <div style="padding:1.5rem;text-align:center;color:var(--text-muted);font-size:13px;">Keine Daten verfügbar</div>
            <?php endif; ?>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <h3 class="panel-title">Newest Affected Products</h3>
            <a href="#" class="panel-link">Alle anzeigen →</a>
          </div>
          <div class="panel-list" id="productList">
            <?php foreach ($newest_products as $p):
                $pname  = $p['name']        ?? 'Unknown';
                $vendor = $p['vendor_name'] ?? '';
            ?>
            <div class="panel-row">
              <span class="product-count"><?= htmlspecialchars(mb_strtoupper(mb_substr($pname, 0, 2))) ?></span>
              <div class="panel-row__text">
                <span class="panel-row__name"><?= htmlspecialchars($pname) ?></span>
                <span class="panel-row__sub"><?= htmlspecialchars($vendor) ?></span>
              </div>
            </div>
            <?php endforeach; ?>
            <?php if (empty($newest_products)): ?>
            <div style="padding:1.5rem;text-align:center;color:var(--text-muted);font-size:13px;">Keine Daten verfügbar</div>
            <?php endif; ?>
          </div>
        </div>

      </section>

    </div><!-- /dashboard -->
  </div><!-- /main-wrapper -->
</div><!-- /app -->

<script>
/* ── DATE ── */
document.getElementById('todayDate').textContent =
  new Date().toLocaleDateString('de-DE', { weekday:'long', day:'numeric', month:'long', year:'numeric' });

/* ── SIDEBAR TOGGLE ── */
document.getElementById('sidebarToggle').addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('collapsed');
  document.getElementById('app').classList.toggle('sidebar-collapsed');
});

/* ── THEME TOGGLE ── */
document.getElementById('themeToggle').addEventListener('click', () => {
  const html = document.documentElement;
  html.dataset.theme = html.dataset.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem('grid-theme', html.dataset.theme);
  setTimeout(drawChart, 50);
});

/* Load saved theme preference */
(function () {
  const saved = localStorage.getItem('grid-theme');
  if (saved) document.documentElement.dataset.theme = saved;
})();

/* ── COUNTER ANIMATION ── */
function animateCounters() {
  const counters = document.querySelectorAll('[data-target]');
  counters.forEach(el => {
    const target = parseFloat(el.dataset.target);
    const isPct  = el.classList.contains('kpi__value--pct');
    const dur    = 1400;
    const start  = performance.now();
    function step(now) {
      const progress = Math.min((now - start) / dur, 1);
      const ease     = 1 - Math.pow(1 - progress, 3);
      const val      = target * ease;
      el.textContent = isPct
        ? val.toFixed(1) + '%'
        : Math.round(val).toLocaleString('de-DE');
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  });
}
window.addEventListener('load', animateCounters);

/* ── CHART ── */
function drawChart() {
  const canvas = document.getElementById('mainChart');
  const ctx    = canvas.getContext('2d');
  const isDark = document.documentElement.dataset.theme === 'dark';

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width  = rect.width  * dpr;
  canvas.height = rect.height * dpr;
  canvas.style.width  = rect.width  + 'px';
  canvas.style.height = rect.height + 'px';
  ctx.scale(dpr, dpr);

  const W = rect.width;
  const H = rect.height;
  const padL = 52, padR = 24, padT = 20, padB = 48;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  // Sample data – 16 days
  const labels = Array.from({length:16}, (_,i) => {
    const d = new Date(); d.setDate(d.getDate() - 15 + i);
    return d.toLocaleDateString('de-DE',{day:'2-digit',month:'2-digit'});
  });
  const dataTotal = [3200,2800,4100,3600,5200,4700,3900,6100,5500,4800,7200,6600,5900,8100,7400,9200];
  const dataHigh  = [1400,1200,1800,1550,2300,2000,1700,2700,2400,2100,3200,2900,2600,3600,3200,4100];

  const maxVal = Math.max(...dataTotal) * 1.15;
  const gridLines = 5;

  const accentColor = isDark ? '#1a8fd1' : '#00659f';
  const dangerColor = isDark ? '#bf6d00' : '#a05800';
  const critColor   = isDark ? '#c44040' : '#a83232';
  const gridColor   = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.07)';
  const textColor   = isDark ? 'rgba(225,225,225,0.38)' : 'rgba(104,113,114,0.8)';

  // Grid
  ctx.font = '11px JetBrains Mono, monospace';
  ctx.fillStyle = textColor;
  ctx.strokeStyle = gridColor;
  ctx.lineWidth = 1;
  for (let i = 0; i <= gridLines; i++) {
    const y = padT + chartH - (i / gridLines) * chartH;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + chartW, y); ctx.stroke();
    ctx.textAlign = 'right';
    ctx.fillText(Math.round((maxVal * i / gridLines) / 1000) + 'k', padL - 8, y + 4);
  }

  const barW   = (chartW / labels.length) * 0.55;
  const barGap = chartW / labels.length;

  // Bars – Total (background)
  labels.forEach((lbl, i) => {
    const x   = padL + i * barGap + barGap * 0.225;
    const bh  = (dataTotal[i] / maxVal) * chartH;
    const y   = padT + chartH - bh;

    const grad = ctx.createLinearGradient(0, y, 0, padT + chartH);
    grad.addColorStop(0, isDark ? 'rgba(26,143,209,0.50)' : 'rgba(0,101,159,0.40)');
    grad.addColorStop(1, isDark ? 'rgba(26,143,209,0.04)' : 'rgba(0,101,159,0.04)');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.roundRect(x, y, barW, bh, [4, 4, 0, 0]);
    ctx.fill();

    // High-prio overlay
    const hh  = (dataHigh[i] / maxVal) * chartH;
    const hy  = padT + chartH - hh;
    const hgrad = ctx.createLinearGradient(0, hy, 0, padT + chartH);
    hgrad.addColorStop(0, isDark ? 'rgba(196,64,64,0.85)' : 'rgba(168,50,50,0.70)');
    hgrad.addColorStop(1, isDark ? 'rgba(196,64,64,0.12)' : 'rgba(168,50,50,0.08)');
    ctx.fillStyle = hgrad;
    ctx.beginPath();
    ctx.roundRect(x + barW * 0.3, hy, barW * 0.4, hh, [3, 3, 0, 0]);
    ctx.fill();

    // X labels
    ctx.fillStyle = textColor;
    ctx.textAlign = 'center';
    ctx.fillText(lbl, x + barW / 2, padT + chartH + 18);
  });

  // Line – trend
  ctx.beginPath();
  ctx.strokeStyle = accentColor;
  ctx.lineWidth   = 2.5;
  ctx.shadowColor = accentColor;
  ctx.shadowBlur  = 8;
  labels.forEach((_, i) => {
    const x  = padL + i * barGap + barGap * 0.225 + barW / 2;
    const y  = padT + chartH - (dataTotal[i] / maxVal) * chartH;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Dots on line
  labels.forEach((_, i) => {
    const x = padL + i * barGap + barGap * 0.225 + barW / 2;
    const y = padT + chartH - (dataTotal[i] / maxVal) * chartH;
    ctx.beginPath();
    ctx.arc(x, y, 3.5, 0, Math.PI * 2);
    ctx.fillStyle   = accentColor;
    ctx.shadowColor = accentColor;
    ctx.shadowBlur  = 12;
    ctx.fill();
    ctx.shadowBlur = 0;
  });

  // Legend
  const legY = padT + chartH + 36;
  const items = [
    { color: accentColor, label: 'Alle Advisories' },
    { color: critColor,   label: 'High-Priority' },
  ];
  let legX = padL;
  items.forEach(it => {
    ctx.fillStyle = it.color;
    ctx.fillRect(legX, legY - 8, 12, 8);
    ctx.fillStyle = textColor;
    ctx.textAlign = 'left';
    ctx.fillText(it.label, legX + 16, legY);
    legX += 130;
  });
}

window.addEventListener('load', () => { setTimeout(drawChart, 100); });
window.addEventListener('resize', drawChart);

/* ── CHART BUTTONS ── */
document.querySelectorAll('.chart-btn').forEach(btn => {
  btn.addEventListener('click', function() {
    document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('chart-btn--active'));
    this.classList.add('chart-btn--active');
    setTimeout(drawChart, 50);
  });
});
</script>
</body>
</html>
