<?php
/**
 * GRID — Advisories Feed
 * Zeigt die 100 aktuellsten Advisories (gruppiert nach WID/EUVD-Advisory-ID),
 * sortiert nach timeline.modified_at absteigend.
 *
 * Gruppierungslogik: mehrere CVE-Dokumente mit derselben WID- oder EUVD-
 * Advisory-ID zählen als EINE Advisory-Zeile (Bsp.: WID-SEC-2026-1438 → 15 CVEs).
 * Es werden immer genau 100 DISTINCT Advisories angezeigt.
 *
 * Stylesheet: GRID/frontend/style/advisories.css
 */

// ─── Konfiguration ────────────────────────────────────────────────────────────
define('API_BASE',    'http://localhost:8000');
define('MAX_GROUPS',  100);   // Wie viele Advisories angezeigt werden
define('PER_PAGE',    200);   // API-Einträge pro Request (Max laut Doku: 200)
define('MAX_PAGES',    20);   // Safety-Limit für Pagination
define('API_TIMEOUT',  10);   // Sekunden

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

// ─── Daten laden & gruppieren ─────────────────────────────────────────────────
$groups        = [];   // [advisory_key => group_data]
$page          = 1;
$error         = null;
$resp          = [];

while (count($groups) < MAX_GROUPS && $page <= MAX_PAGES) {
    $url  = API_BASE . '/API/advisories/'
          . '?page_size=' . PER_PAGE
          . '&page='      . $page
          . '&sort_by=-timeline.modified_at';

    $resp = fetch_api($url);

    if ($resp === null) {
        $error = "API nicht erreichbar. Stelle sicher, dass der GRID-Server unter "
               . API_BASE . " läuft.";
        break;
    }
    if (empty($resp['data'])) break;

    foreach ($resp['data'] as $adv) {
        // Advisory-Schlüssel: WID > EUVD > CVE-ID (Fallback)
        $wid  = $adv['metadata']['raw_source_ids']['cert_bund'] ?? null;
        $euvd = $adv['metadata']['raw_source_ids']['euvd']      ?? null;
        $key  = $wid ?? $euvd ?? ($adv['cve_id'] ?? uniqid('adv_'));

        $mod = $adv['timeline']['modified_at']  ?? '';
        $pub = $adv['timeline']['published_at'] ?? '';

        if (!isset($groups[$key])) {
            $groups[$key] = [
                'key'          => $key,
                'title'        => $adv['title'] ?? '(Kein Titel)',
                'cves'         => [],
                'lead'         => $adv,
                'modified_at'  => $mod,
                'published_at' => $pub,
                'sources'      => [],
            ];
        }

        // CVE nur einmal pro Advisory aufnehmen
        $cve = $adv['cve_id'] ?? null;
        if ($cve && !in_array($cve, $groups[$key]['cves'], true)) {
            $groups[$key]['cves'][] = $cve;
        }

        // Neuestes modified_at der Gruppe merken & als Lead-Dokument setzen
        if ($mod > $groups[$key]['modified_at']) {
            $groups[$key]['modified_at'] = $mod;
            $groups[$key]['lead']        = $adv;
        }

        // Frühestes published_at der Gruppe merken
        if ($pub < $groups[$key]['published_at'] || $groups[$key]['published_at'] === '') {
            $groups[$key]['published_at'] = $pub;
        }

        // Quellen sammeln
        foreach (($adv['metadata']['sources'] ?? []) as $src) {
            $groups[$key]['sources'][$src] = true;
        }
    }

    $has_next = $resp['pagination']['has_next'] ?? false;
    if (!$has_next) break;
    $page++;
}

// Nach modified_at absteigend sortieren, top 100 nehmen
usort($groups, fn($a, $b) => strcmp($b['modified_at'], $a['modified_at']));
$advisories = array_slice($groups, 0, MAX_GROUPS);
$page_total = $resp['pagination']['total'] ?? 0;

// Optionaler Status-Call für Header-Statistiken
$status = fetch_api(API_BASE . '/API/status');

// ─── Hilfsfunktionen ──────────────────────────────────────────────────────────
function cvss_class(?float $s): string {
    if ($s === null) return 'sev-default';
    if ($s >= 9.0)   return 'sev-critical';
    if ($s >= 7.0)   return 'sev-high';
    if ($s >= 4.0)   return 'sev-medium';
    return 'sev-low';
}

function cvss_label(?float $s): string {
    if ($s === null) return 'N/A';
    if ($s >= 9.0)   return 'CRITICAL';
    if ($s >= 7.0)   return 'HIGH';
    if ($s >= 4.0)   return 'MEDIUM';
    return 'LOW';
}

function fmt_date(string $iso): string {
    if (!$iso) return '—';
    try { return (new DateTime($iso))->format('d.m.Y'); }
    catch (Exception $e) { return $iso; }
}

function ago(string $iso): string {
    if (!$iso) return '';
    try {
        $diff = (new DateTime())->diff(new DateTime($iso));
        if ($diff->days === 0)  return 'Heute';
        if ($diff->days === 1)  return 'Gestern';
        if ($diff->days < 7)   return "vor {$diff->days} Tagen";
        if ($diff->days < 30)  return 'vor ' . floor($diff->days / 7)  . ' Wochen';
        if ($diff->days < 365) return 'vor ' . floor($diff->days / 30) . ' Monaten';
        return 'vor ' . floor($diff->days / 365) . ' Jahren';
    } catch (Exception $e) { return ''; }
}

function remediation_class(string $status): string {
    $s = strtolower($status);
    if (str_contains($s, 'patch') || str_contains($s, 'fix') || str_contains($s, 'update')) return 'rem-patch';
    if (str_contains($s, 'workaround'))                                                       return 'rem-workaround';
    if (str_contains($s, 'none') || str_contains($s, 'kein'))                                return 'rem-none';
    return 'rem-unknown';
}

$generated_at = (new DateTime())->format('d.m.Y H:i:s');
?>
<!DOCTYPE html>
<html lang="de" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GRID — Security Advisories</title>
    <meta name="description" content="GRID Security Advisories — Browse the latest vulnerability advisories sorted by modification date.">
    <link rel="icon" type="image/svg+xml" href="/media/logo.svg" />

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">

    <link rel="stylesheet" href="style/advisories.css">
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
          <?php if ($page_total > 0): ?>
          <span class="nav-count"><?= number_format($page_total) ?></span>
          <?php endif; ?>
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

      <!-- ── Section header ── -->
      <div class="section-header">
        <h1 class="section-title">Security Advisories</h1>
        <span class="section-meta">
          <?= count($advisories) ?> von <?= number_format($page_total) ?> &nbsp;·&nbsp; Generiert: <?= htmlspecialchars($generated_at) ?>
        </span>
      </div>

      <?php if ($error): ?>
      <div class="error-banner">
        <strong>⚠ API-Fehler:</strong> <?= htmlspecialchars($error) ?>
      </div>
      <?php endif; ?>

      <?php if (empty($advisories) && !$error): ?>
      <div class="error-banner">
        <strong>Keine Daten:</strong> Die API hat keine Advisories zurückgegeben.
      </div>
      <?php endif; ?>

      <?php if (!empty($advisories)): ?>
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
            <?php foreach ($advisories as $i => $grp):
                $lead    = $grp['lead'];
                $score   = $lead['metrics']['cvss_v3']['base_score'] ?? null;
                $sev     = cvss_class($score);
                $cves    = $grp['cves'];
                $extra   = count($cves) - 2;
                $rem     = $lead['remediation']['status'] ?? '';
                $sources = array_keys($grp['sources']);
                $row_id  = 'row-' . $i;

                $wid  = $lead['metadata']['raw_source_ids']['cert_bund'] ?? null;
                $euvd = $lead['metadata']['raw_source_ids']['euvd']      ?? null;
            ?>
            <tr>

              <!-- # -->
              <td class="td-num"><?= $i + 1 ?></td>

              <!-- Advisory-ID -->
              <td>
                <?php if ($wid): ?>
                  <span class="adv-id-label">WID</span>
                  <span class="adv-id"><?= htmlspecialchars($wid) ?></span>
                <?php elseif ($euvd): ?>
                  <span class="adv-id-label">EUVD</span>
                  <span class="adv-id"><?= htmlspecialchars($euvd) ?></span>
                <?php else: ?>
                  <span class="adv-id-label">CVE</span>
                  <span class="adv-id"><?= htmlspecialchars($cves[0] ?? '—') ?></span>
                <?php endif; ?>
              </td>

              <!-- Titel + Kurzbeschreibung + Erstveröffentlichung -->
              <td>
                <div class="adv-title"><?= htmlspecialchars($grp['title']) ?></div>
                <?php if (!empty($lead['description'])): ?>
                  <div class="adv-desc"><?= htmlspecialchars($lead['description']) ?></div>
                <?php endif; ?>
                <?php if ($grp['published_at']): ?>
                  <div class="adv-published">Veröffentlicht: <?= fmt_date($grp['published_at']) ?></div>
                <?php endif; ?>
              </td>

              <!-- CVEs (erste 2 sichtbar, Rest ausklappbar) -->
              <td>
                <div class="cve-list" id="<?= $row_id ?>">
                  <?php for ($c = 0; $c < min(2, count($cves)); $c++): ?>
                    <span class="cve-tag"><?= htmlspecialchars($cves[$c]) ?></span>
                  <?php endfor; ?>

                  <?php if ($extra > 0): ?>
                    <?php for ($c = 2; $c < count($cves); $c++): ?>
                      <span class="cve-tag cve-hidden" data-row="<?= $row_id ?>">
                        <?= htmlspecialchars($cves[$c]) ?>
                      </span>
                    <?php endfor; ?>
                    <span class="cve-more" id="btn-<?= $row_id ?>"
                          onclick="toggleCves('<?= $row_id ?>')">
                      +<?= $extra ?> weitere
                    </span>
                  <?php endif; ?>
                </div>
              </td>

              <!-- CVSS Score + Severity-Badge -->
              <td>
                <div class="cvss-wrap <?= $sev ?>">
                  <span class="cvss-score">
                    <?= $score !== null ? number_format((float)$score, 1) : '—' ?>
                  </span>
                  <span class="cvss-badge"><?= cvss_label($score) ?></span>
                </div>
              </td>

              <!-- Quelle -->
              <td>
                <div class="src-badges">
                  <?php foreach ($sources as $src): ?>
                    <span class="src-badge src-<?= htmlspecialchars($src) ?>">
                      <?= htmlspecialchars($src) ?>
                    </span>
                  <?php endforeach; ?>
                </div>
              </td>

              <!-- Aktualisiert -->
              <td>
                <span class="mod-date"><?= fmt_date($grp['modified_at']) ?></span>
                <span class="mod-ago"><?= ago($grp['modified_at']) ?></span>
              </td>

              <!-- Remediation-Status -->
              <td>
                <?php if ($rem): ?>
                  <span class="rem-badge <?= remediation_class($rem) ?>">
                    <?= htmlspecialchars($rem) ?>
                  </span>
                <?php else: ?>
                  <span style="color:var(--text-muted);font-size:11px;font-family:'JetBrains Mono',monospace;">—</span>
                <?php endif; ?>
              </td>

            </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
      <?php endif; ?>

      <footer class="page-footer">
        <span>GRID — Global Risk Intelligence Dashboard</span>
        <span>
          Sortierung: <code>timeline.modified_at</code> ↓
          &nbsp;·&nbsp; Gruppiert nach Advisory-ID
          &nbsp;·&nbsp; <?= count($advisories) ?> Einträge
        </span>
      </footer>

    </div><!-- /page-body -->
  </div><!-- /main-wrapper -->
</div><!-- /app -->

<script>
  /* ── SIDEBAR TOGGLE ── */
  document.getElementById('sidebarToggle').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('collapsed');
    document.getElementById('app').classList.toggle('sidebar-collapsed');
  });

  /* ── THEME TOGGLE ── */
  document.getElementById('themeToggle').addEventListener('click', () => {
    const html = document.documentElement;
    const next = html.dataset.theme === 'dark' ? 'light' : 'dark';
    html.dataset.theme = next;
    localStorage.setItem('grid-theme', next);
  });

  /* Load saved theme preference */
  (function () {
    const saved = localStorage.getItem('grid-theme');
    if (saved) document.documentElement.dataset.theme = saved;
  })();

  /* ── SEARCH FILTER ── */
  document.getElementById('searchInput').addEventListener('input', function () {
    const q = this.value.toLowerCase();
    document.querySelectorAll('#advisoryTableBody tr').forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  /* ── CVE-TAGS TOGGLE ── */
  function toggleCves(rowId) {
    const hidden  = document.querySelectorAll('[data-row="' + rowId + '"]');
    const moreBtn = document.getElementById('btn-' + rowId);
    const isOpen  = moreBtn.classList.contains('open');
    hidden.forEach(el => el.classList.toggle('visible', !isOpen));
    moreBtn.classList.toggle('open', !isOpen);
    moreBtn.textContent = isOpen
      ? '+' + hidden.length + ' weitere'
      : 'Weniger ▲';
  }
</script>

</body>
</html>
