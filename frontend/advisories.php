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
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GRID — Security Advisories</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">

    <link rel="stylesheet" href="style/advisories.css">
</head>
<body>

<!-- ── Header ── -->
<header>
    <div class="header-inner">
        <a class="logo" href="#">
            <div class="logo-mark">
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <rect x="1"  y="1"  width="6" height="6" rx="1" fill="white" opacity=".9"/>
                    <rect x="11" y="1"  width="6" height="6" rx="1" fill="white" opacity=".6"/>
                    <rect x="1"  y="11" width="6" height="6" rx="1" fill="white" opacity=".6"/>
                    <rect x="11" y="11" width="6" height="6" rx="1" fill="white" opacity=".9"/>
                </svg>
            </div>
            <div>
                <div class="logo-text">GRID</div>
                <div class="logo-sub">Risk Intelligence</div>
            </div>
        </a>

        <div class="header-spacer"></div>

        <?php if ($status): ?>
        <div class="header-stats">
            <div class="hstat">
                <span class="hstat-val"><?= number_format((int)($status['advisory_count'] ?? 0)) ?></span>
                <span class="hstat-lbl">Advisories</span>
            </div>
            <div class="hstat-divider"></div>
            <div class="hstat">
                <span class="hstat-val"><?= number_format((int)($status['product_count'] ?? 0)) ?></span>
                <span class="hstat-lbl">Produkte</span>
            </div>
            <div class="hstat-divider"></div>
            <div class="hstat">
                <span class="hstat-val"><?= number_format((int)($status['vendor_count'] ?? 0)) ?></span>
                <span class="hstat-lbl">Vendors</span>
            </div>
        </div>
        <?php endif; ?>

        <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">☀ Light</button>
    </div>
</header>

<!-- ── Main ── -->
<div class="wrapper">

    <div class="page-title-bar">
        <h1 class="page-title">Security <span>Advisories</span></h1>
        <div class="page-meta">
            Generiert: <?= htmlspecialchars($generated_at) ?> &nbsp;·&nbsp;
            <?= count($advisories) ?> von <?= number_format($page_total) ?> Einträgen &nbsp;·&nbsp;
            <?= $page - 1 ?> API-Seite(n) abgerufen
        </div>
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
    <div class="table-wrap">
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
            <tbody>
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

                <!-- Quelle (csaf / euvd) -->
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
                        <span style="color:var(--button-background-color);font-size:11px;">—</span>
                    <?php endif; ?>
                </td>

            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
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

</div><!-- /.wrapper -->

<script>
    // ── Theme toggle ──────────────────────────────────────────────────────────
    const themeBtn = document.getElementById('themeBtn');

    function applyTheme(mode) {
        if (mode === 'light') {
            document.body.classList.add('light-mode');
            themeBtn.textContent = '🌙 Dark';
        } else {
            document.body.classList.remove('light-mode');
            themeBtn.textContent = '☀ Light';
        }
    }

    function toggleTheme() {
        const next = document.body.classList.contains('light-mode') ? 'dark' : 'light';
        localStorage.setItem('grid-theme', next);
        applyTheme(next);
    }

    // Gespeicherte Präferenz laden (Standard: Dark)
    applyTheme(localStorage.getItem('grid-theme') || 'dark');


    // ── CVE-Tags aufklappen / zuklappen ──────────────────────────────────────
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
