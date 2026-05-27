<?php
/**
 * api-proxy.php — Same-origin proxy for the GRID FastAPI backend.
 *
 * The browser calls this script (same host/port as the PHP frontend).
 * PHP then fetches http://localhost:8000 server-side and returns the JSON.
 *
 * Usage: /api-proxy.php?path=/API/advisories/&page=1&page_size=200&sort_by=-timeline.modified_at
 */

define('BACKEND',     'http://localhost:8000');
define('API_TIMEOUT', 15);

// ── Security: only allow paths starting with /API/ ──────────────────────────
$path = $_GET['path'] ?? '';
if (!preg_match('#^/API/#', $path)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid path']);
    exit;
}

// ── Forward all other query params (except 'path') ──────────────────────────
$params = $_GET;
unset($params['path']);
$qs  = http_build_query($params);
$url = BACKEND . $path . ($qs ? '?' . $qs : '');

// ── Fetch from backend ───────────────────────────────────────────────────────
$ctx = stream_context_create([
    'http' => [
        'timeout'       => API_TIMEOUT,
        'ignore_errors' => true,
        'method'        => 'GET',
    ]
]);

$raw = @file_get_contents($url, false, $ctx);

// Forward the HTTP status code from the backend
$status_line = $http_response_header[0] ?? 'HTTP/1.1 502 Bad Gateway';
preg_match('/HTTP\/\S+\s+(\d+)/', $status_line, $m);
http_response_code((int)($m[1] ?? 502));

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

if ($raw === false) {
    echo json_encode(['error' => 'Backend unreachable', 'url' => $url]);
    exit;
}

echo $raw;
