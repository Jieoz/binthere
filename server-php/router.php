<?php
// router.php — dev-only router for `php -S` e2e runs. Mirrors the nginx
// fastcgi mapping: everything under /api goes to api.php, /api/stars included.
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (preg_match('#/api(/|$)#', $uri)) {
    $_SERVER['PATH_INFO'] = substr($uri, strpos($uri, '/api') + 4); // after '/api'
    require __DIR__ . '/api.php';
    return true;
}
http_response_code(404);
echo '{"error":"Not found"}';
return true;
