<?php
/* The single place where the content security policy lives. It generates a
   one-time nonce per request and sends the header. Inline scripts carry that
   nonce, so 'unsafe-inline' is not needed for script-src: a <script> injected by
   an attacker, having no nonce, does not run.

   Styles are split across two sources, as CSP3 allows:
   - style-src-elem is strict: 'self' plus the nonce. A foreign <style> or <link>
     cannot be injected without the nonce, and that is the main vector — with it
     half a page can be repainted.
   - style-src-attr keeps 'unsafe-inline', which allows inline style="…"
     attributes. A nonce for those does not exist in CSP at all, and the markup
     uses many of them. The risk of an attribute is far smaller than that of a
     block: it paints its own element and no script runs from it, while forbidding
     them breaks every style="…" on the site — an avatar circle unfolds into a
     full-size picture.

   img and connect are deliberately wide: the browser client loads camera
   snapshots from arbitrary hosts and talks over secure websockets. object-src
   none, base-uri and form-action self and frame-ancestors self close off plugins,
   an injected <base>, a hijacked form target and the site being shown inside
   someone else's frame. */

if (!isset($GLOBALS['CSP_NONCE'])) {
    $GLOBALS['CSP_NONCE'] = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');

    if (!headers_sent()) {
        $n = $GLOBALS['CSP_NONCE'];
        header(
            "Content-Security-Policy: " .
            "default-src 'self'; " .
            "script-src 'self' 'nonce-$n' https://cdnjs.cloudflare.com; " .
            "style-src 'self' 'nonce-$n' https://cdnjs.cloudflare.com; " .
            "style-src-elem 'self' 'nonce-$n' https://cdnjs.cloudflare.com; " .
            "style-src-attr 'unsafe-inline'; " .
            "img-src 'self' data: blob: https:; " .
            "font-src 'self' data: https://cdnjs.cloudflare.com; " .
            "connect-src 'self' https: wss:; " .
            "object-src 'self'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
        );
    }
}

/** The nonce attribute for an inline <script>. */
function csp_nonce_attr(): string {
    return 'nonce="' . htmlspecialchars($GLOBALS['CSP_NONCE'] ?? '', ENT_QUOTES) . '"';
}
