<?php
/* Localisation of the whole site, not just the landing page.

   The site's base language is ENGLISH and lives on bare addresses: /webhook,
   /guide/. Other languages sit behind a prefix: /ru/webhook, /de/guide/.
   The slug is always English, whatever the language of the page.
   Page sources are written in English, so everything but the base is translated.
   The prefix is stripped by .htaccess, which puts the language code into the
   SITELANG environment variable; on repeated rewrite passes Apache prepends
   REDIRECT_, so we match by the suffix of the name.

   Translation is a string replacement through the dictionary lang/<code>.php,
   an [English string => translation] map. The base language has no dictionary:
   the sources are already written in it. */

// The base language comes first: it lives on bare addresses and gets no prefix.
require_once __DIR__ . '/csp.php';   // nonce and the CSP header, before any output

const I18N_BASE = 'en';

$I18N_LANGS = [
    'en' => 'English',
    'ru' => 'Русский',
    'de' => 'Deutsch',
    'es' => 'Español',
    'fr' => 'Français',
    'pt' => 'Português',
    'zh' => '中文',
];

/** The language code: from ?lang= on the landing page, or from the URL prefix
 *  passed by .htaccess in an environment variable. */
function i18n_lang(array $langs): string
{
    $q = (string)($_GET['lang'] ?? '');
    if ($q !== '' && isset($langs[$q])) return $q;
    foreach ($_SERVER as $k => $v) {
        if (substr($k, -8) === 'SITELANG' && isset($langs[(string)$v])) return (string)$v;
    }
    // Calls to /api/ carry no language prefix, yet they answer a person, so the
    // language comes from their cookie. Pages do not consult the cookie: there the
    // address decides, otherwise an English URL would start serving another language.
    if (strncmp((string)($_SERVER['REQUEST_URI'] ?? ''), '/api/', 5) === 0) {
        $ck = (string)($_COOKIE['elang'] ?? '');
        if ($ck !== '' && isset($langs[$ck])) return $ck;
    }
    return I18N_BASE;
}

/** The best supported language from the browser's Accept-Language, else the base. */
function i18n_accept_best(array $langs): string
{
    $hdr = (string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');
    if ($hdr === '') return I18N_BASE;
    $best = I18N_BASE; $bestQ = -1.0;
    foreach (explode(',', $hdr) as $part) {
        $part = trim($part);
        if ($part === '') continue;
        $q = 1.0;
        if (preg_match('/;\s*q\s*=\s*([0-9.]+)/', $part, $m)) $q = (float)$m[1];
        $code = strtolower(substr($part, 0, 2));   // ru-RU → ru, zh-CN → zh
        if ($code !== '' && isset($langs[$code]) && $q > $bestQ) { $best = $code; $bestQ = $q; }
    }
    return $best;
}

/** A link in the language switcher. For the base language it appends ?lang=en so
 *  that the automatic choice records the manual pick in the cookie and does not
 *  drag the reader back to the browser's language. Others get the usual prefixed
 *  address. */
function i18n_switch_href(string $code, string $here): string
{
    if ($code !== I18N_BASE) return i18n_href($code, $here);
    return $here . (strpos($here, '?') === false ? '?' : '&') . 'lang=en';
}

/** Picks the language from the browser's locale on a first visit and remembers
 *  it in a cookie. Call from head.php BEFORE any output.
 *   - an explicit language (a /xx/ prefix or ?lang=) is remembered, no redirect
 *     (for ?lang=en on a bare address the parameter is cleaned out of the URL);
 *   - a cookie is respected: a non-English one moves to the prefix, English stays;
 *   - a first visit with no cookie follows Accept-Language: non-English redirects
 *     to the prefix, English or unknown stays and marks the cookie as English,
 *     after which we stop checking. */
function i18n_autoroute(): void
{
    global $LANG, $I18N_LANGS, $I18N_PATH;
    if (PHP_SAPI === 'cli') return;
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') return;
    if (headers_sent()) return;

    $set = function (string $v) {
        setcookie('elang', $v, ['expires' => time() + 31536000, 'path' => '/', 'samesite' => 'Lax']);
        $_COOKIE['elang'] = $v;
    };
    $target = function (string $code): string {
        global $I18N_PATH;
        $q = $_GET; unset($q['lang']);
        $qs = $q ? '?' . http_build_query($q) : '';
        return i18n_href($code, $I18N_PATH) . $qs;
    };

    // An explicitly requested language: record the choice.
    if ($LANG !== I18N_BASE || isset($_GET['lang'])) {
        if (($_COOKIE['elang'] ?? '') !== $LANG) $set($LANG);
        if (isset($_GET['lang']) && $LANG === I18N_BASE) {   // clean ?lang=en out of the URL
            header('Location: ' . $target(I18N_BASE), true, 302); exit;
        }
        return;
    }

    // A bare English address with no language given.
    $ck = $_COOKIE['elang'] ?? '';
    if ($ck !== '') {
        if ($ck !== I18N_BASE && isset($I18N_LANGS[$ck])) { header('Location: ' . $target($ck), true, 302); exit; }
        return;
    }
    $best = i18n_accept_best($I18N_LANGS);
    $set($best);
    if ($best !== I18N_BASE) { header('Location: ' . $target($best), true, 302); exit; }
}

/** The path of the current page without its language prefix, for switcher links. */
function i18n_path(array $langs): string
{
    $p = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
    $codes = implode('|', array_keys($langs));
    $p = preg_replace("#^/($codes)(/|$)#", '/', $p);
    return $p === '' ? '/' : $p;
}

/* The same path but with the query string, for the language switcher. Canonical
   and hreflang take the bare i18n_path(): a query there would breed duplicate
   addresses. The switcher does need it, though — changing language on
   /claim?c=A1B2C3D4 used to lose the code from the sticker. Our own lang= is
   dropped: the language travels in the prefix. */
function i18n_here(string $path): string
{
    parse_str((string)parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_QUERY), $q);
    unset($q['lang']);
    return $q ? $path . '?' . http_build_query($q) : $path;
}

/** The address of this same page in another language. */
function i18n_href(string $code, string $path): string
{
    // The base language sits on the bare address. The trailing slash is kept:
    // /guide/ → /ru/guide/, without it the path hits a directory (DirectorySlash
    // Off) and returns 403.
    if ($code === I18N_BASE) return $path;
    return $path === '/' ? "/$code" : '/' . $code . $path;
}

/** The languages that can actually be shown: the base one plus those whose
    dictionary is filled in. An empty dictionary stub is not a language — it would
    serve English text under someone else's code, and the switcher would be lying
    to the reader. */
function i18n_available(array $langs): array
{
    // Completeness is measured against the largest dictionary. A partially
    // translated language must not be offered: the page would come out as a
    // mixture of two.
    $sizes = [];
    foreach ($langs as $code => $name) {
        if ($code !== I18N_BASE) $sizes[$code] = count(i18n_map($code));
    }
    $full = $sizes ? max($sizes) : 0;
    $out  = [];
    foreach ($langs as $code => $name) {
        if ($code === I18N_BASE || ($full && $sizes[$code] >= $full * 0.95)) $out[$code] = $name;
    }
    return $out;
}

/* Extra dictionaries for heavy sections. The documentation alone runs to nearly
   fifteen hundred strings per language, and keeping them in the common dictionary
   would load them on EVERY request to any page. So a section declares its own
   set: i18n_use('docs') before i18n_begin(). */
$I18N_SETS = [];
function i18n_use(string $set): void
{
    if (!in_array($set, $GLOBALS['I18N_SETS'], true)) $GLOBALS['I18N_SETS'][] = $set;
}

/** A language's dictionary. The base language has none: the sources are already
    written in it. An empty dictionary means the page stays in the base language. */
function i18n_map(string $lang): array
{
    if ($lang === I18N_BASE) return [];
    $load = function (string $path): array {
        if (!is_file($path)) return [];
        $m = require $path;
        return is_array($m) ? $m : [];
    };
    $m = $load(__DIR__ . "/../lang/$lang.php");
    foreach ($GLOBALS['I18N_SETS'] ?? [] as $set) {
        $m += $load(__DIR__ . "/../lang/$set/$lang.php");
    }
    return $m;
}

/* Translation of a single string. Needed where the output-buffer translator
   cannot reach: strings inside <script>, message bodies, JSON responses. The
   dictionary is cached so the file is not read on every call. */
function i18n_t(string $s): string
{
    global $LANG;
    static $map = null, $for = null;
    if ($for !== $LANG) { $map = i18n_map($LANG); $for = $LANG; }
    return $map[$s] ?? $s;
}

/* Translation happens on WHOLE fragments: the text between tags and the values
   of textual attributes. A substring replacement over the entire HTML is out of
   the question — a short key mangles words and markup: a short "Guide" would be
   swapped inside "Guide to settings", and a short word once turned the middle of
   a longer one into a translation. Matching ignores the surrounding whitespace
   but keeps it in place. */
function i18n_translate(string $html): string
{
    global $LANG;
    $html = str_replace('<html lang="en"', '<html lang="' . $LANG . '"', $html);
    $map = i18n_map($LANG);            // empty for the base language: nothing to translate
    if (!$map) return i18n_prefix_links($html);

    $html = preg_replace_callback('/>(\s*)([^<>]*?)(\s*)</s', function ($m) use ($map) {
        return isset($map[$m[2]]) ? '>' . $m[1] . $map[$m[2]] . $m[3] . '<' : $m[0];
    }, $html);

    $html = preg_replace_callback(
        '/\b(content|title|alt|placeholder|aria-label)="([^"]*)"/',
        function ($m) use ($map) {
            $t = trim($m[2]);
            return isset($map[$t]) ? $m[1] . '="' . htmlspecialchars($map[$t], ENT_QUOTES) . '"' : $m[0];
        },
        $html
    );

    return i18n_prefix_links($html);
}

/* Internal links on a translated page must lead to the same language:
   href="/webhook" → href="/ru/webhook". Without this every click sent the reader
   back to the English version. Assets, /api/ and anything with a file extension
   are left alone: they have no language version. */
function i18n_prefix_links(string $html): string
{
    global $LANG, $I18N_LANGS;
    if ($LANG === I18N_BASE) return $html;   // the base language lives without a prefix
    $skipDirs = '#^/(api|adm|admin|assets|fonts|img|images|pic|uploads|sound)#i';
    $langs    = implode('|', array_keys($I18N_LANGS));

    // data-lang marks the switcher's own links: their address is already built by
    // i18n_href, and a prefix would break the way back to the base language,
    // turning "/" into "/de".
    return preg_replace_callback('/(data-lang\s+)?\b(href|action)="(\/[^"]*)"/', function ($m) use ($LANG, $langs, $skipDirs) {
        if ($m[1] !== '') return $m[0];
        $p = $m[3];
        if (strpos($p, '//') === 0) return $m[0];                       // protocol-relative
        if (preg_match("#^/($langs)(/|$|\#|\?)#", $p)) return $m[0];     // already carries a language
        if (preg_match($skipDirs, $p)) return $m[0];
        // The guest browser client is a separate application with its own runtime
        // localisation: it needs no prefix, and the language goes as a parameter,
        // otherwise it resets.
        if (preg_match('#^/app(/|$)#', $p)) {
            return $m[2] . '="' . $p . (strpos($p, '?') === false ? '?' : '&') . 'lang=' . $LANG . '"';
        }
        $path = explode('#', explode('?', $p, 2)[0], 2)[0];
        if (strpos(basename($path), '.') !== false) return $m[0];       // a file, not a page
        $rest = $p === '/' ? '' : $p;
        return $m[2] . '="/' . $LANG . $rest . '"';
    }, $html);
}

$LANG      = i18n_lang($I18N_LANGS);
$I18N_PATH = i18n_path($I18N_LANGS);
$I18N_HERE = i18n_here($I18N_PATH);   // the path with its query, for the language switcher
$I18N_LANGS = i18n_available($I18N_LANGS);   // only finished languages appear in the interface

// A language was asked for that has no translation: send the reader to the base
// one, so English text does not sit under someone else's code and search engines
// do not collect duplicates.
if (!isset($I18N_LANGS[$LANG]) && PHP_SAPI !== 'cli') {
    header('Location: ' . i18n_href(I18N_BASE, $I18N_PATH), true, 301);
    exit;
}

/* Turns on output processing: text translation and link prefixes. Everyone needs
   it — a translated language for the text, the base language at least for the link
   prefixes. ONLY head.php calls it, that is, the page that prints the whole
   document. The header and footer must not: they render into a nested buffer (the
   landing page collects them with ob_get_clean), and an extra buffer scrambles the
   output order — the header used to end up at the bottom of the page. */
function i18n_begin(): void
{
    static $started = false;
    if ($started) return;
    $started = true;
    ob_start('i18n_translate');
}
