<?php
/* The shared document head. Before including it you may set:
     $pageTitle, $pageDesc, $pageCanonical, $bodyClass.
   Assets use absolute paths so the partial works at any nesting depth. */
require_once __DIR__ . '/i18n.php';
// A single-language landing page: the language is fixed, with no automatic
// routing and no hreflang, and the switcher is hidden. The page sets this.
// require head.php: $GLOBALS['seoStandalone']=true; $GLOBALS['seoLang']='ru'.
if (!empty($GLOBALS['seoStandalone'])) {
    $LANG = $GLOBALS['seoLang'] ?? 'ru';
    $navLangCode = $LANG;
    $GLOBALS['hideLangSwitch'] = true;
} else {
    i18n_autoroute();   // first visit: language from the browser locale, remembered in a cookie
}
i18n_begin();   // translate the output and prefix internal links
$pageTitle     = $pageTitle     ?? 'Entrixy — open barriers, gates, locks and intercoms';
$pageDesc      = $pageDesc      ?? 'Access control from your phone: open barriers, gates, locks and intercoms automatically.';
$pageCanonical = $pageCanonical ?? null;
$bodyClass     = $bodyClass     ?? 'bg-white';
?><!doctype html>
<html lang="en" data-force-theme="light" class="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<meta name="theme-color" content="#0a1230">
<title><?= htmlspecialchars($pageTitle) ?></title>
<meta name="description" content="<?= htmlspecialchars($pageDesc) ?>">
<?php
/* The canonical address carries the prefix of the current language; the others
   are declared with hreflang so a search engine does not treat them as
   duplicates. */
if ($pageCanonical):
  // The server's own address rather than a hardcoded domain: on a self-hosted
  // installation the canonical page must be its own.
  $origin = function_exists('site_url') ? site_url('') : 'https://entrixy.com';
  $canon = (!empty($GLOBALS['seoStandalone']) || $LANG === I18N_BASE) ? $pageCanonical : $origin . i18n_href($LANG, $I18N_PATH);
?>
<link rel="canonical" href="<?= htmlspecialchars($canon) ?>">
<meta property="og:url" content="<?= htmlspecialchars($canon) ?>">
<?php if (empty($GLOBALS['seoStandalone'])): ?>
<?php foreach ($I18N_LANGS as $langCode => $name): ?>
<link rel="alternate" hreflang="<?= $langCode ?>" href="<?= htmlspecialchars($origin . i18n_href($langCode, $I18N_PATH)) ?>">
<?php endforeach; ?>
<link rel="alternate" hreflang="x-default" href="<?= htmlspecialchars($origin . $I18N_PATH) ?>">
<?php endif; ?>
<?php endif; ?>
<meta property="og:type" content="website">
<meta property="og:site_name" content="Entrixy">
<meta property="og:title" content="<?= htmlspecialchars($pageTitle) ?>">
<meta property="og:description" content="<?= htmlspecialchars($pageDesc) ?>">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/png" sizes="192x192" href="/favicon.png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="stylesheet" href="/fonts/inter-tight.css">
<link rel="stylesheet" href="/assets.css">
<script <?= csp_nonce_attr() ?>>
  // Libraries insert <style> elements at runtime with no nonce, and the content
  // security policy cuts them off. We stamp a nonce onto such styles as they are
  // inserted. STYLE only: scripts are left alone, so nothing blesses an injection.
  (function(){
    var n = document.currentScript && document.currentScript.nonce;
    if(!n) return;
    ["appendChild","insertBefore"].forEach(function(m){
      var orig = Node.prototype[m];
      Node.prototype[m] = function(el){
        if(el && el.tagName==="STYLE" && !el.nonce) el.setAttribute("nonce", n);
        return orig.apply(this, arguments);
      };
    });
  })();
  (function(){
    function show(){document.documentElement.classList.add('ns-ready');}
    if(document.readyState==='complete'){show();}
    else{window.addEventListener('load',show);
         document.addEventListener('DOMContentLoaded',function(){
           if(getComputedStyle(document.body).backgroundColor){show();}
         });}
  })();
</script>
<style <?= csp_nonce_attr() ?>>
  /* A deep blue gradient for the hero. */
  .hero-bg {
    background-color: #0a1230;
    background-image:
      radial-gradient(1500px 900px at 50% 45%, rgba(110,160,255,.13), transparent 70%),
      linear-gradient(180deg, #0d183a 0%, #0a1230 70%, #060c20 100%);
  }
  /* Warm gold with a gradient. */
  .gold-bg {
    background-color: #F5EFD8;
    background-image:
      radial-gradient(900px 400px at 20% 0%, rgba(180,190,210,.14), transparent 60%),
      radial-gradient(700px 500px at 85% 30%, rgba(255,250,225,.45), transparent 65%),
      radial-gradient(800px 600px at 30% 90%, rgba(230,218,180,.28), transparent 70%),
      linear-gradient(180deg, #ECE5CD 0%, #F5EFD8 30%, #F8F2DD 70%, #EEE7CD 100%);
  }
  @media (max-width: 1279px) {
    #lang-dropdown.mobile-open {
      display: block !important; opacity: 1 !important; visibility: visible !important;
      pointer-events: auto !important; transform: translateY(0) !important;
    }
    #lang-nav-item .nav-arrow { transform: rotate(0deg) !important; transition: transform .25s ease; }
    #lang-nav-item.mobile-open .nav-arrow { transform: rotate(180deg) !important; }
  }
</style>
</head>
<body class="<?= htmlspecialchars($bodyClass) ?>">
