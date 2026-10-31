<?php
/**
 * The footer for a self-hosted installation.
 *
 * A footer normally carries a site map and legal pages. All of that belongs to a
 * service, not to a server someone raised for themselves. What stays is a line
 * saying what the page runs on and a link to the project — no menu, and no
 * promises made on someone else's behalf.
 */
$sourceUrl = getenv('ENTRIXY_SOURCE_URL') ?: 'https://github.com/entrixy/server';
if (!filter_var($sourceUrl, FILTER_VALIDATE_URL) || !in_array(parse_url($sourceUrl, PHP_URL_SCHEME), ['http', 'https'], true)) {
    $sourceUrl = 'https://github.com/entrixy/server';
}
?>
<footer class="sf-wrap">
  <span><?= i18n_t('Powered by Entrixy') ?></span>
  · <a href="<?= htmlspecialchars($sourceUrl, ENT_QUOTES, 'UTF-8') ?>" rel="noopener">Source code</a>
  · <a href="/licenses/index.php">Software licenses</a>
</footer>
<style <?= csp_nonce_attr() ?>>
  .sf-wrap{padding:28px 16px;text-align:center;font-size:13px;color:rgba(30,31,41,.5)}
</style>
