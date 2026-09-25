<?php
/**
 * The footer for a self-hosted installation.
 *
 * A footer normally carries a site map and legal pages. All of that belongs to a
 * service, not to a server someone raised for themselves. What stays is a line
 * saying what the page runs on and a link to the project — no menu, and no
 * promises made on someone else's behalf.
 */
?>
<footer class="sf-wrap">
  <span><?= i18n_t('Powered by Entrixy') ?></span>
</footer>
<style <?= csp_nonce_attr() ?>>
  .sf-wrap{padding:28px 16px;text-align:center;font-size:13px;color:rgba(30,31,41,.5)}
</style>
