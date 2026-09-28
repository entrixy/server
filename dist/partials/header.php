<?php
/**
 * The header for a self-hosted installation.
 *
 * A header normally carries a section menu and a way into an account. A
 * self-hosted server has no such pages, and the menu would turn into a couple of
 * dozen links leading nowhere. So only the name and the logo remain: an
 * invitation page needs nothing else.
 */
?>
<header class="sh-wrap">
  <!-- No link: a self-hosted installation has neither a front page nor a section
       the logo could sensibly lead to. -->
  <span class="sh-logo"><img src="/img/logo-wordmark.svg" alt="Entrixy" height="28"></span>
</header>
<style <?= csp_nonce_attr() ?>>
  .sh-wrap{display:flex;align-items:center;justify-content:center;padding:22px 16px}
  .sh-logo{display:inline-flex;align-items:center;text-decoration:none}
  .sh-logo img{height:28px;width:auto;display:block}
</style>
