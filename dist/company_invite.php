<?php
/**
 * Where a company's QR code lands: /c/<code>, and /o/ for the same address in
 * its agreed form.
 * The visitor arrives from a service's own interface — a nanny agency, a cleaning
 * company — having been asked for access to a gate. Here they see WHO is asking
 * and what exactly will happen, install the app and issue a key by picking the
 * company from a list. The key string is never forwarded to anyone.
 */
require __DIR__ . '/_config.php';
require_once __DIR__ . '/lib/account.php';   // site_url(): this server's own address
require_once __DIR__ . '/lib/org.php';   // the human-readable form of a domain

$orgCode = preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_GET['code'] ?? ''));
$orgCode = substr($orgCode, 0, 16);

$org = null; $state = 'not_found';
if ($orgCode !== '') {
    $st = db()->prepare(
        'SELECT r.status, r.expires_at, o.name, o.logo_hash, o.domain, o.pubkey
         FROM org_requests r JOIN orgs o ON o.id = r.org_id
         WHERE r.code = ? AND o.status <> "blocked"'
    );
    $st->execute([$orgCode]);
    $org = $st->fetch(PDO::FETCH_ASSOC);
    if ($org) {
        $state = $org['status'];
        if ($state === 'new' && strtotime($org['expires_at']) < time()) $state = 'expired';
    }
}
$orgName = $org ? $org['name'] : '';
// A domain counts as tied to the company only while it carries the key that
// signs every call; there is no one-off check here.
$orgVerified = $org && !empty($org['domain']) && !empty($org['pubkey']);
$orgDomain = $orgVerified ? org_domain_display($org['domain']) : null;
// A logo is shown only for a company with a confirmed domain: it is the easiest
// thing to fake, and so it hangs on that single check.
$orgLogo = ($orgVerified && $org['logo_hash']) ? '/img/org/' . $org['logo_hash'] . '.png' : null;

$pageTitle     = 'Access request — Entrixy';
$pageDesc      = 'A service is asking for access to your barrier. Decide yourself what to grant and take it back at any time.';
$pageCanonical = site_url('/c');
require __DIR__ . '/partials/head.php';
?>
<style <?= csp_nonce_attr() ?>>
  .og-wrap{max-width:560px;margin:0 auto;padding:40px 20px 60px}
  .og-card{background:#fff;border-radius:20px;box-shadow:0 0 0 1px #ebecef,0 1px 3px rgba(16,20,40,.05);padding:30px 30px 34px}
  .og-org{display:flex;align-items:center;gap:14px;margin-bottom:6px}
  .og-logo{flex:0 0 52px;width:52px;height:52px;border-radius:14px;object-fit:cover;background:#f2f4fa}
  .og-mono{flex:0 0 52px;width:52px;height:52px;border-radius:14px;background:#eef3ff;color:#1a3fa0;font-size:22px;font-weight:700;display:flex;align-items:center;justify-content:center}
  .og-name{font-size:18px;font-weight:600;color:#1e1f29;line-height:1.25}
  .og-dom{display:block;font-size:13px;font-weight:500;color:#1a7f3c;margin-top:2px}
  .og-dom.warn{color:#b26a00}
  .og-sub{color:#6b7280;font-size:14.5px;line-height:1.6;margin:14px 0 0}
  .og-steps{counter-reset:s;margin:20px 0 0;padding:0;list-style:none}
  .og-steps li{position:relative;padding:0 0 14px 38px;font-size:14.5px;color:#374151;line-height:1.5}
  .og-steps li:before{counter-increment:s;content:counter(s);position:absolute;left:0;top:-1px;width:25px;height:25px;border-radius:50%;background:#eef3ff;color:#1a3fa0;font-size:12.5px;font-weight:700;display:flex;align-items:center;justify-content:center}
  .og-btn{display:block;width:100%;margin-top:14px;padding:14px;border-radius:11px;background:#1e1f29;color:#fff;font-size:15px;font-weight:600;text-decoration:none;text-align:center;box-sizing:border-box}
  .og-btn:hover{background:#33343f}
  .og-btn.ghost{background:#fff;color:#1e1f29;border:1px solid #dfe1e6}
  .og-btn.ghost:hover{background:#f6f7f9}
  .og-note{background:#f4f7ff;border:1px solid #dde6fb;border-radius:12px;padding:14px 16px;margin-top:18px;font-size:13.5px;color:#2a3f5f;line-height:1.55}
  .og-note.gray{background:#f6f7f9;border-color:#e7e8ec;color:#4b5563}
  /* The domain must read as a link: colour, underline and an "opens in a new tab"
     mark, or a person will not realise they can go and look. */
  .og-dom-link{display:inline-flex;align-items:center;gap:4px;color:#1a56a8;font-weight:600;text-decoration:underline;text-underline-offset:2px}
  .og-dom-link:hover{color:#123f7d}
  .og-dom-link svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
</style>
<?php require __DIR__ . '/partials/header.php'; ?>

<main>
<section class="pt-46 md:pt-[204px] hero-bg relative z-0 overflow-hidden pb-10 md:pb-16">
  <div class="main-container relative z-30 text-center">
    <h1 class="text-white font-medium mb-3 text-heading-4 sm:text-heading-3 md:text-heading-3 leading-[1.1] max-w-[680px] mx-auto">Access to your barrier</h1>
    <p class="cfg-sub max-w-[560px] mx-auto text-tagline-1 font-light">You decide what to grant, see every opening in the log and take access back in one tap.</p>
  </div>
</section>

<div class="og-wrap">
  <div class="og-card">
<?php if ($state === 'new' || $state === 'claimed'): ?>
    <div class="og-org">
      <?php if ($orgLogo): ?>
        <img class="og-logo" src="<?= htmlspecialchars($orgLogo) ?>" alt="" width="52" height="52">
      <?php else: ?>
        <span class="og-mono"><?= htmlspecialchars(mb_substr($orgName, 0, 1)) ?></span>
      <?php endif; ?>
      <span class="og-name"><?= htmlspecialchars($orgName) ?>
        <?php if ($orgDomain): ?><span class="og-dom"><?= htmlspecialchars($orgDomain) ?></span>
        <?php else: ?><span class="og-dom warn">domain not confirmed</span><?php endif; ?>
      </span>
    </div>
    <div class="og-note <?= $orgDomain ? '' : 'gray' ?>">
      <?php if ($orgDomain): ?>
        <?= sprintf(
          i18n_t('Be sure to check the domain %s against the site of the company you are about to grant access to.'),
          '<a class="og-dom-link" href="https://' . htmlspecialchars($orgDomain) . '" rel="noopener nofollow" target="_blank">'
            . htmlspecialchars($orgDomain)
            . '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4h6v6M20 4l-8 8M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg></a>'
        ) ?>
      <?php else: ?>
        <?= i18n_t('This company has not confirmed a domain — there is only the name it entered. Grant access if you are sure who is asking.') ?>
      <?php endif; ?>
    </div>
    <p class="og-sub">This company is asking for access to your barrier so that its employee can drive in on the day of the visit. Access is granted to the company, not to a particular person, and every opening is recorded in your log with the name of whoever pressed the button.</p>
    <ol class="og-steps">
      <li>Install the app and add your barrier — it takes a couple of minutes.</li>
      <li>Grant access: the company will already be waiting in the list, nothing to copy or forward.</li>
      <li>Take it back whenever you want. The company cannot pass the access on to anyone else.</li>
    </ol>
    <a class="og-btn" href="entrixy://org?code=<?= rawurlencode($orgCode) ?>">Open in the app</a>
    <a class="og-btn ghost" id="ogInstall" href="/download" data-code="<?= htmlspecialchars($orgCode) ?>">Install the app</a>
    <p class="og-sub" id="ogCopied" hidden>The link is copied: after installation the app will pick it up itself, scanning again is not needed.</p>
    <div class="og-note">Your barrier has to open on a call from your number, and your phone has to stay online — the app dials for you at the moment of the request. If your barrier has an Entrixy controller, the phone is not needed at all.</div>
<?php elseif ($state === 'issued'): ?>
    <div class="og-org">
      <?php if ($orgLogo): ?><img class="og-logo" src="<?= htmlspecialchars($orgLogo) ?>" alt="" width="52" height="52"><?php else: ?><span class="og-mono"><?= htmlspecialchars(mb_substr($orgName, 0, 1)) ?></span><?php endif; ?>
      <span class="og-name"><?= htmlspecialchars($orgName) ?></span>
    </div>
    <p class="og-sub">This link has already been used: access for this visit is granted. If it was you, the company is in your app under companies, together with the log of openings — you take the access back there at any time. If the link reached you by chance, ask the company for a new one: each link works once.</p>
    <a class="og-btn" href="entrixy://guests">Open in the app</a>
<?php elseif ($state === 'expired'): ?>
    <p class="og-sub">This request has expired. Ask the company for a new link — it takes them one click.</p>
<?php else: ?>
    <p class="og-sub">This link is not valid. Check that the address was scanned in full, or ask the company for a new one.</p>
<?php endif; ?>
  </div>
</div>
</main>

<script <?= csp_nonce_attr() ?>>
// On the way to install the app the request link is copied to the clipboard: the
// app picks it up at first launch, so nobody has to find it again.
(function () {
  var b = document.getElementById('ogInstall');
  if (!b) return;
  b.addEventListener('click', function () {
    var url = <?= json_encode(site_url('/c/')) ?> + b.dataset.code;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url);
      else {
        var ta = document.createElement('textarea');
        ta.value = url; document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); ta.remove();
      }
      var n = document.getElementById('ogCopied');
      if (n) n.hidden = false;
    } catch (e) {}
  });
})();
</script>

<?php require __DIR__ . '/partials/footer.php'; require __DIR__ . '/partials/scripts.php'; ?>
