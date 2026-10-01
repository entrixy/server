<?php
/**
 * Where a passed-on key lands: /i/<code>.
 * The link is sent not by the object's owner but by a guest whom the owner allowed
 * to pass access on. Here a person sees what is being offered and opens the key
 * in the app, where it is born on their own device.
 */
require __DIR__ . '/_config.php';
require_once __DIR__ . '/lib/account.php';   // site_url(): this server's own address

$code = substr(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_GET['code'] ?? '')), 0, 22);

$state = 'not_found'; $objects = 0; $depth = 0;
if ($code !== '') {
    // One link may carry several parts — objects from keys of different owners.
    // The recipient sees them as one key, so the page sums them up.
    // The link lives until the one who passed it deletes it: an accepted part
    // whose key is still alive opens again on the same handset.
    $st = db()->prepare('SELECT k.status, k.number_ids, k.ble_ids, k.depth, k.expires_at, uk.id AS alive
                           FROM key_invites k LEFT JOIN user_keys uk ON uk.id = k.child_key_id
                          WHERE k.grp = ?');
    $st->execute([$code]);
    $seen = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $inv) {
        $s = $inv['status'];
        if ($s === 'redeemed') $s = $inv['alive'] ? 'new' : 'cancelled';
        elseif ($s === 'new' && strtotime($inv['expires_at']) < time()) $s = 'expired';
        $seen[] = $s;
        foreach ([$inv['number_ids'], $inv['ble_ids']] as $list) {
            foreach (explode(',', (string)$list) as $x) if ((int)$x > 0) $objects++;
        }
        $depth = max($depth, (int)$inv['depth']);
    }
    if ($seen) $state = in_array('new', $seen, true) ? 'new' : $seen[0];
}

$pageTitle     = 'Someone passed you a key — Entrixy';
$pageDesc      = 'Someone passed you a key. Open it in the app: the key is created on your phone.';
$pageCanonical = site_url('/i');
require __DIR__ . '/partials/head.php';
?>
<style <?= csp_nonce_attr() ?>>
  .og-wrap{max-width:560px;margin:0 auto;padding:40px 20px 60px}
  .og-card{background:#fff;border-radius:20px;box-shadow:0 0 0 1px #ebecef,0 1px 3px rgba(16,20,40,.05);padding:30px 30px 34px}
  .og-sub{color:#6b7280;font-size:14.5px;line-height:1.6;margin:0}
  .og-steps{counter-reset:s;margin:20px 0 0;padding:0;list-style:none}
  .og-steps li{position:relative;padding:0 0 14px 38px;font-size:14.5px;color:#374151;line-height:1.5}
  .og-steps li:before{counter-increment:s;content:counter(s);position:absolute;left:0;top:-1px;width:25px;height:25px;border-radius:50%;background:#eef3ff;color:#1a3fa0;font-size:12.5px;font-weight:700;display:flex;align-items:center;justify-content:center}
  .og-btn{display:block;width:100%;margin-top:14px;padding:14px;border-radius:11px;background:#1e1f29;color:#fff;font-size:15px;font-weight:600;text-decoration:none;text-align:center;box-sizing:border-box}
  .og-btn:hover{background:#33343f}
  .og-btn.ghost{background:#fff;color:#1e1f29;border:1px solid #dfe1e6}
  .og-btn.ghost:hover{background:#f6f7f9}
  .og-note{background:#f4f7ff;border:1px solid #dde6fb;border-radius:12px;padding:14px 16px;margin-top:18px;font-size:13.5px;color:#2a3f5f;line-height:1.55}
</style>
<?php require __DIR__ . '/partials/header.php'; ?>

<main>
<section class="pt-46 md:pt-[204px] hero-bg relative z-0 overflow-hidden pb-10 md:pb-16">
  <div class="main-container relative z-30 text-center">
    <h1 class="text-white font-medium mb-3 text-heading-4 sm:text-heading-3 md:text-heading-3 leading-[1.1] max-w-[680px] mx-auto">You have been passed a key</h1>
    <p class="cfg-sub max-w-[560px] mx-auto text-tagline-1 font-light">Open it in the app: the key is created on your phone and works only there.</p>
  </div>
</section>

<div class="og-wrap">
  <div class="og-card">
<?php if ($state === 'new'): ?>
    <p class="og-sub">Objects in the key: <strong><?= (int)$objects ?></strong></p>
    <ol class="og-steps">
      <li>Install the app if you do not have it yet.</li>
      <li>Open the key in the app: your phone creates it itself, nothing is copied or forwarded.</li>
      <li>The objects appear in your list as soon as the owner confirms the key.</li>
    </ol>
    <a class="og-btn" id="og-open" href="entrixy://invite?code=<?= rawurlencode($code) ?>&amp;h=<?= rawurlencode(site_host()) ?>">Open in the app</a>
    <script <?= csp_nonce_attr() ?>>
      // The key to the first message lives after # and never reaches the server;
      // the app needs it, so it goes along.
      (function(){var h=location.hash.slice(1),a=document.getElementById('og-open');
        if(h&&/^[A-Za-z0-9_-]+$/.test(h))a.href+='&w='+h;})();
    </script>
    <a class="og-btn ghost" href="https://entrixy.com/download/android">Install the app</a>
    <a class="og-btn ghost" id="og-web" href="https://entrixy.com/app/#i=<?= rawurlencode($code) ?>&amp;h=<?= rawurlencode(site_host()) ?>">Open in the browser</a>
    <script <?= csp_nonce_attr() ?>>
      // Браузер принимает ключ сам; ключ к первому сообщению — из якоря.
      (function(){var h=location.hash.slice(1),a=document.getElementById('og-web');
        if(h&&/^[A-Za-z0-9_-]+$/.test(h))a.href+='&w='+h;})();
    </script>
    <?php if ($depth > 0): ?>
    <div class="og-note">You may pass this key on to others.</div>
    <?php else: ?>
    <div class="og-note">This key is for you alone: it cannot be passed on.</div>
    <?php endif; ?>
<?php elseif ($state === 'expired' || $state === 'cancelled'): ?>
    <p class="og-sub">This key is no longer valid. Ask whoever sent it for a new link.</p>
<?php else: ?>
    <p class="og-sub">This link is not valid. Check that the address was copied in full, or ask for a new one.</p>
<?php endif; ?>
  </div>
</div>
</main>

<?php require __DIR__ . '/partials/footer.php'; require __DIR__ . '/partials/scripts.php'; ?>
