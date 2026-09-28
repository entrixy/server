<?php
/**
 * Where a chain invitation lands: /i/<code>.
 * The link is sent not by the object's owner but by a guest whom the owner allowed
 * to pass access on. Here a person sees what is being offered and opens the
 * invitation in the app, where the key is born on their own device.
 */
require __DIR__ . '/_config.php';
require_once __DIR__ . '/lib/account.php';   // site_url(): this server's own address

$code = substr(preg_replace('/[^A-Za-z0-9_-]/', '', (string)($_GET['code'] ?? '')), 0, 22);

$state = 'not_found'; $objects = 0; $depth = 0;
if ($code !== '') {
    $st = db()->prepare('SELECT status, number_ids, depth, expires_at FROM key_invites WHERE code = ?');
    $st->execute([$code]);
    if ($inv = $st->fetch(PDO::FETCH_ASSOC)) {
        $state   = $inv['status'];
        $objects = count(explode(',', $inv['number_ids']));
        $depth   = (int)$inv['depth'];
        if ($state === 'new' && strtotime($inv['expires_at']) < time()) $state = 'expired';
    }
}

$pageTitle     = 'Access invitation — Entrixy';
$pageDesc      = 'Someone is passing you access to a barrier. Open the invitation in the app — the key is created on your phone.';
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
    <h1 class="text-white font-medium mb-3 text-heading-4 sm:text-heading-3 md:text-heading-3 leading-[1.1] max-w-[680px] mx-auto">You have been given access</h1>
    <p class="cfg-sub max-w-[560px] mx-auto text-tagline-1 font-light">Open the invitation in the app: the key is created on your phone and works only there.</p>
  </div>
</section>

<div class="og-wrap">
  <div class="og-card">
<?php if ($state === 'new'): ?>
    <p class="og-sub">The invitation opens <?= $objects === 1 ? 'one entrance' : $objects . ' entrances' ?>. The owner of the barrier sees the whole chain of who passed access to whom, and takes it back in one tap — together with everything granted further down.</p>
    <ol class="og-steps">
      <li>Install the app if you do not have it yet.</li>
      <li>Open the invitation: your phone creates the key itself, nothing is copied or forwarded.</li>
      <li>The barrier appears in your list as soon as the owner confirms the key.</li>
    </ol>
    <a class="og-btn" href="entrixy://invite?code=<?= rawurlencode($code) ?>">Open in the app</a>
    <a class="og-btn ghost" href="https://entrixy.com/download/android">Install the app</a>
    <?php if ($depth > 0): ?>
    <div class="og-note">You may pass this access on <?= $depth === 1 ? 'one step further' : $depth . ' steps further' ?>. Everyone you give it to stays visible to the owner by name.</div>
    <?php else: ?>
    <div class="og-note">This access is for you alone: it cannot be passed on any further.</div>
    <?php endif; ?>
<?php elseif ($state === 'redeemed'): ?>
    <p class="og-sub">This invitation has already been used. If the key is not on your phone, ask for a new invitation — it takes one tap.</p>
    <a class="og-btn" href="entrixy://guests">Open in the app</a>
<?php elseif ($state === 'expired' || $state === 'cancelled'): ?>
    <p class="og-sub">The invitation is no longer valid. Ask for a new link from whoever sent you this one.</p>
<?php else: ?>
    <p class="og-sub">This link is not valid. Check that the address was copied in full, or ask for a new one.</p>
<?php endif; ?>
  </div>
</div>
</main>

<?php require __DIR__ . '/partials/footer.php'; require __DIR__ . '/partials/scripts.php'; ?>
