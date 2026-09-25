<?php
require_once __DIR__ . '/partials/csp.php';   // nonce + CSP
// The page that receives a guest key. The key arrives in the fragment
// (https://entrixy.com/key#<75-character blob>) and never reaches the server:
// all of the logic is on the client. This is only the static shell.
header('Content-Type: text/html; charset=utf-8');
?><!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<script <?= csp_nonce_attr() ?>>document.documentElement.lang=((localStorage.getItem('gon_lang')||navigator.language||navigator.userLanguage||'').slice(0,2)==='ru')?'ru':'en';</script>
<title>Entrixy</title>
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/png" sizes="192x192" href="/favicon.png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="stylesheet" href="/fonts/inter-tight.css">
<style <?= csp_nonce_attr() ?>>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{font-family:'Inter Tight',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  background:linear-gradient(135deg,#1a56a8 0%,#0e3266 100%);color:#101828;
  min-height:100dvh;display:flex;flex-direction:column;align-items:center;justify-content:flex-start;
  padding:56px 18px 32px;-webkit-font-smoothing:antialiased}
.brand{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:26px}
.brand .brand-icon{width:30px;height:30px;display:block;pointer-events:none}
.brand .brand-word{height:26px;width:auto;display:block}
.card{background:#fff;border-radius:24px;padding:30px 24px;width:100%;max-width:380px;
  box-shadow:0 24px 64px rgba(0,0,0,.35);text-align:center;animation:up .4s cubic-bezier(.34,1.56,.64,1)}
@keyframes up{0%{opacity:0;transform:translateY(20px)}100%{opacity:1;transform:translateY(0)}}
.spin{width:40px;height:40px;margin:20px auto;border:3px solid #e6e9ef;border-top-color:#1a56a8;border-radius:50%;animation:sp .8s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
.eyebrow{font-size:13px;color:#667085;font-weight:500;margin-bottom:6px}
.host{font-size:24px;font-weight:600;letter-spacing:-.02em;margin-bottom:6px;word-break:break-word}
.welcome{font-size:14px;color:#475467;line-height:1.55;margin:12px 0 4px;white-space:pre-wrap;word-break:break-word}
.actions{margin-top:24px;display:flex;flex-direction:column;gap:10px}
.btn{display:block;width:100%;height:50px;border:none;border-radius:999px;font-size:15px;font-weight:600;
  font-family:inherit;cursor:pointer;transition:opacity .2s}
.btn:active{opacity:.85}
.btn-primary{background:#1e1f29;color:#fff}
.btn-second{background:#eef1f6;color:#101828}
.hint{font-size:12px;color:#98a2b3;margin-top:14px;line-height:1.5}
.err{font-size:15px;color:#d92d20;padding:16px 0}
a.home{display:inline-block;margin-top:18px;color:#667085;font-size:13px;text-decoration:none}
</style>
</head>
<body>
<div class="brand">
  <object class="brand-icon" data="/img/logo-mono-animated-white.svg" type="image/svg+xml" aria-label="Entrixy"></object>
  <img class="brand-word" src="/img/logo-wordmark-white.svg" alt="Entrixy">
</div>
<div class="card">
  <div id="loading"><div class="spin"></div></div>

  <div id="content" hidden>
    <div class="eyebrow" id="eyebrow"></div>
    <div class="host" id="host"></div>
    <div class="welcome" id="welcome" hidden></div>
    <div class="actions" id="actions"></div>
    <div class="hint" id="hint" hidden></div>
  </div>

  <div id="error" hidden>
    <div class="err" id="err-text"></div>
    <a class="home" href="/">Entrixy</a>
  </div>
</div>

<script src="/app/crypto.js?v=3"></script>
<script <?= csp_nonce_attr() ?>>
(function () {
  'use strict';
  var browserLang = (navigator.language || '').slice(0, 2);
  var urlLang = new URLSearchParams(location.search).get('lang');
  if (urlLang) localStorage.setItem('gon_lang', urlLang);
  var uiLang = localStorage.getItem('gon_lang') || (['ru','de','es','fr','pt','zh'].indexOf(browserLang) >= 0 ? browserLang : 'en');
  var S = {
    ru: {
      eyebrow: 'Вам передали доступ',
      generic: 'Гостевой ключ Entrixy',
      use_web: 'Открыть в браузере',
      install_pwa: 'Установить как приложение',
      install_app: 'Установить приложение Android',
      copied: 'Ключ скопирован. Установите приложение — оно добавит ключ автоматически.',
      no_key: 'Ссылка не содержит ключа.',
      load_failed: 'Страница не загрузилась полностью. Проверьте связь и откройте ссылку ещё раз.',
      retry: 'Повторить',
      hint_apk: 'Для Android лучше полноценное приложение: в нём можно добавлять собственные объекты, и оно работает в фоне.',
      native_hint: 'Этот ключ работает только в приложении Entrixy для Android — в браузере он не откроется.',
    },
    en: {
      eyebrow: 'You\'ve been granted access',
      generic: 'Entrixy guest key',
      use_web: 'Open in browser',
      install_pwa: 'Install as an app',
      install_app: 'Install the Android app',
      copied: 'Key copied. Install the app — it will add the key automatically.',
      no_key: 'The link does not contain a key.',
      load_failed: 'The page did not load completely. Check your connection and open the link again.',
      retry: 'Retry',
      hint_apk: 'On Android the full app works better: it lets you add your own objects and runs in the background.',
      native_hint: 'This key works only in the Entrixy app for Android — it will not open in a browser.',
    },
    de: {
      eyebrow: 'Ihnen wurde Zugang gegeben',
      generic: 'Entrixy-Gastschlüssel',
      use_web: 'Im Browser öffnen',
      install_pwa: 'Als App installieren',
      install_app: 'Android-App installieren',
      copied: 'Schlüssel kopiert. Installieren Sie die App — sie fügt den Schlüssel automatisch hinzu.',
      no_key: 'Der Link enthält keinen Schlüssel.',
      load_failed: 'Die Seite wurde nicht vollständig geladen. Prüfen Sie die Verbindung und öffnen Sie den Link erneut.',
      retry: 'Erneut versuchen',
      hint_apk: 'Unter Android ist die vollwertige App besser: Sie können eigene Objekte anlegen, und sie läuft im Hintergrund.',
      native_hint: 'Dieser Schlüssel funktioniert nur in der Entrixy-App für Android — im Browser öffnet er nicht.',
    },
    es: {
      eyebrow: 'Te han dado acceso',
      generic: 'Llave de invitado de Entrixy',
      use_web: 'Abrir en el navegador',
      install_pwa: 'Instalar como aplicación',
      install_app: 'Instalar la aplicación de Android',
      copied: 'Llave copiada. Instala la aplicación: añadirá la llave automáticamente.',
      no_key: 'El enlace no contiene ninguna llave.',
      load_failed: 'La página no se cargó por completo. Compruebe la conexión y abra el enlace de nuevo.',
      retry: 'Reintentar',
      hint_apk: 'En Android va mejor la aplicación completa: permite añadir tus propios objetos y funciona en segundo plano.',
      native_hint: 'Esta llave solo funciona en la aplicación Entrixy para Android; en el navegador no se abre.',
    },
    fr: {
      eyebrow: 'On vous a donné accès',
      generic: 'Clé d\'invité Entrixy',
      use_web: 'Ouvrir dans le navigateur',
      install_pwa: 'Installer comme application',
      install_app: 'Installer l\'application Android',
      copied: 'Clé copiée. Installez l\'application — elle ajoutera la clé automatiquement.',
      no_key: 'Le lien ne contient pas de clé.',
      load_failed: 'La page ne s\'est pas chargée entièrement. Vérifiez la connexion et rouvrez le lien.',
      retry: 'Réessayer',
      hint_apk: 'Sur Android, l\'application complète est préférable : elle permet d\'ajouter vos propres objets et tourne en arrière-plan.',
      native_hint: 'Cette clé ne fonctionne que dans l\'application Entrixy pour Android — elle ne s\'ouvrira pas dans un navigateur.',
    },
    pt: {
      eyebrow: 'Deram-lhe acesso',
      generic: 'Chave de convidado Entrixy',
      use_web: 'Abrir no navegador',
      install_pwa: 'Instalar como aplicação',
      install_app: 'Instalar a aplicação Android',
      copied: 'Chave copiada. Instale a aplicação — ela acrescenta a chave automaticamente.',
      no_key: 'A ligação não contém nenhuma chave.',
      load_failed: 'A página não carregou completamente. Verifique a ligação e abra o link novamente.',
      retry: 'Tentar de novo',
      hint_apk: 'No Android a aplicação completa é melhor: permite acrescentar os seus próprios objetos e corre em segundo plano.',
      native_hint: 'Esta chave só funciona na aplicação Entrixy para Android — no navegador não abre.',
    },
    zh: {
      eyebrow: '有人给了您访问权限',
      generic: 'Entrixy 访客密钥',
      use_web: '在浏览器中打开',
      install_pwa: '安装为应用',
      install_app: '安装 Android 应用',
      copied: '密钥已复制。安装应用后，它会自动添加这个密钥。',
      no_key: '该链接里没有密钥。',
      load_failed: '页面未完全加载。请检查网络后重新打开链接。',
      retry: '重试',
      hint_apk: '在 Android 上，完整应用更好用：可以添加自己的对象，还能在后台运行。',
      native_hint: '此密钥只能在 Android 版 Entrixy 应用中使用——浏览器里打不开。',
    },
  };
  var t = S[uiLang] || S.en;

  var ua = navigator.userAgent;
  var isAndroid = /android/i.test(ua);

  var deferredPrompt = null;
  window.addEventListener('beforeinstallprompt', function (e) { e.preventDefault(); deferredPrompt = e; });

  function $(id) { return document.getElementById(id); }

  // Parsing the key lives in an external script. If it did not arrive — no
  // network, or a misconfigured server — the page must say so honestly instead of
  // spinning an indicator forever.
  if (typeof EntrixyCrypto === 'undefined') {
    $('loading').hidden = true;
    $('err-text').textContent = t.load_failed;
    $('error').hidden = false;
    var retry = document.createElement('button');
    retry.className = 'btn btn-primary';
    retry.textContent = t.retry;
    retry.onclick = function () { location.reload(); };
    $('error').appendChild(retry);
    return;
  }

  var parsed = EntrixyCrypto.parseInviteUri(location.href);
  if (!parsed || !parsed.userKey) {
    $('loading').hidden = true;
    $('err-text').textContent = t.no_key;
    $('error').hidden = false;
    return;
  }

  // The address of the browser client. The key travels in the anchor, so it never
  // leaves the device, and beside it goes the server the key belongs to: the page
  // may be served by someone else's server, while the client is always ours.
  function webAppUrl() {
    return 'https://entrixy.com/app/#' + location.hash.replace(/^#/, '')
         + '&h=' + encodeURIComponent(location.host);
  }

  function saveKey() {
    var keys = JSON.parse(localStorage.getItem('gon_keys') || '[]');
    var kb64 = parsed.kGuest ? EntrixyCrypto.b64uEncode(parsed.kGuest) : '';
    var ex = keys.find(function (x) { return x.user_key === parsed.userKey; });
    if (ex) { if (kb64) ex.k_guest_b64 = kb64; }
    else keys.push({ user_key: parsed.userKey, k_guest_b64: kb64 });
    localStorage.setItem('gon_keys', JSON.stringify(keys));
  }

  function mkBtn(label, cls, onClick) {
    var b = document.createElement('button');
    b.className = 'btn ' + cls;
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }
  // Copy the link and send the visitor to the Android installation page: the app
  // picks the key up from the clipboard. We point at /download/android, which
  // explains Play Protect and the steps, rather than at the raw file.
  function downloadApk() {
    var url = location.href;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url);
      else {
        var ta = document.createElement('textarea');
        ta.value = url; document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); ta.remove();
      }
    } catch (e) {}
    $('hint').textContent = t.copied;
    $('hint').hidden = false;
    // Only we distribute the app: another server has no download page, and a
    // tampered client is the worst thing this page guards against. An owner of
    // their own server can change the address here at their own risk.
    setTimeout(function () { location.href = 'https://entrixy.com/download/android'; }, 600);
  }

  // The options depend on whether the key is app-only or ordinary.
  function buildActions(nativeOnly) {
    var acts = $('actions'); acts.innerHTML = '';
    if (nativeOnly) {
      // The only option is the native app; the browser client is not offered.
      acts.appendChild(mkBtn(t.install_app, 'btn-primary', downloadApk));
      $('hint').textContent = t.native_hint;
      $('hint').hidden = false;
      return;
    }
    // The browser client comes from our server as well, carrying the key and the
    // address of the server that key belongs to. An owner who wants to host the
    // client themselves changes the address here to '/app/'.
    acts.appendChild(mkBtn(t.use_web, 'btn-primary', function () { saveKey(); location.href = webAppUrl(); }));
    acts.appendChild(mkBtn(t.install_pwa, 'btn-second', function () {
      saveKey();
      if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt.userChoice.then(function () { location.href = webAppUrl(); }); }
      else { location.href = webAppUrl(); }
    }));
    if (isAndroid) {
      acts.appendChild(mkBtn(t.install_app, 'btn-second', downloadApk));
      $('hint').textContent = t.hint_apk;
      $('hint').hidden = false;
    }
  }

  $('eyebrow').textContent = t.eyebrow;
  $('host').textContent = t.generic;

  // First we learn whether the key is app-only and build the buttons, then fetch
  // the sender separately.
  var revealed = false;
  function reveal() {
    revealed = true;
    $('loading').hidden = true; $('content').hidden = false;
  }
  // The server's answer is needed only to tell whether the browser is allowed. If
  // it does not come, the buttons are shown anyway: the key is already here, in the
  // page address, and the app opens it without any server.
  setTimeout(function () { if (!revealed) { buildActions(false); reveal(); } }, 5000);
  fetch('/api/key_bundle.php', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_key: parsed.userKey })
  }).then(function (r) { return r.json(); }).then(function (d) {
    buildActions(!!(d && d.native_only));
    reveal();
    // The sender's name is best-effort and does not affect the buttons.
    if (parsed.kGuest && d && d.bundle_cipher) {
      EntrixyCrypto.decryptString(parsed.kGuest, d.bundle_cipher).then(function (json) {
        if (!json) return;
        var b = JSON.parse(json);
        if (b.host_label) $('host').textContent = b.host_label;
        if (b.welcome) { $('welcome').textContent = b.welcome; $('welcome').hidden = false; }
      }).catch(function () {});
    }
  }).catch(function () { buildActions(false); reveal(); });
})();
</script>
</body>
</html>
