<?php
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Software licenses — Entrixy server</title>
<style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 16px}pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin:24px 0}</style>
<h1>Software licenses</h1>
<p>Original server code is licensed under AGPL-3.0. Third-party components retain their own licenses and copyright notices.</p>
<?php foreach (glob(__DIR__ . '/*.txt') as $file): ?>
<details><summary><?= htmlspecialchars(basename($file), ENT_QUOTES, 'UTF-8') ?></summary>
<pre><?= htmlspecialchars(file_get_contents($file), ENT_QUOTES, 'UTF-8') ?></pre></details>
<?php endforeach; ?>
</html>
