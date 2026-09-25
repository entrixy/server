<?php
/**
 * Brings the database up to the schema that came in the archive.
 *
 * The schema in sql/01-schema.sql is always complete and always current. On
 * the very first start MariaDB loads it itself, and never looks there again:
 * the initdb directory only runs against an empty database. So after an
 * update we compare what is in the database with what arrived and add
 * whatever is missing — tables, columns, indexes.
 *
 * We add, but never drop and never reshape: a leftover column from an older
 * version is harmless, while lost data cannot be brought back. If a release
 * needs an existing column reworked, that is stated in the release notes
 * separately.
 */
$host = getenv('DB_HOST') ?: 'db';
$name = getenv('DB_NAME') ?: 'entrixy';
$user = getenv('DB_USER') ?: 'entrixy';
$pass = getenv('DB_PASS') ?: '';
$file = getenv('SCHEMA_FILE') ?: '/app/sql/01-schema.sql';

if (!is_file($file)) { fwrite(STDERR, "schema file not found: $file\n"); exit(0); }

// The database comes up alongside and may not be accepting connections yet.
$db = null;
for ($i = 0; $i < 30; $i++) {
    try {
        $db = new PDO("mysql:host=$host;dbname=$name;charset=utf8mb4", $user, $pass,
                      [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        break;
    } catch (Throwable $e) { sleep(2); }
}
if (!$db) { fwrite(STDERR, "database unreachable, schema not checked\n"); exit(0); }

/* Parse the dump: we care about the table name, its columns and its keys. */
$sql = file_get_contents($file);
preg_match_all('/CREATE TABLE `([a-z_]+)` \((.*?)\n\) ([^;]*);/s', $sql, $m, PREG_SET_ORDER);

$added = 0;
foreach ($m as $t) {
    [$whole, $table, $body, $opts] = $t;

    $have = $db->query("SHOW TABLES LIKE " . $db->quote($table))->fetch();
    if (!$have) {
        $db->exec($whole);
        echo "table $table created\n";
        $added++;
        continue;
    }

    $cols = [];
    foreach ($db->query("SHOW COLUMNS FROM `$table`") as $r) $cols[$r['Field']] = true;
    $keys = [];
    foreach ($db->query("SHOW INDEX FROM `$table`") as $r) $keys[$r['Key_name']] = true;

    $prev = null;                       // so the column lands in its place rather than at the end
    foreach (explode("\n", $body) as $line) {
        $line = rtrim(trim($line), ',');
        if ($line === '') continue;

        if (preg_match('/^`([a-z0-9_]+)` (.+)$/i', $line, $c)) {
            [, $col, $def] = $c;
            if (!isset($cols[$col])) {
                $where = $prev ? "AFTER `$prev`" : 'FIRST';
                $db->exec("ALTER TABLE `$table` ADD COLUMN `$col` $def $where");
                echo "column $table.$col added\n";
                $added++;
            }
            $prev = $col;
            continue;
        }

        if (preg_match('/^(UNIQUE KEY|KEY) `([a-z0-9_]+)` (.+)$/i', $line, $k)) {
            [, $kind, $kn, $rest] = $k;
            if (!isset($keys[$kn])) {
                $db->exec("ALTER TABLE `$table` ADD $kind `$kn` $rest");
                echo "index $table.$kn added\n";
                $added++;
            }
        }
    }
}

echo $added ? "schema updated, changes: $added\n" : "schema is up to date\n";
