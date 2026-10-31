<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
// Isolated signature checks: no configuration, network or production database.
require __DIR__ . '/../dist/lib/guest_auth.php';
class AuthTestStatement extends PDOStatement {
    private string $query;
    public function __construct(string $query) { $this->query = $query; }
    public function execute(?array $params = null): bool {
        if (str_starts_with($this->query, 'INSERT INTO guest_nonces')) {
            $nonce = implode(':', $params);
            if (isset(AuthTestDb::$nonces[$nonce])) throw new RuntimeException('duplicate');
            AuthTestDb::$nonces[$nonce] = true;
        }
        return true;
    }
    public function fetch(int $mode = PDO::FETCH_DEFAULT, int $cursorOrientation = PDO::FETCH_ORI_NEXT, int $cursorOffset = 0): mixed { return AuthTestDb::$row; }
}
class AuthTestDb extends PDO {
    public static array $row = [];
    public static array $nonces = [];
    public function __construct() {}
    public function prepare(string $query, array $options = []): PDOStatement|false { return new AuthTestStatement($query); }
}
function db(): PDO { static $db; return $db ??= new AuthTestDb(); }
function check(bool $ok, string $label): void { if (!$ok) throw new RuntimeException($label); echo "PASS $label\n"; }
$link = sodium_crypto_sign_seed_keypair(str_repeat('a', 32));
$device = sodium_crypto_sign_seed_keypair(str_repeat('b', 32));
AuthTestDb::$row = ['id'=>1,'sign_pub'=>sodium_crypto_sign_publickey($link),'sign_suite'=>'v1','bound_device_fp'=>null,'sign_pub_device'=>null];
function request(string $pair, string $endpoint = 'key_bundle', string $body = '{}', ?string $nonce = null): array {
    $id = str_repeat('a',64); $ts = (string)time(); $nonce ??= bin2hex(random_bytes(12));
    $_SERVER = ['HTTP_X_ENTRIXY_KEY'=>$id,'HTTP_X_ENTRIXY_TS'=>$ts,'HTTP_X_ENTRIXY_NONCE'=>$nonce,'HTTP_X_ENTRIXY_SUITE'=>'v1',
        'HTTP_X_ENTRIXY_SIG'=>base64_encode(sodium_crypto_sign_detached(guest_sign_material($id,$ts,$nonce,$endpoint,$body),sodium_crypto_sign_secretkey($pair)))];
    $via = null; $row = guest_auth([], $endpoint, $body, $via); return [$row,$via];
}
check(request($link)[0] !== null, 'unbound invitation can fetch bundle');
AuthTestDb::$row['bound_device_fp'] = str_repeat('c',64);
check(request($link)[0] === null, 'legacy binding cannot authorize ordinary request');
check(request($link,'key_bind')[0] !== null, 'legacy binding can migrate through key_bind');
AuthTestDb::$row['sign_pub_device'] = sodium_crypto_sign_publickey($device);
check(request($device)[0] !== null, 'bound device authorizes');
[$row,$via] = request($link); check($row === null && $via === 'link_elsewhere', 'copied invitation is refused after binding');
$nonce = bin2hex(random_bytes(12)); check(request($device,'key_bundle','{}',$nonce)[0] !== null, 'fresh nonce accepted');
check(request($device,'key_bundle','{}',$nonce)[0] === null, 'replayed nonce refused');
request($device); $via = null; check(guest_auth([], 'key_bundle', '{"changed":true}', $via) === null, 'body tampering refused');
request($device); $via = null; check(guest_auth([], 'key_bind', '{}', $via) === null, 'endpoint substitution refused');
request($device); $_SERVER['HTTP_X_ENTRIXY_TS'] = (string)(time()-600); $via=null;
check(guest_auth([], 'key_bundle', '{}', $via) === null, 'expired signature refused');
