<?php
// test-format.php — port-parity tests for the PHP validation layer.
// Feeds the same vectors as the e2e suite: valid paste, every rejection path.
require __DIR__ . '/../lib/format.php';
require __DIR__ . '/../lib/ids.php';

$pass = 0; $fail = 0;
function check(string $name, bool $ok) {
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ok  {$name}\n"; }
    else { $fail++; echo "FAIL  {$name}\n"; }
}

function expect_format_error(string $name, callable $fn) {
    try { $fn(); check($name, false); }
    catch (FormatError $e) { check($name, true); }
    catch (Throwable $t) { check($name . ' (wrong exc: ' . get_class($t) . ')', false); }
}

$IV12 = 'AAAAAAAAAAAAAAAA'; // 12 zero bytes, b64url
$WK = b64url_encode(str_repeat('A', 48));
$CT = 'QUJD'; // "ABC"

$goodAdata = [
    'alg' => 'A256GCM', 'kdf' => 'hkdf', 'iter' => 0, 'comp' => 'none',
    'fmt' => 'plaintext', 'bar' => false, 'ivc' => $IV12, 'ivw' => $IV12, 'skdf' => '',
];
$goodPaste = ['v' => 1, 'ct' => $CT, 'wk' => $WK, 'adata' => $goodAdata, 'meta' => ['expire' => '1day']];

// happy paths
try { $clean = validate_paste($goodPaste); check('valid paste passes', $clean['meta']['expire'] === '1day'); }
catch (Throwable $e) { check('valid paste passes (' . $e->getMessage() . ')', false); }

$pb = $goodAdata; $pb['kdf'] = 'pbkdf2-hkdf'; $pb['iter'] = ITER_V1; $pb['skdf'] = b64url_encode(str_repeat('B', 16));
try { validate_paste(['v' => 1, 'ct' => $CT, 'wk' => $WK, 'adata' => $pb, 'meta' => ['expire' => 'never']]); check('pbkdf2 variant passes', true); }
catch (Throwable $e) { check('pbkdf2 variant passes (' . $e->getMessage() . ')', false); }

// rejections
expect_format_error('wrong version', function () use ($goodPaste) {
    validate_paste(array_merge($goodPaste, ['v' => 2]));
});
expect_format_error('missing field', function () use ($CT, $WK, $goodAdata) {
    validate_paste(['v' => 1, 'ct' => $CT, 'wk' => $WK, 'adata' => $goodAdata]);
});
expect_format_error('extra field', function () use ($goodPaste) {
    validate_paste(array_merge($goodPaste, ['hack' => 1]));
});
expect_format_error('bad alg', function () use ($goodPaste, $goodAdata) {
    $a = $goodAdata; $a['alg'] = 'AES-GCM';
    validate_paste(array_merge($goodPaste, ['adata' => $a]));
});
expect_format_error('iter nonzero for hkdf', function () use ($goodPaste, $goodAdata) {
    $a = $goodAdata; $a['iter'] = 310000;
    validate_paste(array_merge($goodPaste, ['adata' => $a]));
});
expect_format_error('iter below min for pbkdf2', function () use ($goodPaste, $goodAdata) {
    $a = $goodAdata; $a['kdf'] = 'pbkdf2-hkdf'; $a['iter'] = 99999; $a['skdf'] = b64url_encode(str_repeat('B', 16));
    validate_paste(array_merge($goodPaste, ['adata' => $a]));
});
expect_format_error('ivc wrong length', function () use ($goodPaste, $goodAdata) {
    $a = $goodAdata; $a['ivc'] = 'AAAA';
    validate_paste(array_merge($goodPaste, ['adata' => $a]));
});
expect_format_error('ivc non-canonical b64', function () use ($goodPaste, $goodAdata) {
    $a = $goodAdata; $a['ivc'] = 'BBBBBBBAAAAA'; // low bits set in final char
    validate_paste(array_merge($goodPaste, ['adata' => $a]));
});
expect_format_error('wk wrong length', function () use ($goodPaste, $goodAdata) {
    validate_paste(array_merge($goodPaste, ['wk' => b64url_encode(str_repeat('A', 32))]));
});
expect_format_error('ct too large', function () use ($goodPaste, $goodAdata) {
    validate_paste(array_merge($goodPaste, ['ct' => str_repeat('A', MAX_CT_B64 + 1)]));
});
expect_format_error('invalid expire', function () use ($goodPaste) {
    validate_paste(array_merge($goodPaste, ['meta' => ['expire' => '1d']]));
});
expect_format_error('created not int', function () use ($goodPaste) {
    validate_paste(array_merge($goodPaste, ['meta' => ['expire' => '1day', 'created' => 'now']]));
});
expect_format_error('prototype key', function () use ($goodPaste) {
    validate_paste(array_merge($goodPaste, ['__proto__' => []]));
});

// base64url canonical-form specifics
check('b64url rejects + char', b64url_decode('QU+J') === null);
check('b64url rejects / char', b64url_decode('QU/J') === null);
check('b64url decodes ABC', b64url_decode('QUJD') === 'ABC');
check('b64url rejects bad length', b64url_decode('A') === null);
check('b64url accepts -_', strlen(b64url_decode('----____')) === 6);

// ids
$id = gen_id('f');
check('file id shape', preg_match('/^f[A-Za-z0-9_-]{22}$/', $id) === 1);
check('parse roundtrip', parse_id($id)['file'] === true);
check('parse rejects wrong prefix', parse_id('x' . substr($id, 1)) === null);
check('parse rejects short', parse_id(substr($id, 0, -1)) === null);

$tok = gen_delete_token();
$dth = hash_token($tok);
check('token verifies', verify_token($tok, $dth));
check('token rejects wrong', verify_token(gen_delete_token(), $dth) === false);
check('token rejects malformed', verify_token('!!!', $dth) === false);

echo "\n{$pass} passed, {$fail} failed\n";
exit($fail > 0 ? 1 : 0);
