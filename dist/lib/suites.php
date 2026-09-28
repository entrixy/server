<?php
/**
 * The registry of crypto suites.
 *
 * A suite is one line of choices: how a key is derived, what encrypts, what
 * signs. The suite is named, and the name comes first: before the colon in a
 * ciphertext, before the first dot in signed material, and in a request
 * header. Parsing always starts with the name, and an unknown name is a
 * refusal rather than an attempt to guess the format.
 *
 * Why: one day a suite has to change — an algorithm ages, forward secrecy
 * arrives. That change must not break what is already issued, so the name
 * lives inside the signed data: rewriting it in transit stops the signature
 * from matching.
 *
 * How to add one: write an entry here, teach signature checking the new
 * algorithm, and issue new keys under the new name. Keys already issued keep
 * working under theirs — both names simply appear in what the server
 * advertises.
 */

const ENTRIXY_SUITES = [
    'v1' => [
        'kdf'   => 'HKDF-SHA256',
        'aead'  => 'AES-256-GCM',
        'sign'  => 'Ed25519',
        'nonce' => 12,
        'tag'   => 16,
    ],
];

/** What we offer to whoever receives a key today. */
const ENTRIXY_SUITE_PREFERRED = 'v1';

function suite_known(string $id): bool
{
    return isset(ENTRIXY_SUITES[$id]);
}

/** The names this server accepts, most preferred first. */
function suite_list(): array
{
    $ids = array_keys(ENTRIXY_SUITES);
    usort($ids, fn($a, $b) => $b <=> $a);
    return $ids;
}

/** The suite name from a ciphertext "v1:…". null when there is none. */
function suite_of_blob(string $blob): ?string
{
    $i = strpos($blob, ':');
    return $i === false ? null : substr($blob, 0, $i);
}
