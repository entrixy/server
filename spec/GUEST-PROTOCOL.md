# Entrixy guest protocol, version 1

This describes what a client must do to act as a guest: to fetch what it is
allowed to open, to hold a live connection, and to open. It is written so that
another implementation can be built from it alone, and it carries test vectors
so that such an implementation can be checked step by step.

The suite in this document is `v1`. Its name appears inside every signature and
every ciphertext, so a future suite cannot be mistaken for this one, and cannot
be swapped for it in transit either — see "Crypto suites" below.

## What the server knows and what it does not

A guest key is a random string. It lives in the link the owner hands over, in
the fragment after `#`, which browsers never send anywhere. The server never
receives that string: not when the key is issued, not when it is used.

What the server stores for each key is its fingerprint — `sha256(user_key)`,
used to find the row — and the public half of a signing pair. The private half
is derived on the device from the key itself and never leaves it.

That is the whole point of the design: whoever runs the server cannot open a
gate with what the server holds.

## Deriving the signing pair

    seed    = HKDF-SHA256(ikm = utf8(user_key), salt = empty, info = "entrixy-guest-sign-v1", 32 bytes)
    keypair = Ed25519 from seed
    key_id  = hex(sha256(utf8(user_key)))

`key_id` identifies the key to the server. It cannot open anything.

## Signing a request

Requests are ordinary JSON over HTTPS. The signature travels in headers, not in
the body — it covers the body, so it cannot sit inside it.

    X-Entrixy-Key    key_id
    X-Entrixy-Ts     unix seconds, accepted within 300 seconds of server time
    X-Entrixy-Nonce  16 to 32 random bytes, hex; accepted once per key
    X-Entrixy-Sig    base64 of the Ed25519 signature
    X-Entrixy-Suite  suite name; may be omitted, and then means "v1"

The signed material is one line:

    <suite>.<key_id>.<ts>.<nonce>.<endpoint>.<hex sha256 of the raw request body>

`endpoint` is the script name without `.php` and without a query string, for
example `key_bundle` or `key_delegate`. Including it means a signature taken
from one call cannot be replayed against another.

The server refuses a request when the timestamp is outside the window, when the
nonce was used before, when the signature does not verify, when the key has no
public half stored, when the suite is one the server does not know, or when the
suite is not the one this key was issued under.

## Crypto suites

A suite is one line of choices: how a key is derived, what encrypts, what
signs. `v1` is:

    kdf   HKDF-SHA256
    aead  AES-256-GCM, 12-byte nonce, 16-byte tag
    sign  Ed25519

The name of the suite is carried in three places, and always first: before the
colon in a ciphertext (`v1:<base64url …>`), as the first field of signed
material, and in the `X-Entrixy-Suite` header (or the `suite` field of the
websocket greeting). A decoder reads the name before anything else and refuses
a name it does not know, rather than guessing at the bytes behind it.

Because the name sits inside the signed material, it cannot be rewritten in
transit: change the header and the signature stops matching. And a key is bound
to the suite it was issued under, so a key issued under a strong suite cannot be
presented under a weaker one later.

A client asks what a server speaks before it starts:

    GET /api/meta.php
    { "protocol": { "suites": ["v1"], "preferred": "v1", "detail": { … } },
      "features": { "websocket": true, "delegation": true, "access_code": false } }

The client picks the first of its own suites, in its own order of preference,
that the server also lists, and refuses to go on when the lists do not
intersect. A server that does not answer this call at all is treated as `v1`.

When a key is issued (`key_create`, and `key_delegate` on redemption) the
issuing client names the suite in a `suite` field alongside `key_hash` and
`sign_pub`. Keys issued earlier, with no name given, are `v1`.

## The live connection

The websocket carries no headers, so the guest's greeting carries the same
fields inside the message, and signs the fingerprint of the device instead of a
body:

    { "type": "guest_hello", "key_id": …, "ts": …, "nonce": …, "sig": …,
       "device_fp": …, "client": "app" | "web" }

    material = v1.<key_id>.<ts>.<nonce>.guest_hello.<hex sha256 of device_fp>

A greeting overheard on the wire is useless elsewhere: it is bound to that
device fingerprint and its nonce is spent.

## Issuing a key

The owner's device generates the key, derives the pair, and sends the server
only what it needs:

    POST /api/key_create.php
    { "device_id": …, "device_secret": …, "key_hash": <key_id>,
       "sign_pub": <base64url of the 32-byte public half>, … }

The response carries no key: the server has never seen one. Passing a key down
a chain works the same way — the recipient generates their own key and sends
`key_hash` and `sign_pub` when redeeming an invitation.

## What a guest calls

    key_bundle     the encrypted bundle: object keys, welcome text, templates
    key_bind       binds the key to this device on first use
    key_validate   whether the key is alive, and whether it is the caller's own
    message_ack    delivery and read receipts
    guest_call     opens an object that the owner's phone dials
    key_delegate   create, list and cancel invitations (a=create|list|cancel)

All of them are signed as described above. `key_delegate?a=info` and
`a=redeem` are open: the caller does not hold a key yet.

## Contents of the bundle

The bundle is encrypted with K_guest, the second half of the link:

    v1:<base64url( nonce(12) || ciphertext || tag(16) )>      AES-256-GCM

Inside it, `obj_keys` maps an object id to the key of that object, `welcome` is
the owner's greeting, `templates` are automation rules. Object data itself —
name, phone number, radius — is a separate blob of the same shape, encrypted
with the object key.

## Settling on a device

A key lives on exactly one handset: the first one that uses it. Until this
version that rule was a string comparison on the server — a fingerprint stored
next to the key — which means it held only as far as the server was willing to
hold it.

Now the handset proves it. On binding, the client derives a second pair from
the key and the device's own fingerprint:

    seed_device = HKDF-SHA256(ikm = utf8(user_key), salt = utf8(device_fp),
                              info = "entrixy-guest-device-v1", 32 bytes)

and sends the public half with the binding request, which is still signed by
the pair derived from the link:

    POST key_bind   { "device_fp": …, "device_pub": base64url(32 bytes) }
    → { "ok": 1, "bound": "new" | "same", "device_key": true }

From the moment the server stores `device_pub`, every signature on that key —
requests and the websocket greeting alike — is checked against it, and the pair
derived from the link is refused everywhere. A copy of the link that surfaces
later opens nothing.

Nothing is stored for this: the pair is derived again from the key and the
hardware fingerprint, so a reinstall on the same handset produces the same pair
and binding answers `same`. Another handset produces a different pair, and the
key does not travel to it — the answer is `needs_new_key`, and the owner issues
a fresh key rather than the server being talked into a move. That answer is
given only to a caller whose signature matches the pair derived from the link,
so it tells nothing to anyone who does not already hold it.

A client that cannot keep a pair of its own — a page in a browser, say — sends
no `device_pub`, and the key goes on being checked against the link. The rule
is per key, not per server: a key settles the first time a client that can do
this uses it.

## Changing an object key

An object key is long-lived, and one day it has to change: a guest is revoked
and their copy of the key stays with them. From the moment it changes, that
copy reads only what was encrypted before it.

The owner drives the change, and the server never learns anything new:

1. The owner reads the object's record with the current key, generates a new
   one, re-encrypts the record and sends it back. The key it replaces is kept
   as the previous generation.
2. Every key that still holds the object gets a fresh bundle. The revoked one
   does not.

The bundle therefore carries two more fields next to `obj_keys`: `obj_epoch`,
which counts the generation per object, and `obj_keys_prev`, the generation
before it. A reader tries the current key first and the previous one after, and
a record either opens or it does not — the ciphertext authenticates itself, so
there is no guessing. The previous generation covers the gap between the record
being re-encrypted and a bundle arriving; nothing older than one step is kept.

The cost is one small write per remaining key, and it is paid by the owner's
phone, not by the guest. A guest that was offline through the whole thing
fetches its bundle on the next start and never notices.

## Test vectors

Every value below was produced by the reference implementation and verified by
a second one.

    user_key         TESTvector_userkey_0123456789abc
    seed             b7752d2b05e8ed1a850a7b9451b23cd9c88da0b1b805285faaf2143981509e98
    sign_pub (hex)   17bd4b4ebc02752dd74c05091bb5fe5427480465bfd35237a2f0678d1162633b
    sign_pub (b64url)F71LTrwCdS3XTAUJG7X-VCdIBGW_01I3ovBnjRFiYzs
    key_id           986a908ef63f57ab606977ba7d76248d7dff01d48d627efa95479b0ba3df6af5

A signed request:

    ts               1790000000
    nonce            0123456789abcdef0123456789abcdef
    endpoint         key_bind
    body             {"device_fp":"aaaa"}
    material         v1.986a908ef63f57ab606977ba7d76248d7dff01d48d627efa95479b0ba3df6af5.1790000000.0123456789abcdef0123456789abcdef.key_bind.6de43f3094fca1abcd581340d6ee48bc78921af3892ae68b556d9f626e204872
    signature        4+ACUxMQ/AcN3hhR+1rFCfJf15RY0BAlEVmIywIaNtCFX9yJkehSUL6elkpwI88PdMk2MRrJbxpMPN+HTYgRCQ==

The pair a handset settles with, from the same test key:

    device_fp        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    seed_device      9998e85347cd2912f16bb2bcb91e3c3f767494a7b9da30f16cee9b0ca448ed31
    device_pub (hex) eb9c44b8a3ee79f166fb9c72546818e32d4ed8de1537f2fa555ebfdbd4610186
    device_pub (b64) 65xEuKPuefFm-5xyVGgY4y1O2N4VN_L6VV6_29RhAYY

A signed greeting:

    device_fp        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    material         v1.986a908ef63f57ab606977ba7d76248d7dff01d48d627efa95479b0ba3df6af5.1790000000.0123456789abcdef0123456789abcdef.guest_hello.ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb
    signature        DmigCW653zJ4m21WunRKBM66EsCEz4VavQAuBOqe73jivdzfsvKnAVAC9L7b5t4OtxXGlbolHfwPyyWeo46BCw==

## Conformance

An implementation conforms when it derives the same `seed`, `sign_pub` and
`key_id` from the test key; produces the two signatures above byte for byte
from the given timestamps and nonces; refuses to send the key string anywhere;
uses a fresh nonce per request; and treats a missing or invalid signature as a
failure rather than falling back to anything else.

## Known limits of this version

The signing pair is derived from the key, so until the key settles on a device
anyone holding the link holds the pair: the signature proves possession of the
key, not of a particular handset. After it settles, the opposite holds — see
"Settling on a device" — but a key used only from a browser never settles.

There is no forward secrecy: a leaked link opens past bundles as well as future
ones. Changing an object key limits what an old copy can read from that point
on, but it does not reach back.
