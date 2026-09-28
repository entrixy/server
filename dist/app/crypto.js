/* Entrixy PWA E2EE — WebCrypto AES-256-GCM helpers.
 * Compatible with the format used by the Android client: "v1:<base64url(nonce(12)+ct+tag(16))>".
 * WebCrypto appends the tag to the ciphertext itself; we only base64url the lot.
 *
 * Every key is a Uint8Array(32). The user key and the guest key arrive in the URL
 * fragment and never appear in an HTTP request. The server serves this file, so
 * the trust model is: we trust the code the server hands us.
 */
(function (global) {
  'use strict';

  function b64uEncode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64uDecode(str) {
    if (!str) return new Uint8Array();
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function importAesKey(keyBytes) {
    return crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
  }

  /** Encrypt a string into "v1:<base64url>". */
  async function encryptString(keyBytes, plaintext) {
    const key = await importAesKey(keyBytes);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder().encode(plaintext);
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, enc
    ));
    const out = new Uint8Array(nonce.length + ct.length);
    out.set(nonce, 0); out.set(ct, nonce.length);
    return SUITE + ':' + b64uEncode(out);
  }

  /** Decrypt "v1:<base64url>" into a string; null on failure. */
  async function decryptString(keyBytes, blob) {
    if (!blob || !SUPPORTED.some(s => blob.startsWith(s + ':'))) return null;
    try {
      const raw = b64uDecode(blob.slice(3));
      if (raw.length < 28) return null; // 12 nonce + tag
      const nonce = raw.slice(0, 12);
      const ct = raw.slice(12);
      const key = await importAesKey(keyBytes);
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, ct
      );
      return new TextDecoder().decode(pt);
    } catch (e) {
      return null;
    }
  }

  /** Decrypt "v1:<base64url>" into bytes; null on failure.
   *  Used for binary data, such as object avatars. */
  async function decryptBytes(keyBytes, blob) {
    if (!blob || !SUPPORTED.some(s => blob.startsWith(s + ':'))) return null;
    try {
      const raw = b64uDecode(blob.slice(3));
      if (raw.length < 28) return null; // 12 nonce + tag
      const nonce = raw.slice(0, 12);
      const ct = raw.slice(12);
      const key = await importAesKey(keyBytes);
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, ct
      );
      return new Uint8Array(pt);
    } catch (e) {
      return null;
    }
  }

  /** HMAC-SHA256(key, msg) as a Uint8Array(32), for the encrypted socket proof. */
  async function hmacSha256(keyBytes, msgBytes) {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
    return new Uint8Array(sig);
  }
  // Standard base64, not the url variant: tokens and signatures in bundle.sock
  // come through the Android encoder.NO_WRAP.
  function b64Decode(s) { const bin = atob(s); const a = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function b64Encode(bytes) { let s = ''; for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }

  // The single key blob: user_key(32) + kGuest_b64url(43) = 75 characters.
  // user_key is base64url of 24 bytes, always 32 characters; kGuest is 32 bytes,
  // always 43. We cut at index 32. A blob of 32 characters is a user key alone,
  // with no encryption.
  function splitBlob(blob) {
    if (blob.length === 75) {
      return { userKey: blob.slice(0, 32), kGuest: b64uDecode(blob.slice(32)) };
    }
    if (blob.length === 32) return { userKey: blob, kGuest: null };
    return null;
  }

  /** Parser for an invitation key. Formats:
   *  1. "https://entrixy.com/key#<75-character blob>" — the current format.
   *  2. "entrixy:k?t=USERKEY&k=K_GUEST_B64URL" — an older deep link.
   *  3. "https://entrixy.com/go/<USERKEY>" or "...?t=..#k=.." — older still.
   *  4. a bare blob of 75 characters, or a bare user key of 32. */
  function parseInviteUri(input) {
    if (!input) return null;
    const s = input.trim();
    // Format 2: entrixy:k?t=...&k=...
    if (s.startsWith('entrixy:k')) {
      const q = s.indexOf('?');
      if (q < 0) return null;
      const params = new URLSearchParams(s.slice(q + 1));
      const t = params.get('t') || '';
      const k = params.get('k') || '';
      if (!t) return null;
      return { userKey: t, kGuest: k ? b64uDecode(k) : null };
    }
    // Formats 1 and 3: an https URL
    if (s.startsWith('http')) {
      try {
        const u = new URL(s);
        // Format 1: the single blob in the fragment, /key#<75 characters>.
        // The fragment may carry more after it — the app is handed the key as
        // "#<blob>&h=<server>" — so only the part before the first ampersand
        // is the blob. Reading the whole fragment here is what once turned
        // the page's own address into a key named "app".
        if (u.hash.length > 1) {
          const b = splitBlob(u.hash.slice(1).split('&')[0]);
          if (b) return b;
        }
        // Format 3: t in the query or path, kGuest in #k=
        const t = u.searchParams.get('t') || u.pathname.split('/').filter(Boolean).pop() || '';
        let kEnc = '';
        if (u.hash) kEnc = (new URLSearchParams(u.hash.slice(1))).get('k') || '';
        // A key is 32 characters. Anything shorter is a piece of the address
        // that happened to be last, not an invitation.
        if (t.length < 32) return null;
        return { userKey: t, kGuest: kEnc ? b64uDecode(kEnc) : null };
      } catch (_) { return null; }
    }
    // Format 4: a bare blob or key
    if (/^[A-Za-z0-9_-]{75}$/.test(s)) return splitBlob(s);
    if (/^[A-Za-z0-9_-]{16,}$/.test(s)) return { userKey: s, kGuest: null };
    return null;
  }

  /**
   * Signing a guest's requests.
   *
   * The server receives no key string, neither at issue nor in use: it finds
   * the row by the fingerprint, and the right is proved by a signature. The
   * pair is derived from the string itself, so the link stays as it is and
   * there is nothing extra to keep.
   */
  async function signSeed(userKey) {
    const ikm = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(userKey), 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('entrixy-guest-sign-v1'),
    }, ikm, 256);
    return new Uint8Array(bits);
  }

  // The browser accepts a private key only wrapped: sixteen bytes of header
  // and then the seed.
  async function signKey(userKey) {
    const seed = await signSeed(userKey);
    const der = new Uint8Array(48);
    der.set([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20], 0);
    der.set(seed, 16);
    return crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
  }

  function hexOf(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /** The key's fingerprint: the server finds a row by it; it opens nothing. */
  async function keyHash(userKey) {
    return hexOf(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(userKey)));
  }

  /**
   * The crypto suite: its name travels as the first field of the signed
   * material and as a header, so rewriting it in transit breaks the match.
   */
  const SUITE = 'v1';
  const SUPPORTED = ['v1'];

  /** The suite agreed with the server. null when there is no common one. */
  function agreeSuite(serverSuites) {
    if (!serverSuites || !serverSuites.length) return SUITE;
    return SUPPORTED.find(s => serverSuites.includes(s)) || null;
  }

  /** Signature headers for one request. */
  async function signHeaders(userKey, endpoint, body) {
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = hexOf(crypto.getRandomValues(new Uint8Array(16)));
    const bodyHash = hexOf(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)));
    const keyId = await keyHash(userKey);
    const material = `${SUITE}.${keyId}.${ts}.${nonce}.${endpoint}.${bodyHash}`;
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, await signKey(userKey),
      new TextEncoder().encode(material));
    return {
      'X-Entrixy-Key': keyId, 'X-Entrixy-Ts': ts, 'X-Entrixy-Nonce': nonce,
      'X-Entrixy-Sig': btoa(String.fromCharCode(...new Uint8Array(sig))),
      'X-Entrixy-Suite': SUITE,
    };
  }

  /** Fields of the signed greeting: a live connection carries no headers. */
  async function helloFields(userKey, deviceFp) {
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = hexOf(crypto.getRandomValues(new Uint8Array(16)));
    const fpHash = hexOf(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(deviceFp)));
    const keyId = await keyHash(userKey);
    const material = `${SUITE}.${keyId}.${ts}.${nonce}.guest_hello.${fpHash}`;
    const sig = await crypto.subtle.sign({ name: 'Ed25519' }, await signKey(userKey),
      new TextEncoder().encode(material));
    return { key_id: keyId, ts, nonce, suite: SUITE,
             sig: btoa(String.fromCharCode(...new Uint8Array(sig))) };
  }

  global.EntrixyCrypto = {
    signHeaders, helloFields, keyHash, agreeSuite, SUITE,
    encryptString, decryptString, decryptBytes,
    hmacSha256, b64Decode, b64Encode,
    b64uEncode, b64uDecode,
    parseInviteUri,
  };
})(window);
