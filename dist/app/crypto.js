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
    return 'v1:' + b64uEncode(out);
  }

  /** Decrypt "v1:<base64url>" into a string; null on failure. */
  async function decryptString(keyBytes, blob) {
    if (!blob || !blob.startsWith('v1:')) return null;
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
    if (!blob || !blob.startsWith('v1:')) return null;
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
        // Format 1: the single blob in the fragment, /key#<75 characters>
        if (u.hash.length > 1 && u.hash.indexOf('=') < 0) {
          const b = splitBlob(u.hash.slice(1));
          if (b) return b;
        }
        // Format 3: t in the query or path, kGuest in #k=
        const t = u.searchParams.get('t') || u.pathname.split('/').filter(Boolean).pop() || '';
        let kEnc = '';
        if (u.hash) kEnc = (new URLSearchParams(u.hash.slice(1))).get('k') || '';
        if (!t) return null;
        return { userKey: t, kGuest: kEnc ? b64uDecode(kEnc) : null };
      } catch (_) { return null; }
    }
    // Format 4: a bare blob or key
    if (/^[A-Za-z0-9_-]{75}$/.test(s)) return splitBlob(s);
    if (/^[A-Za-z0-9_-]{16,}$/.test(s)) return { userKey: s, kGuest: null };
    return null;
  }

  global.EntrixyCrypto = {
    encryptString, decryptString, decryptBytes,
    hmacSha256, b64Decode, b64Encode,
    b64uEncode, b64uDecode,
    parseInviteUri,
  };
})(window);
