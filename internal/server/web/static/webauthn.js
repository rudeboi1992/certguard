// Security keys (WebAuthn/FIDO2). Shared by the login page, the settings page
// and the vault unlock dialog, so the base64url plumbing and the prf handling
// live in exactly one place.
//
// WebAuthn speaks ArrayBuffers where JSON speaks base64url, so every ceremony
// is bracketed by a decode on the way in and an encode on the way out.
const WebAuthnKit = (() => {
  const b64uToBuf = (s) => {
    const pad = s.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(pad + '==='.slice((pad.length + 3) % 4));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  };
  const bufToB64u = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const supported = () => !!(window.PublicKeyCredential && navigator.credentials);

  // The server sends protocol JSON with base64url fields; turn it into the
  // ArrayBuffer-shaped object navigator.credentials expects.
  function decodeCreation(opts) {
    const p = opts.publicKey || opts;
    return {
      ...p,
      challenge: b64uToBuf(p.challenge),
      user: { ...p.user, id: b64uToBuf(p.user.id) },
      excludeCredentials: (p.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    };
  }

  function decodeRequest(opts) {
    const p = opts.publicKey || opts;
    return {
      ...p,
      challenge: b64uToBuf(p.challenge),
      allowCredentials: (p.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    };
  }

  const encodeAttestation = (cred) => ({
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
  });

  const encodeAssertion = (cred) => ({
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
    },
  });

  // Browsers report a user cancelling and a key being unusable through the same
  // exception type, so translate to something a person can act on.
  function explain(err) {
    if (!err) return 'Security key failed';
    if (err.name === 'NotAllowedError') return 'Cancelled, or the key was not touched in time';
    if (err.name === 'InvalidStateError') return 'That key is already registered on this account';
    if (err.name === 'SecurityError') {
      return 'This page’s address cannot be used with security keys — certguard must be reached by hostname, not by IP';
    }
    if (err.name === 'NotSupportedError') return 'This key does not support what certguard asked for';
    return err.message || String(err);
  }

  // --- prf (vault) ---------------------------------------------------------
  // The prf extension yields a stable secret per (key, salt), which is what
  // makes a security key usable for encryption rather than only for proving
  // presence. Support is not universal: some authenticators and some browsers
  // simply return nothing, and callers must handle that rather than assume.
  const prfExtension = (saltBytes) => ({ prf: { eval: { first: saltBytes } } });

  function prfResult(cred) {
    const ext = cred.getClientExtensionResults();
    const first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    return first ? new Uint8Array(first) : null;
  }

  const randomSalt = () => crypto.getRandomValues(new Uint8Array(32));

  return {
    supported, decodeCreation, decodeRequest,
    encodeAttestation, encodeAssertion, explain,
    prfExtension, prfResult, randomSalt,
    b64uToBuf, bufToB64u,
    toB64: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
    fromB64: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
  };
})();
