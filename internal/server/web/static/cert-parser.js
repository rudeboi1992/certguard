// Client-side certificate parser. Parses .pem/.cer/.crt/.p12/.pfx entirely in
// the browser using node-forge; the file bytes never leave this page. Only
// extracted metadata (name, expiry, subject, issuer, fingerprint) is returned
// for the caller to send to the API. This preserves the privacy property of the
// original ExpiryGuard while feeding certguard's richer model.
//
// We deliberately do NOT use forge.pki.certificateFromAsn1 for X.509 files: it
// eagerly parses the subjectPublicKeyInfo and throws "OID is not RSA" on ECDSA
// / Ed25519 certificates (very common today). Since we only need validity,
// names, and a fingerprint, we walk the ASN.1 TBSCertificate directly, which
// works for any key type. PKCS#12 still goes through forge.pkcs12.
window.CertParser = (function () {
  const VALID = ['.pem', '.cer', '.crt', '.p12', '.pfx'];
  const MAX_BYTES = 5 * 1024 * 1024;

  const ext = (name) => '.' + name.split('.').pop().toLowerCase();

  function readFile(file, asBinary) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onerror = () => reject(new Error('could not read file'));
      r.onload = (e) => resolve(e.target.result);
      if (asBinary) r.readAsArrayBuffer(file); else r.readAsText(file);
    });
  }

  function bufToBinaryString(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  function dn(attributes) {
    return attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(',');
  }

  function commonName(attributes) {
    const pick = (sn) => {
      for (const a of attributes) if (a.shortName === sn) return a.value;
      return null;
    };
    return pick('CN') || pick('O') || null;
  }

  function asn1TimeToDate(node) {
    if (node.type === forge.asn1.Type.UTCTIME) return forge.asn1.utcTimeToDate(node.value);
    return forge.asn1.generalizedTimeToDate(node.value);
  }

  function fingerprintFromDer(derBinary) {
    const md = forge.md.sha256.create();
    md.update(derBinary);
    return md.digest().toHex();
  }

  // extractFromDer walks the Certificate -> TBSCertificate SEQUENCE and pulls
  // the fields we care about without touching the public key.
  function extractFromDer(derBinary, filename) {
    const cert = forge.asn1.fromDer(derBinary);
    const tbs = cert.value[0];
    // TBSCertificate: [version]? serial sigAlg issuer validity subject spki ...
    let i = 0;
    if (tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) i = 1;
    const issuer = forge.pki.RDNAttributesAsArray(tbs.value[i + 2]);
    const validity = tbs.value[i + 3];
    const subject = forge.pki.RDNAttributesAsArray(tbs.value[i + 4]);
    return {
      name: commonName(subject) || filename.replace(/\.[^/.]+$/, ''),
      notBefore: asn1TimeToDate(validity.value[0]),
      expiry: asn1TimeToDate(validity.value[1]),
      subject: dn(subject),
      issuer: dn(issuer),
      sha256: fingerprintFromDer(derBinary),
    };
  }

  async function parseFile(file, promptFn) {
    const e = ext(file.name);
    if (!VALID.includes(e)) throw new Error('Unsupported file type');
    if (file.size > MAX_BYTES) throw new Error('File too large to parse in browser');

    if (e === '.p12' || e === '.pfx') {
      const buf = await readFile(file, true);
      const asn1 = forge.asn1.fromDer(bufToBinaryString(buf));
      let p12;
      try {
        p12 = forge.pkcs12.pkcs12FromAsn1(asn1, '');
      } catch (_) {
        const pw = (promptFn ? promptFn() : '') || '';
        p12 = forge.pkcs12.pkcs12FromAsn1(asn1, pw);
      }
      const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
      const arr = bags[forge.pki.oids.certBag];
      if (!arr || !arr.length) throw new Error('No certificate found in file');
      // Re-derive DER from the bag's cert so we reuse the key-agnostic path.
      const der = forge.asn1.toDer(forge.pki.certificateToAsn1(arr[0].cert)).getBytes();
      return extractFromDer(der, file.name);
    }

    // .pem / .cer / .crt -- obtain DER bytes, then parse structurally.
    let der;
    if (e === '.pem') {
      const text = await readFile(file, false);
      if (!text.includes('-----BEGIN CERTIFICATE-----')) throw new Error('Invalid PEM');
      der = forge.pki.pemToDer(text).getBytes();
    } else {
      const buf = await readFile(file, true);
      const bin = bufToBinaryString(buf);
      if (bin.includes('-----BEGIN CERTIFICATE-----')) {
        der = forge.pki.pemToDer(new TextDecoder().decode(buf)).getBytes();
      } else {
        der = bin; // assume DER
      }
    }
    return extractFromDer(der, file.name);
  }

  return { parseFile, VALID };
})();
