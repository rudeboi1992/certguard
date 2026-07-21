// Client-side certificate parser. Parses .pem/.cer/.crt/.p12/.pfx entirely in
// the browser using node-forge; the file bytes never leave this page. Only
// extracted metadata (name, expiry, subject, issuer, fingerprint) is returned
// for the caller to send to the API. This preserves the privacy property of the
// original ExpiryGuard while feeding certguard's richer model.
window.CertParser = (function () {
  const VALID = ['.pem', '.cer', '.crt', '.p12', '.pfx'];
  const MAX_BYTES = 5 * 1024 * 1024;

  function ext(name) {
    return '.' + name.split('.').pop().toLowerCase();
  }

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

  function commonName(cert) {
    const pick = (sn) => {
      for (const a of cert.subject.attributes) {
        if (a.shortName === sn) return a.value;
      }
      return null;
    };
    return pick('CN') || pick('O') || null;
  }

  function fingerprint(cert) {
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const md = forge.md.sha256.create();
    md.update(der);
    return md.digest().toHex();
  }

  function dn(attributes) {
    return attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(',');
  }

  function extract(cert, filename) {
    return {
      name: commonName(cert) || filename.replace(/\.[^/.]+$/, ''),
      expiry: new Date(cert.validity.notAfter),
      notBefore: new Date(cert.validity.notBefore),
      subject: dn(cert.subject.attributes),
      issuer: dn(cert.issuer.attributes),
      sha256: fingerprint(cert),
    };
  }

  async function parseFile(file, promptFn) {
    const e = ext(file.name);
    if (!VALID.includes(e)) throw new Error('Unsupported file type');
    if (file.size > MAX_BYTES) throw new Error('File too large to parse in browser');

    let cert;
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
      cert = arr[0].cert;
    } else if (e === '.cer' || e === '.crt') {
      const buf = await readFile(file, true);
      try {
        cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(bufToBinaryString(buf)));
      } catch (_) {
        const text = new TextDecoder().decode(buf);
        if (!text.includes('-----BEGIN CERTIFICATE-----')) throw new Error('Unrecognized certificate encoding');
        cert = forge.pki.certificateFromPem(text);
      }
    } else {
      const text = await readFile(file, false);
      if (!text.includes('-----BEGIN CERTIFICATE-----')) throw new Error('Invalid PEM');
      cert = forge.pki.certificateFromPem(text);
    }

    return extract(cert, file.name);
  }

  return { parseFile, VALID };
})();
