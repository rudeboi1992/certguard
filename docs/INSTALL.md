# Installing certguard

certguard is **one app**. These are just different ways to run it. Pick the row
that matches you and follow that one section — you don't need to read the others.

| Your situation | Use | HTTPS? |
|---|---|---|
| **Proxmox** host | [Proxmox one-liner](#proxmox-one-line) | optional (green padlock) |
| Just want to **try it** | [Docker one-liner](#try-it-docker) | no (localhost) |
| **Home / office LAN**, no public domain | [Internal](#internal-lan-trusted-padlock) | ✅ trusted |
| You own a **public domain** | [Public domain](#public-domain) | ✅ trusted |
| You already run a **reverse proxy** | [Behind your proxy](#behind-a-proxy) | ✅ (your proxy) |

Every path ends the same way: **open the page and create your admin account.**
No config files to edit.

---

## Proxmox (one line) <a id="proxmox-one-line"></a>

On the Proxmox host shell (as root):

```
bash -c "$(curl -fsSL https://raw.githubusercontent.com/rudeboi1992/certguard/main/deploy/proxmox-install.sh)"
```

It builds a container, installs Docker, runs certguard, and prints a URL like
`http://192.168.1.50:8181`. Open it, create your admin. Done.

**Want the green padlock?** Add `MODE=internal`:

```
MODE=internal bash -c "$(curl -fsSL https://raw.githubusercontent.com/rudeboi1992/certguard/main/deploy/proxmox-install.sh)"
```

This prints `https://<ip>`. Then do the one-time [Trust the certificate](#trust-the-certificate) step.

---

## Try it (Docker) <a id="try-it-docker"></a>

On any machine with Docker:

```
docker run -d --name certguard -p 8181:8181 -v certguard-data:/data \
  ghcr.io/rudeboi1992/certguard:latest
```

Open **http://localhost:8181** (or `http://<host-ip>:8181`) and create your admin.

> Plain HTTP — fine on your own machine or a trusted VPN. Don't put real secrets
> on it over a shared network without HTTPS (use the internal method below).

---

## Internal — LAN, trusted padlock <a id="internal-lan-trusted-padlock"></a>

For a network with **no public domain** where you still want a real padlock.

1. Create a file named `.env` next to the compose file:
   ```
   CERTGUARD_DOMAIN=certguard.lan
   ```
   (and make `certguard.lan` point at the host in your DNS, or a hosts entry).
2. Start it:
   ```
   docker compose -f docker-compose.internal.yml up -d
   ```
3. Open `https://certguard.lan`, create your admin.
4. Do the one-time [Trust the certificate](#trust-the-certificate) step.

> On Proxmox, the `MODE=internal` one-liner above does all of this for you and
> works with just the container's IP — no DNS needed.

---

## Public domain <a id="public-domain"></a>

One container, a real Let's Encrypt certificate — **this puts certguard on the
public internet.** Since it holds a secret vault, first turn on **2FA** and the
**zero-knowledge vault**, and ideally front it with SSO.

1. Point your domain's DNS at the host, ports 80 + 443 reachable from outside.
2. Create `.env`:
   ```
   CERTGUARD_ACME_DOMAIN=certguard.example.com
   ```
3. Start it:
   ```
   docker compose -f docker-compose.aio.yml up -d
   ```
4. Open `https://certguard.example.com`, create your admin. The cert is trusted
   everywhere — nothing to install.

---

## Behind a proxy you already run <a id="behind-a-proxy"></a>

Already running Nginx Proxy Manager, Traefik, or Caddy?

1. Run certguard (the [Docker one-liner](#try-it-docker) is fine).
2. Point your proxy at `certguard:8181` (or `<host-ip>:8181`).
3. Set `CERTGUARD_COOKIE_SECURE=true` on the certguard container.

Your proxy handles the certificate the same way it does for your other apps.

---

## Trust the certificate <a id="trust-the-certificate"></a>

Only for the **internal** method (Let's Encrypt certs are trusted automatically).
Your browser will warn once — this makes it stop and show the green padlock.

**Get the certificate:** click through the warning, then open
**Settings → Security → Download CA certificate** (or just visit
`https://<your-cert-address>/ca.crt`). Save the `.crt` file.

Then install it:

### Windows
1. Double-click the `.crt` file → **Install Certificate**.
2. Choose **Local Machine** → Next (approve the admin prompt).
3. **Place all certificates in the following store** → **Browse** →
   **Trusted Root Certification Authorities** → OK → Finish.
4. **Fully quit your browser and reopen it** — Edge/Chrome only read the
   certificate store at startup, so a refresh alone won't work. ← the common gotcha
5. Reload the page: green padlock.

*(On a Windows domain, push the same `.crt` to every machine at once via Group
Policy: Computer Config → Policies → Windows Settings → Security Settings →
Public Key Policies → Trusted Root Certification Authorities → Import.)*

### macOS
1. Double-click the `.crt` → it opens **Keychain Access** → add it to the
   **System** keychain.
2. Find it in the System keychain, double-click → expand **Trust** → set
   **When using this certificate: Always Trust**.
3. Fully quit and reopen your browser.

### Linux
```
sudo cp your-cert.crt /usr/local/share/ca-certificates/certguard.crt
sudo update-ca-certificates
```
Restart your browser. (Firefox uses its own store — import it under
Settings → Privacy & Security → Certificates → View Certificates → Authorities.)

---

## First-run: create your admin

However you installed it, the first time you open certguard it asks you to
**create the admin account** right in the browser. That account is the
administrator; add more people later under **Settings → Users**. There is no
public sign-up.

Prefer it created automatically (no setup screen)? Set both
`CERTGUARD_ADMIN_EMAIL` and `CERTGUARD_ADMIN_PASSWORD` on first run.
