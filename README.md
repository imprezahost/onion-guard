# Onion Guard

> Proof-of-Work + firewall + reverse proxy for Tor `.onion` hidden services, managed from your **aaPanel** dashboard.

Onion Guard sits in front of your hidden services and forces visitors to pass a cryptographic challenge before traffic ever reaches your backend. Bots, scrapers and DDoS bursts hit the gate instead of your application — without third-party CAPTCHAs and without leaving the Tor network.

Visitors using Tor Browser with JavaScript disabled (NoScript / paranoid mode) automatically fall back to an in-image CAPTCHA. Both paths emit the same session cookie, so the rest of the pipeline behaves identically.

---

## Better together: pair with Tor Manager

Onion Guard handles **protection at runtime**. To create and configure the `.onion` services in the first place, install our companion plugin:

> **[Tor Manager](https://github.com/imprezahost/tor-manager)** — manage `torrc`, hidden service directories and vanity `.onion` addresses from aaPanel.

```
  Tor Manager   ----->  creates and configures hidden services in /etc/tor/torrc
                            |
                            v
  Onion Guard   ----->  auto-discovers them, applies PoW + firewall + proxy
                            |
                            v
                          your application (WordPress, etc.)
```

You can use either plugin standalone, but installing both gives you a complete pipeline: provisioning + protection, all from the aaPanel UI.

---

## Highlights

### Proof-of-Work challenge

- SHA-256 challenge solved in the browser via the Web Crypto API
- Configurable difficulty (3 to 6 leading hex zeros)
- Adaptive difficulty under load (auto-raises above 80 req / 60 s)
- Stateless JWT session cookie with configurable TTL (default 1 h)

### No-JavaScript fallback

- Server-rendered PNG CAPTCHA via Pillow, activated by `<noscript>` style swap
- 5 unambiguous characters per challenge (no `0/O`, `1/I`)
- Single-use tokens with a 5-minute TTL, replay-safe
- Branding-colour aware
- Emits the same JWT cookie on success — downstream pipeline is unchanged

### Multi-domain

- Supports multiple `.onion` services on one panel
- Auto-discovers hidden services by parsing `torrc` and reading each `HiddenServiceDir/hostname`
- Per-domain backend (host, port, virtual host) and per-domain enable/disable

### Firewall

- Path blocklist (defaults include `/wp-admin/`, `/.env`, `/.git/`, `/xmlrpc.php`, ...)
- User-Agent blocklist (`sqlmap`, `nikto`, `nmap`, `dirbuster`, `gobuster`, `wfuzz`, ...)
- Per-circuit rate limit, 2-minute sliding window (default 120 req), when the service exports circuit ids; a single shared bucket otherwise
- All lists editable from the panel

### Branding

- Customisable challenge page: title, subtitle, primary / background / card / text colour
- Local logo upload (PNG, SVG, JPG, WebP, GIF, max 2 MB) - no third-party fetches
- Optional "Provided by Impreza Host" credit toggle (on by default, hideable)
- Live preview in the panel

### Web server integration

- Auto-detects nginx or Apache
- Injects `proxy_pass` / `ProxyPass` snippets into virtual hosts
- Creates an internal backend vhost (`og_backend.conf` on port 7780) to break the proxy loop
- Validates nginx syntax (`nginx -t`) before applying changes
- Enables required Apache modules (`proxy`, `proxy_http`, `headers`) automatically
- Clean removal restores the original configuration

---

## Architecture

```
  Visitor (.onion)
      |
      v
    Tor  ----->  Web server (nginx / Apache) - port 80 / 443
      |
      v   (proxy_pass / ProxyPass --> 127.0.0.1:7777)
    Onion Guard (Flask, port 7777)
      |
      |  /pow/challenge        - SHA-256 challenge (JS path)
      |  /pow/verify           - PoW solution, emits JWT cookie
      |  /pow/gate             - HTML gate page (JS + <noscript>)
      |  /pow/captcha.png      - PNG CAPTCHA (no-JS fallback)
      |  /pow/captcha-verify   - CAPTCHA solution, emits JWT cookie
      |  /pow/logo             - locally-served logo
      |  /*                    - token check, then proxy to backend
      |
      v   (internal proxy --> 127.0.0.1:7780)
    Internal backend vhost (og_backend.conf)
      |
      v
    Application (WordPress, etc.)
```

---

## Installation

Onion Guard installs as an **aaPanel plugin**.

### Requirements

- aaPanel 7.x or newer on Linux (Debian / Ubuntu / RHEL family)
- Python 3 with `venv` support
- nginx or Apache
- Tor configured with at least one `HiddenServiceDir`
- Outbound access to PyPI (for Flask, httpx, PyJWT, Pillow)

### Install

```bash
# On your aaPanel server, as root:
cd /www/server/panel/plugin
git clone https://github.com/imprezahost/onion-guard.git onion_guard
bash onion_guard/install.sh
bt restart
```

Then open the aaPanel UI and go to **App Store / Installed**. The **Onion Guard** icon will appear (hard-refresh with `Ctrl+Shift+R` if not visible).

The first time you open the plugin, it runs a diagnostic (Python, venv, Tor, torrc, permissions). Click **Install Onion Guard** to deploy the Flask service to `/opt/onion_guard/`. Installation runs in the background and streams a live log into the panel.

### Uninstall

From the panel: **Service Control --> Uninstall**. Or from the CLI:

```bash
bash /www/server/panel/plugin/onion_guard/uninstall.sh
```

This stops the service, removes `/opt/onion_guard/`, deletes the backend vhost and unregisters the systemd unit.

---

## On-disk layout (after install)

| Path | Purpose |
|---|---|
| `/opt/onion_guard/server.py` | Flask PoW server + reverse proxy |
| `/opt/onion_guard/config.json` | Main config (domains, difficulty, secret, ports, ...) |
| `/opt/onion_guard/blocklist.json` | Blocked paths and User-Agents |
| `/opt/onion_guard/branding.json` | Challenge-page customisation |
| `/opt/onion_guard/logo/` | Locally-stored logo |
| `/opt/onion_guard/venv/` | Python virtualenv (Flask, httpx, PyJWT, Pillow) |
| `/etc/systemd/system/onion_guard.service` | systemd unit |
| `/run/onion_guard/stats.json` | Live runtime stats (systemd runtime directory, 0700) |
| `<vhost dir>/og_circuit.conf` | Shared nginx listener for Tor connections carrying a PROXY header |

---

## Panel tabs

| Tab | What it does |
|---|---|
| **Status** | Service state, port, uptime, live stats (PoW solved, blocked, rate-limited, active tokens) |
| **Domains** | List discovered `.onion` services, toggle protection per domain, configure each backend |
| **Config** | PoW difficulty, JWT TTL, secret regeneration, listener port, rate limit |
| **Branding** | Colours, title, logo, "Provided by" toggle, live preview |
| **Firewall** | Path and User-Agent blocklists |
| **Web Server** | Scan vhosts, inject / remove snippets, check Apache modules |
| **Logs** | Live `journalctl` tail of `onion_guard.service` |

---

## Dependencies

| Package | Purpose |
|---|---|
| [Flask](https://flask.palletsprojects.com/) | Web framework |
| [httpx](https://www.python-httpx.org/) | HTTP client for the reverse proxy |
| [PyJWT](https://pyjwt.readthedocs.io/) | JWT issue and verify |
| [Pillow](https://python-pillow.org/) | Server-side PNG CAPTCHA rendering |
| [waitress](https://docs.pylonsproject.org/projects/waitress/) | Production WSGI server (pure Python, no compiler needed) |

All installed into the plugin's own venv at `/opt/onion_guard/venv/`. No system-Python pollution.

---

## Security notes

- The JWT secret is generated on first run and stored in `config.json` (root-only). Rotate via **Config --> Regenerate Secret**.
- `/opt/onion_guard/` is `chmod 750`, owned by root.
- PoW challenges are HMAC-signed by the server, verified in constant time, time-limited and single-use. A solution is only accepted against a challenge this server issued, and only once.
- CAPTCHA tokens are single-use with a 5-minute TTL; replay-safe.
- All challenge-page assets (logo, CAPTCHA) are served locally - no third-party requests.

---

## Author

Built and maintained by [Impreza Host](https://imprezahost.com). Issues and pull requests welcome.

---

## License

Released under the MIT License. See [LICENSE](LICENSE).
