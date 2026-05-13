# coding: utf-8
# Onion Guard - aaPanel Plugin v2.2
# PoW protection for .onion hidden services (multi-domain)

import sys, os, json, re, subprocess, time, secrets, hashlib, signal, glob


class onion_guard_main:
    __plugin_path   = '/www/server/panel/plugin/onion_guard'
    __install_dir   = '/opt/onion_guard'
    __service_name  = 'onion_guard'
    __service_file  = '/etc/systemd/system/onion_guard.service'
    __config_file   = '/opt/onion_guard/config.json'
    __server_script = '/opt/onion_guard/server.py'
    __venv_python   = '/opt/onion_guard/venv/bin/python'
    __venv_pip      = '/opt/onion_guard/venv/bin/pip'
    __stats_file    = '/tmp/onion_guard_stats.json'
    __blocklist_file= '/opt/onion_guard/blocklist.json'
    __branding_file = '/opt/onion_guard/branding.json'
    __logo_dir      = '/opt/onion_guard/logo'
    __install_log   = '/tmp/onion_guard_install.log'
    __install_pid   = '/tmp/onion_guard_install.pid'

    __torrc_paths = ['/etc/tor/torrc', '/usr/local/etc/tor/torrc', '/etc/torrc']

    __default_config = {
        'pow_secret':  '',
        'difficulty':  4,
        'token_ttl':   3600,
        'listen_port': 7777,
        'internal_port': 7780,
        'rate_limit':  120,
        'enabled':     True,
        'domains':     {},
    }

    __default_branding = {
        'logo_url':         '',
        'primary_color':    '#00bf80',
        'page_title':       'Security Verification',
        'subtitle':         'Your browser is completing a proof-of-work challenge.<br>This protects the network from automated attacks.',
        'background_color': '#0a0a0a',
        'card_color':       '#111111',
        'text_color':       '#e0e0e0',
        'show_branding':    True,
    }

    __default_blocklist = {
        'paths': ['/admin/','/administrator/','/.env','/.git/','/wp-login.php',
                  '/wp-admin/','/xmlrpc.php','/configuration.php','/install/',
                  '/vendor/phpunit/','/config.php','/../','/etc/passwd','/shell','/cmd'],
        'user_agents': ['sqlmap','nikto','masscan','nmap','zgrab','dirbuster','gobuster','wfuzz']
    }

    # --- Shell helpers ---
    def _exec(self, cmd, timeout=60):
        try:
            env = os.environ.copy()
            env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
            env['HOME'] = '/root'
            r = subprocess.run(['bash','-c',cmd], capture_output=True, text=True, timeout=timeout, env=env)
            return r.stdout.strip(), r.stderr.strip(), r.returncode
        except subprocess.TimeoutExpired:
            return '', 'Timed out', 1
        except Exception as e:
            return '', str(e), 1

    def _file_exists(self, path):
        _, _, c = self._exec('test -f "%s"' % path)
        return c == 0

    def _dir_exists(self, path):
        _, _, c = self._exec('test -d "%s"' % path)
        return c == 0

    def _read_file_shell(self, path):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return True, f.read(), ''
        except Exception as e:
            return False, '', str(e)

    def _write_file_shell(self, path, content):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True, ''
        except Exception as e:
            return False, str(e)

    def _read_json(self, path, default=None):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return default if default is not None else {}

    def _write_json(self, path, data):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            return True, ''
        except Exception as e:
            return False, str(e)

    # --- Service helpers ---
    def _service_running(self):
        _, _, c = self._exec('systemctl is-active --quiet %s' % self.__service_name)
        return c == 0

    def _service_enabled(self):
        _, _, c = self._exec('systemctl is-enabled --quiet %s' % self.__service_name)
        return c == 0

    def _reload_systemd(self):
        self._exec('systemctl daemon-reload')

    def _signal_reload(self):
        pid_out, _, _ = self._exec("systemctl show %s --property=MainPID --value" % self.__service_name)
        pid = pid_out.strip()
        if pid and pid != '0':
            self._exec('kill -USR1 %s 2>/dev/null' % pid)
        return json.dumps({'status': True, 'msg': 'Applied.'})

    # =========================================================================
    # QUICK CHECK
    # =========================================================================
    def quick_check(self, args=None):
        installed = self._file_exists(self.__server_script) and self._file_exists(self.__venv_python)
        return json.dumps({
            'status': True, 'installed': installed,
            'running': self._service_running() if installed else False,
            'enabled': self._service_enabled() if installed else False,
        })

    # =========================================================================
    # DIAGNOSE
    # =========================================================================
    def diagnose(self, args=None):
        import socket
        results = {}
        try:
            o, _, c = self._exec('python3 --version 2>&1')
            results['python3'] = (o or 'unknown') if c == 0 else 'NOT FOUND'
        except Exception as e:
            results['python3'] = 'ERROR: ' + str(e)
        try:
            _, _, c = self._exec('python3 -c "import venv" 2>&1')
            results['python3_venv'] = 'OK' if c == 0 else 'MISSING - run: apt install python3-venv'
        except Exception as e:
            results['python3_venv'] = 'ERROR: ' + str(e)
        try:
            _, _, c = self._exec('python3 -c "import pip" 2>&1')
            if c == 0:
                results['pip'] = 'OK'
            else:
                _, _, c2 = self._exec('python3 -m ensurepip --version 2>&1')
                results['pip'] = 'Missing but ensurepip available (will auto-install)' if c2 == 0 else 'MISSING - run: apt install python3-pip'
        except Exception as e:
            results['pip'] = 'ERROR: ' + str(e)
        try:
            socket.setdefaulttimeout(5)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(('pypi.org', 443))
            results['pypi_access'] = 'OK'
        except Exception as e:
            results['pypi_access'] = 'UNREACHABLE (' + str(e) + ')'
        try:
            _, _, c = self._exec('systemctl --version 2>&1')
            results['systemd'] = 'OK' if c == 0 else 'NOT FOUND'
        except Exception as e:
            results['systemd'] = 'ERROR: ' + str(e)
        try:
            _, _, c = self._exec('which tor 2>/dev/null')
            if c == 0:
                o2, _, _ = self._exec('tor --version 2>&1 | head -1')
                results['tor'] = o2 or 'OK'
            else:
                results['tor'] = 'NOT FOUND (optional)'
        except Exception as e:
            results['tor'] = 'ERROR: ' + str(e)
        torrc_found = False
        for p in self.__torrc_paths:
            if self._file_exists(p):
                results['torrc'] = 'OK (' + p + ')'
                torrc_found = True
                break
        if not torrc_found:
            results['torrc'] = 'NOT FOUND'
        try:
            _, _, c = self._exec('test -w /opt')
            results['write_opt'] = 'OK' if c == 0 else 'NO WRITE on /opt'
        except Exception as e:
            results['write_opt'] = 'ERROR: ' + str(e)
        try:
            o, _, _ = self._exec('whoami 2>&1')
            results['running_as'] = o or 'unknown'
        except Exception as e:
            results['running_as'] = 'ERROR: ' + str(e)
        return json.dumps({'status': True, 'results': results})

    def install_dependency(self, args=None):
        allowed = {'pip': 'python3-pip', 'venv': 'python3-venv'}
        pkg = (args or {}).get('pkg', '').strip()
        if pkg not in allowed:
            return json.dumps({'status': False, 'msg': 'Invalid package: ' + pkg})
        apt_pkg = allowed[pkg]
        o1, e1, c1 = self._exec('apt-get update -qq 2>&1', timeout=120)
        if c1 != 0:
            return json.dumps({'status': False, 'msg': 'apt-get update failed.', 'logs': [o1 or e1 or '']})
        o2, e2, c2 = self._exec('apt-get install -y ' + apt_pkg + ' 2>&1', timeout=120)
        if c2 != 0:
            return json.dumps({'status': False, 'msg': 'Failed to install ' + apt_pkg, 'logs': [o2 or e2 or '']})
        return json.dumps({'status': True, 'msg': apt_pkg + ' installed successfully.'})

    # =========================================================================
    # TORRC DOMAIN DISCOVERY
    # =========================================================================
    def _find_torrc(self):
        for p in self.__torrc_paths:
            if self._file_exists(p):
                return p
        return None

    def _parse_torrc_services(self):
        torrc = self._find_torrc()
        if not torrc:
            return []
        ok, content, _ = self._read_file_shell(torrc)
        if not ok:
            return []
        services = []
        current_dir = None
        current_ports = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            if line.startswith('HiddenServiceDir'):
                if current_dir:
                    services.append({'dir': current_dir, 'ports': list(current_ports)})
                parts = line.split(None, 1)
                current_dir = parts[1].strip() if len(parts) > 1 else None
                current_ports = []
            elif line.startswith('HiddenServicePort') and current_dir:
                parts = line.split()
                if len(parts) >= 3:
                    current_ports.append({'virtual_port': parts[1], 'target': parts[2]})
                elif len(parts) >= 2:
                    current_ports.append({'virtual_port': parts[1], 'target': ''})
        if current_dir:
            services.append({'dir': current_dir, 'ports': list(current_ports)})
        result = []
        for svc in services:
            hostname_file = os.path.join(svc['dir'], 'hostname')
            hostname = ''
            if self._file_exists(hostname_file):
                ok2, h, _ = self._read_file_shell(hostname_file)
                if ok2:
                    hostname = h.strip()
            result.append({'dir': svc['dir'], 'hostname': hostname, 'ports': svc['ports']})
        return result

    def scan_domains(self, args=None):
        discovered = self._parse_torrc_services()
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        domains = cfg.get('domains', {})
        torrc_path = self._find_torrc()
        found = []
        new_count = 0
        for svc in discovered:
            hostname = svc.get('hostname', '')
            if not hostname or not hostname.endswith('.onion'):
                found.append({'dir': svc['dir'], 'hostname': '(not generated yet)', 'ports': svc['ports'], 'enabled': False, 'in_config': False})
                continue
            if hostname not in domains:
                backend_host = '127.0.0.1'
                backend_port = 443
                for p in svc.get('ports', []):
                    target = p.get('target', '')
                    if ':' in target:
                        h, pt = target.rsplit(':', 1)
                        backend_host = h
                        try: backend_port = int(pt)
                        except: pass
                        break
                domains[hostname] = {'enabled': True, 'backend_host': backend_host, 'backend_port': backend_port, 'backend_domain': ''}
                new_count += 1
            found.append({
                'dir': svc['dir'], 'hostname': hostname, 'ports': svc['ports'],
                'enabled': domains.get(hostname, {}).get('enabled', True),
                'in_config': hostname in domains,
                'backend': domains.get(hostname, {}),
            })
        if new_count > 0:
            cfg['domains'] = domains
            self._write_json(self.__config_file, cfg)
        return json.dumps({'status': True, 'torrc': torrc_path or '', 'services': found, 'new_added': new_count})

    def get_domains(self, args=None):
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        return json.dumps({'status': True, 'domains': cfg.get('domains', {})})

    def set_domain_protection(self, args=None):
        domain = (args or {}).get('domain', '').strip()
        enabled = str((args or {}).get('enabled', 'true')).lower() in ('true', '1', 'yes')
        if not domain:
            return json.dumps({'status': False, 'msg': 'Domain is required.'})
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        domains = cfg.get('domains', {})
        if domain not in domains:
            domains[domain] = {'enabled': enabled, 'backend_host': '127.0.0.1', 'backend_port': 443, 'backend_domain': ''}
        else:
            domains[domain]['enabled'] = enabled
        cfg['domains'] = domains
        ok, err = self._write_json(self.__config_file, cfg)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Write failed: ' + err})
        if self._service_running():
            self._exec('systemctl restart %s' % self.__service_name)
        state = 'enabled' if enabled else 'disabled'
        return json.dumps({'status': True, 'msg': 'Protection ' + state + '.'})

    def save_domain_config(self, args=None):
        domain = (args or {}).get('domain', '').strip()
        if not domain:
            return json.dumps({'status': False, 'msg': 'Domain is required.'})
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        domains = cfg.get('domains', {})
        if domain not in domains:
            domains[domain] = {'enabled': True}
        if 'backend_host' in args:
            domains[domain]['backend_host'] = str(args['backend_host']).strip()
        if 'backend_port' in args:
            try: domains[domain]['backend_port'] = int(args['backend_port'])
            except: pass
        if 'backend_domain' in args:
            domains[domain]['backend_domain'] = str(args['backend_domain']).strip()
        cfg['domains'] = domains
        ok, err = self._write_json(self.__config_file, cfg)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Write failed: ' + err})
        if self._service_running():
            self._exec('systemctl restart %s' % self.__service_name)
        return json.dumps({'status': True, 'msg': 'Backend config saved.'})

    def remove_domain(self, args=None):
        domain = (args or {}).get('domain', '').strip()
        if not domain:
            return json.dumps({'status': False, 'msg': 'Domain is required.'})
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        domains = cfg.get('domains', {})
        if domain in domains:
            del domains[domain]
        cfg['domains'] = domains
        self._write_json(self.__config_file, cfg)
        return json.dumps({'status': True, 'msg': 'Domain removed from config.'})

    def scan_vhost_onions(self, args=None):
        """Scan vhost files for .onion ServerName/server_name declarations and report which
        ones are NOT yet covered by Onion Guard's domain list. Subdomains routed via
        Apache/nginx vhosts are not visible from torrc alone, so this complements scan_domains.
        """
        ws = self._detect_webserver()
        vhost_dir = self._find_vhost_dir(ws)
        if not vhost_dir:
            return json.dumps({'status': True, 'webserver': ws, 'vhost_dir': '',
                               'domains': [], 'uncovered': []})
        try:
            files = sorted(f for f in os.listdir(vhost_dir) if f.endswith('.conf'))
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Cannot list ' + vhost_dir + ': ' + str(e)})
        found = set()
        for fname in files:
            if fname == self.__backend_conf:
                continue
            path = os.path.join(vhost_dir, fname)
            ok, content, _ = self._read_file_shell(path)
            if not ok:
                continue
            if ws == 'nginx':
                for m in re.finditer(r'^\s*server_name\s+([^;]+);', content,
                                     re.IGNORECASE | re.MULTILINE):
                    for name in m.group(1).split():
                        n = name.strip().lower().rstrip('.')
                        if n and n.endswith('.onion') and '*' not in n and '_' != n[:1]:
                            found.add(n)
            else:
                for m in re.finditer(r'^\s*(?:ServerName|ServerAlias)\s+(.+)$', content,
                                     re.IGNORECASE | re.MULTILINE):
                    for name in m.group(1).split():
                        n = name.strip().lower().rstrip('.')
                        # aaPanel prefixes the *:443 ServerName with "SSL." — strip it for matching.
                        if n.startswith('ssl.'):
                            n = n[4:]
                        if n and n.endswith('.onion') and '*' not in n:
                            found.add(n)
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        configured = {k.lower() for k in cfg.get('domains', {}).keys()}
        uncovered = sorted(found - configured)
        return json.dumps({'status': True, 'webserver': ws, 'vhost_dir': vhost_dir,
                           'domains': sorted(found), 'configured': sorted(configured),
                           'uncovered': uncovered})

    # =========================================================================
    # BRANDING
    # =========================================================================
    def _find_logo(self):
        """Return the path to the logo file if it exists, else None."""
        logo_dir = self.__logo_dir
        if not self._dir_exists(logo_dir):
            return None
        for ext in ('png', 'svg', 'jpg', 'jpeg', 'webp', 'gif'):
            p = os.path.join(logo_dir, 'logo.' + ext)
            if self._file_exists(p):
                return p
        return None

    def get_branding(self, args=None):
        branding = self._read_json(self.__branding_file, dict(self.__default_branding))
        logo_path = self._find_logo()
        logo_b64 = ''
        logo_mime = ''
        if logo_path:
            try:
                import base64, mimetypes
                mime = mimetypes.guess_type(logo_path)[0] or 'image/png'
                with open(logo_path, 'rb') as f:
                    logo_b64 = base64.b64encode(f.read()).decode('ascii')
                logo_mime = mime
            except:
                pass
        branding['has_logo'] = bool(logo_path)
        branding['logo_data'] = logo_b64
        branding['logo_mime'] = logo_mime
        return json.dumps({'status': True, 'branding': branding})

    def upload_logo(self, args=None):
        """Receive base64-encoded image and save to logo dir."""
        import base64
        data_b64 = (args or {}).get('data', '')
        mime = (args or {}).get('mime', '').strip().lower()
        if not data_b64 or not mime:
            return json.dumps({'status': False, 'msg': 'Missing image data or mime type.'})
        allowed = {
            'image/png': 'png', 'image/svg+xml': 'svg', 'image/jpeg': 'jpg',
            'image/webp': 'webp', 'image/gif': 'gif',
        }
        ext = allowed.get(mime)
        if not ext:
            return json.dumps({'status': False, 'msg': 'Unsupported format. Use PNG, SVG, JPG, WebP, or GIF.'})
        try:
            raw = base64.b64decode(data_b64)
        except Exception:
            return json.dumps({'status': False, 'msg': 'Invalid base64 data.'})
        if len(raw) > 2 * 1024 * 1024:
            return json.dumps({'status': False, 'msg': 'Logo too large (max 2 MB).'})
        # Create dir and remove any old logo
        self._exec('mkdir -p %s' % self.__logo_dir)
        self._exec('rm -f %s/logo.*' % self.__logo_dir)
        dest = os.path.join(self.__logo_dir, 'logo.' + ext)
        try:
            with open(dest, 'wb') as f:
                f.write(raw)
            os.chmod(dest, 0o644)
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Write failed: ' + str(e)})
        # Clear logo_url in branding config (no longer needed)
        branding = self._read_json(self.__branding_file, dict(self.__default_branding))
        branding['logo_url'] = ''
        self._write_json(self.__branding_file, branding)
        if self._service_running():
            self._exec('systemctl restart %s' % self.__service_name)
        return json.dumps({'status': True, 'msg': 'Logo uploaded.'})

    def delete_logo(self, args=None):
        """Remove the logo file."""
        self._exec('rm -rf %s' % self.__logo_dir)
        branding = self._read_json(self.__branding_file, dict(self.__default_branding))
        branding['logo_url'] = ''
        self._write_json(self.__branding_file, branding)
        if self._service_running():
            self._exec('systemctl restart %s' % self.__service_name)
        return json.dumps({'status': True, 'msg': 'Logo removed.'})

    def save_branding(self, args=None):
        branding = self._read_json(self.__branding_file, dict(self.__default_branding))
        a = args or {}
        for f in ['primary_color','page_title','subtitle','background_color','card_color','text_color']:
            if f in a:
                branding[f] = str(a[f])
        if 'show_branding' in a:
            v = a['show_branding']
            branding['show_branding'] = bool(v) if isinstance(v, bool) else str(v).lower() in ('1','true','yes','on')
        ok, err = self._write_json(self.__branding_file, branding)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Write failed: ' + err})
        if self._service_running():
            self._exec('systemctl restart %s' % self.__service_name)
        return json.dumps({'status': True, 'msg': 'Branding saved and service restarted.'})

    # =========================================================================
    # INSTALL
    # =========================================================================
    def install_guard(self, args=None):
        try:
            self._exec('rm -f %s %s' % (self.__install_log, self.__install_pid))
            script = self._build_install_sh()
            script_path = '/tmp/onion_guard_installer.sh'
            with open(script_path, 'w') as f:
                f.write(script)
            os.chmod(script_path, 0o755)
            cmd = 'nohup bash %s > %s 2>&1 & echo $!' % (script_path, self.__install_log)
            pid_out, _, c = self._exec(cmd)
            if pid_out.strip():
                with open(self.__install_pid, 'w') as f:
                    f.write(pid_out.strip())
            return json.dumps({'status': True, 'msg': 'Installation started.', 'poll': True})
        except Exception as ex:
            return json.dumps({'status': False, 'msg': 'Could not start installer: ' + str(ex)})

    def install_progress(self, args=None):
        log_content = ''
        try:
            with open(self.__install_log, 'r') as f:
                log_content = f.read()
        except Exception:
            log_content = '(waiting for installer to start...)'
        running = False
        try:
            with open(self.__install_pid, 'r') as f:
                pid = f.read().strip()
            if pid:
                _, _, c = self._exec('kill -0 %s 2>/dev/null' % pid)
                running = (c == 0)
        except Exception:
            pass
        done = '[DONE]' in log_content
        failed = '[FAILED]' in log_content
        return json.dumps({'status': True, 'log': log_content, 'done': done, 'failed': failed, 'running': running and not done and not failed})

    def _build_service_text(self, cfg):
        return (
            '[Unit]\nDescription=Onion Guard - PoW Protection Server\nAfter=network.target tor.service\n\n'
            '[Service]\nType=simple\nUser=root\nWorkingDirectory={install_dir}\n'
            'Environment="CONFIG_FILE={config_file}"\n'
            'Environment="BLOCKLIST_FILE={blocklist_file}"\n'
            'Environment="BRANDING_FILE={branding_file}"\n'
            'Environment="STATS_FILE={stats_file}"\n'
            'ExecStart={venv_python} {server_script}\n'
            'Restart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n'
        ).format(
            install_dir=self.__install_dir, config_file=self.__config_file,
            blocklist_file=self.__blocklist_file, branding_file=self.__branding_file,
            stats_file=self.__stats_file, venv_python=self.__venv_python,
            server_script=self.__server_script,
        )

    def _write_service_file(self, cfg):
        content = self._build_service_text(cfg)
        try:
            with open(self.__service_file, 'w', encoding='utf-8') as f:
                f.write(content)
            return True, ''
        except Exception as e:
            return False, str(e)

    def _build_install_sh(self):
        install_dir = self.__install_dir
        secret = secrets.token_hex(32)
        cfg = dict(self.__default_config)
        cfg['pow_secret'] = secret
        # Auto-discover domains on install
        for svc in self._parse_torrc_services():
            hostname = svc.get('hostname', '')
            if hostname and hostname.endswith('.onion'):
                bh, bp = '127.0.0.1', 443
                for p in svc.get('ports', []):
                    t = p.get('target', '')
                    if ':' in t:
                        parts = t.rsplit(':', 1)
                        bh = parts[0]
                        try: bp = int(parts[1])
                        except: pass
                        break
                cfg['domains'][hostname] = {'enabled': True, 'backend_host': bh, 'backend_port': bp, 'backend_domain': ''}
        svc_text = self._build_service_text(cfg)
        bl_json = json.dumps(self.__default_blocklist, indent=2)
        br_json = json.dumps(self.__default_branding, indent=2)
        cfg_json = json.dumps(cfg, indent=2)
        server_src = self._get_server_script_src()
        sh = '''#!/bin/bash
set -e
LOG="{log}"
log() {{ echo "$1" | tee -a "$LOG"; }}
log "=== Onion Guard Installer ==="
log ""
log "[1/7] Creating install directory..."
mkdir -p {install_dir}
log "  OK"
log "[2/7] Checking python3-venv..."
PY_VER=$(python3 -c "import sys; print('%d.%d' % sys.version_info[:2])")
apt-get install -y python3-venv python3.${{PY_VER##*.}}-venv >> "$LOG" 2>&1 || true
log "  OK"
log "[3/7] Creating Python venv..."
python3 -m venv --without-pip {install_dir}/venv >> "$LOG" 2>&1 || {{ log "[FAILED] venv creation failed."; exit 1; }}
log "  OK"
log "[4/7] Installing Python packages (flask, httpx, PyJWT, Pillow)..."
VENV_PYTHON="{install_dir}/venv/bin/python"
$VENV_PYTHON -m ensurepip --upgrade >> "$LOG" 2>&1 || true
$VENV_PYTHON -m pip install --upgrade pip >> "$LOG" 2>&1 || true
$VENV_PYTHON -m pip install flask httpx PyJWT Pillow >> "$LOG" 2>&1 || {{ log "[FAILED] pip install failed."; exit 1; }}
log "  OK"
log "[5/7] Writing configuration files..."
cat > {config_file} << 'CONFIG_EOF'
{cfg_json}
CONFIG_EOF
cat > {blocklist_file} << 'BL_EOF'
{bl_json}
BL_EOF
cat > {branding_file} << 'BR_EOF'
{br_json}
BR_EOF
cat > {server_script} << 'SERVER_EOF'
{server_src}
SERVER_EOF
chmod 750 {server_script}
log "  OK"
log "[6/7] Setting permissions..."
chown -R root:root {install_dir}
chmod -R 750 {install_dir}
log "  OK"
log "[7/7] Installing systemd service..."
cat > {service_file} << 'SVC_EOF'
{svc}
SVC_EOF
systemctl daemon-reload
systemctl enable {service_name} >> "$LOG" 2>&1
systemctl restart {service_name} >> "$LOG" 2>&1 || true
sleep 2
if systemctl is-active --quiet {service_name}; then
    log ""; log "=== [DONE] Onion Guard installed and running! ==="
else
    log ""; log "=== [DONE] Files installed. Service may need manual start. ==="
fi
'''.format(
            log=self.__install_log, install_dir=install_dir,
            config_file=self.__config_file, blocklist_file=self.__blocklist_file,
            branding_file=self.__branding_file, server_script=self.__server_script,
            service_file=self.__service_file, service_name=self.__service_name,
            cfg_json=cfg_json, bl_json=bl_json, br_json=br_json,
            server_src=server_src, svc=svc_text,
        )
        return sh

    def uninstall_guard(self, args=None):
        self._exec('systemctl stop %s 2>/dev/null' % self.__service_name)
        self._exec('systemctl disable %s 2>/dev/null' % self.__service_name)
        self._exec('rm -f %s' % self.__service_file)
        self._reload_systemd()
        self._exec('rm -rf %s' % self.__install_dir)
        # Clean up backend vhost conf
        vhost_dir = self._find_vhost_dir()
        if vhost_dir:
            backend_path = os.path.join(vhost_dir, self.__backend_conf)
            if self._file_exists(backend_path):
                self._exec('rm -f ' + backend_path)
        return json.dumps({'status': True, 'msg': 'Onion Guard uninstalled.'})

    def update_server_script(self, args=None):
        """Upgrade the server.py in-place without a full reinstall."""
        if not self._file_exists(self.__server_script):
            return json.dumps({'status': False, 'msg': 'Onion Guard is not installed.'})
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        # Ensure internal_port exists in config
        if 'internal_port' not in cfg:
            cfg['internal_port'] = 7780
            self._write_json(self.__config_file, cfg)
        # Ensure Pillow is present (added in v2.1 for no-JS CAPTCHA fallback)
        extra_msg = ''
        _, _, c_pil = self._exec('%s -c "import PIL" 2>/dev/null' % self.__venv_python)
        if c_pil != 0:
            _, e_pil, c_inst = self._exec('%s -m pip install Pillow 2>&1' % self.__venv_python, timeout=180)
            if c_inst != 0:
                extra_msg = ' Pillow install failed (no-JS CAPTCHA will not render): ' + e_pil
        # Write the latest server.py
        server_src = self._get_server_script_src()
        try:
            with open(self.__server_script, 'w', encoding='utf-8') as f:
                f.write(server_src)
        except Exception as e:
            return json.dumps({'status': False, 'msg': 'Write failed: ' + str(e)})
        # Update service file and restart
        self._write_service_file(cfg)
        self._reload_systemd()
        if self._service_running():
            self._exec('systemctl restart %s' % self.__service_name)
        # Surface backend-config health warnings so a stale og_backend.conf doesn't silently
        # keep producing loops after the upgrade (v2.2 hardens the cloner, but existing
        # backend confs written by older versions may still be poisoned).
        health = self._check_backend_conf_health()
        if health:
            extra_msg += ' Backend health warnings: ' + ' | '.join(health)
        return json.dumps({'status': True, 'msg': 'Server script updated and service restarted. Remember to re-inject vhost snippets.' + extra_msg})

    # =========================================================================
    # SERVICE CONTROL
    # =========================================================================
    def start_service(self, args=None):
        _, e, c = self._exec('systemctl start %s' % self.__service_name)
        return json.dumps({'status': c == 0, 'msg': 'Service started.' if c == 0 else (e or 'Failed.')})

    def stop_service(self, args=None):
        _, e, c = self._exec('systemctl stop %s' % self.__service_name)
        return json.dumps({'status': c == 0, 'msg': 'Service stopped.' if c == 0 else (e or 'Failed.')})

    def restart_service(self, args=None):
        _, e, c = self._exec('systemctl restart %s' % self.__service_name)
        return json.dumps({'status': c == 0, 'msg': 'Service restarted.' if c == 0 else (e or 'Failed.')})

    # =========================================================================
    # STATUS
    # =========================================================================
    def get_status(self, args=None):
        running = self._service_running()
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        stats = self._read_json(self.__stats_file, {})
        uptime = ''
        if running:
            s, _, c = self._exec('systemctl show %s --property=ActiveEnterTimestamp --value' % self.__service_name)
            if c == 0 and s: uptime = s.strip()
        port_open = False
        if running:
            _, _, c = self._exec('ss -tlnp | grep :%s ' % cfg.get('listen_port', 7777))
            port_open = (c == 0)
        domains = cfg.get('domains', {})
        return json.dumps({
            'status': True, 'running': running, 'enabled': self._service_enabled(),
            'port': cfg.get('listen_port', 7777), 'port_open': port_open,
            'difficulty': cfg.get('difficulty', 4), 'token_ttl': cfg.get('token_ttl', 3600),
            'uptime': uptime, 'config_difficulty': cfg.get('difficulty', 4),
            'total_domains': len(domains),
            'protected_domains': sum(1 for d in domains.values() if d.get('enabled', True)),
            'stats': {
                'pow_solved': stats.get('pow_solved', 0), 'blocked': stats.get('blocked', 0),
                'rate_limited': stats.get('rate_limited', 0), 'tokens_active': stats.get('tokens_active', 0),
                'current_difficulty': stats.get('current_difficulty', cfg.get('difficulty', 4)),
                'requests_last_60s': stats.get('requests_last_60s', 0),
            }
        })

    # =========================================================================
    # CONFIG
    # =========================================================================
    def get_config(self, args=None):
        try:
            cfg = self._read_json(self.__config_file, dict(self.__default_config))
            safe = dict(cfg)
            if safe.get('pow_secret'):
                safe['pow_secret'] = '****' + str(safe['pow_secret'])[-4:]
            safe.pop('domains', None)
            return json.dumps({'status': True, 'config': safe})
        except Exception as e:
            return json.dumps({'status': False, 'msg': str(e)})

    def save_config(self, args):
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        for f in ['difficulty','token_ttl','listen_port','rate_limit']:
            if f in args:
                try: cfg[f] = int(args[f])
                except: pass
        if args.get('pow_secret') and '****' not in str(args['pow_secret']):
            cfg['pow_secret'] = str(args['pow_secret']).strip()
        ok, err = self._write_json(self.__config_file, cfg)
        if not ok:
            return json.dumps({'status': False, 'msg': 'Write failed: ' + err})
        self._write_service_file(cfg)
        self._reload_systemd()
        if self._service_running():
            self._exec('systemctl restart %s' % self.__service_name)
        return json.dumps({'status': True, 'msg': 'Configuration saved and service restarted.'})

    def regenerate_secret(self, args=None):
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        cfg['pow_secret'] = secrets.token_hex(32)
        ok, err = self._write_json(self.__config_file, cfg)
        if not ok:
            return json.dumps({'status': False, 'msg': err})
        self._write_service_file(cfg)
        self._reload_systemd()
        if self._service_running():
            self._exec('systemctl restart %s' % self.__service_name)
        return json.dumps({'status': True, 'msg': 'New secret generated and service restarted.'})

    # =========================================================================
    # BLOCKLIST
    # =========================================================================
    def get_blocklist(self, args=None):
        bl = self._read_json(self.__blocklist_file, dict(self.__default_blocklist))
        return json.dumps({'status': True, 'blocklist': bl})

    def add_blocked_path(self, args):
        path = str(args.get('path', '')).strip()
        if not path: return json.dumps({'status': False, 'msg': 'Path is required.'})
        bl = self._read_json(self.__blocklist_file, dict(self.__default_blocklist))
        if path not in bl['paths']:
            bl['paths'].append(path)
            self._write_json(self.__blocklist_file, bl)
        return self._signal_reload()

    def remove_blocked_path(self, args):
        path = str(args.get('path', '')).strip()
        bl = self._read_json(self.__blocklist_file, dict(self.__default_blocklist))
        bl['paths'] = [p for p in bl['paths'] if p != path]
        self._write_json(self.__blocklist_file, bl)
        return self._signal_reload()

    def add_blocked_agent(self, args):
        agent = str(args.get('agent', '')).strip()
        if not agent: return json.dumps({'status': False, 'msg': 'User-agent is required.'})
        bl = self._read_json(self.__blocklist_file, dict(self.__default_blocklist))
        if agent not in bl['user_agents']:
            bl['user_agents'].append(agent)
            self._write_json(self.__blocklist_file, bl)
        return self._signal_reload()

    def remove_blocked_agent(self, args):
        agent = str(args.get('agent', '')).strip()
        bl = self._read_json(self.__blocklist_file, dict(self.__default_blocklist))
        bl['user_agents'] = [u for u in bl['user_agents'] if u != agent]
        self._write_json(self.__blocklist_file, bl)
        return self._signal_reload()

    # =========================================================================
    # WEB SERVER DETECTION & INTEGRATION (Apache + nginx)
    # =========================================================================

    __apache_vhost_dirs = [
        '/www/server/panel/vhost/apache',
        '/etc/apache2/sites-available',
        '/etc/apache2/sites-enabled',
        '/etc/httpd/conf.d',
    ]
    __nginx_vhost_dirs = [
        '/www/server/panel/vhost/nginx',
        '/etc/nginx/sites-enabled',
        '/etc/nginx/sites-available',
        '/etc/nginx/conf.d',
    ]
    __snippet_marker   = '# >>> Onion Guard Proxy'
    __snippet_end      = '# <<< Onion Guard Proxy'
    __backend_marker   = '# >>> Onion Guard Backend'
    __backend_end      = '# <<< Onion Guard Backend'
    __backend_conf     = 'og_backend.conf'
    __nginx_disabled   = '# OG_OFF# '       # prefix used to comment‑out original location blocks

    # ------------- detection ------------------------------------------------

    def _detect_webserver(self):
        """Return 'nginx', 'apache', or 'unknown'."""
        for cmd in ['nginx -v 2>&1', '/www/server/nginx/sbin/nginx -v 2>&1']:
            o, _, c = self._exec(cmd)
            if c == 0 and 'nginx' in (o or '').lower():
                return 'nginx'
        for cmd in ['apache2ctl -v 2>&1', 'apachectl -v 2>&1', '/www/server/apache/bin/apachectl -v 2>&1']:
            o, _, c = self._exec(cmd)
            if c == 0 and ('apache' in (o or '').lower() or 'server version' in (o or '').lower()):
                return 'apache'
        return 'unknown'

    def detect_webserver(self, args=None):
        ws = self._detect_webserver()
        return json.dumps({'status': True, 'webserver': ws})

    # ------------- vhost dir helpers ----------------------------------------

    def _find_vhost_dir(self, webserver=None):
        ws = webserver or self._detect_webserver()
        dirs = self.__nginx_vhost_dirs if ws == 'nginx' else self.__apache_vhost_dirs
        for d in dirs:
            if self._dir_exists(d):
                return d
        return None

    # ------------- snippet builders -----------------------------------------

    def _build_snippet_lines(self, port=None, webserver=None):
        ws = webserver or self._detect_webserver()
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        if port is None:
            port = int(cfg.get("listen_port", 7777))
        if ws == 'nginx':
            return self._build_nginx_snippet(port)
        return self._build_apache_snippet(port)

    def _build_apache_snippet(self, port):
        return "\n".join([
            "    " + self.__snippet_marker,
            "    RequestHeader set X-Forwarded-For \"%{REMOTE_ADDR}s\"",
            "    ProxyPreserveHost On",
            "    ProxyPass        / http://127.0.0.1:" + str(port) + "/",
            "    ProxyPassReverse / http://127.0.0.1:" + str(port) + "/",
            "    " + self.__snippet_end,
        ])

    def _build_nginx_snippet(self, port):
        return "\n".join([
            "    " + self.__snippet_marker,
            "    location ^~ / {",
            "        proxy_pass http://127.0.0.1:" + str(port) + ";",
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $remote_addr;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_set_header X-Forwarded-Ssl on;",
            "        proxy_buffering off;",
            "        proxy_request_buffering off;",
            "    }",
            "    " + self.__snippet_end,
        ])

    # ------------- get snippet API ------------------------------------------

    def get_webserver_snippet(self, args=None):
        ws = self._detect_webserver()
        snippet = self._build_snippet_lines(webserver=ws)
        return json.dumps({"status": True, "snippet": snippet, "webserver": ws})

    # keep old name as alias for backwards compatibility
    def get_apache_snippet(self, args=None):
        return self.get_webserver_snippet(args)

    # ------------- Apache backend vhost -------------------------------------

    def _build_apache_backend_vhost(self, conf_path, internal_port):
        """Clone Apache vhost into an internal HTTP backend.
        Strips: SSL directives, marker-delimited OG snippets, unmarked self-referencing
        proxy directives (defense-in-depth), and skips pure-redirect blocks (HTTP->HTTPS)
        that would cause 301 loops when cloned onto the internal port.
        """
        ok, content, _ = self._read_file_shell(conf_path)
        if not ok:
            return None, "Cannot read " + conf_path
        content_clean = re.sub(
            r'\n*\s*' + re.escape(self.__backend_marker) + r'.*?' + re.escape(self.__backend_end),
            '', content, flags=re.DOTALL)
        blocks = re.findall(r'(<VirtualHost[^>]*>)(.*?)(</VirtualHost>)', content_clean, re.DOTALL)
        if not blocks:
            return None, "No VirtualHost found in " + conf_path
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        listen_port = int(cfg.get('listen_port', 7777))
        ssl_re = re.compile(r'^\s*(SSLEngine|SSLCertificate\w*|SSLProtocol|SSLCipherSuite|SSLHonor\w*|SSLSession\w*|SSLVerify\w*|SSLProxy\w*|SSLStapling\w*|SSLUseStapling)\b', re.IGNORECASE)
        og_re = re.compile(
            r'\s*' + re.escape(self.__snippet_marker) + r'.*?' + re.escape(self.__snippet_end) + r'\s*',
            re.DOTALL)
        # Strip any ProxyPass/ProxyPassReverse to OG's listen port (defense against unmarked manual entries).
        og_proxy_re = re.compile(
            r'^[ \t]*ProxyPass(?:Reverse)?[ \t]+\S+[ \t]+https?://127\.0\.0\.1:' + str(listen_port) + r'/?[ \t]*$',
            re.IGNORECASE | re.MULTILINE)
        # Companion directives that typically wrap the OG snippet without markers.
        og_companion_re = re.compile(
            r'^[ \t]*(?:# Onion Guard\b.*|RequestHeader[ \t]+set[ \t]+X-Forwarded-For[ \t]+["\']%\{REMOTE_ADDR\}s["\'][ \t]*|ProxyPreserveHost[ \t]+(?:On|Off)[ \t]*)$',
            re.IGNORECASE | re.MULTILINE)
        has_doc_root_re = re.compile(r'^\s*DocumentRoot\b', re.IGNORECASE | re.MULTILINE)
        pure_redirect_re = re.compile(
            r'^\s*(?:RewriteRule\s+\S+\s+https?://|Redirect(?:Match)?\s+(?:permanent\s+|\d+\s+)?\S*\s*https?://)',
            re.IGNORECASE | re.MULTILINE)
        vhosts = []
        skipped = 0
        for _open, body, _close in blocks:
            # Skip "pure" HTTP->HTTPS redirect blocks (no DocumentRoot, has a redirect to https://).
            if not has_doc_root_re.search(body) and pure_redirect_re.search(body):
                skipped += 1
                continue
            clean = og_re.sub('\n', body)
            clean = og_proxy_re.sub('', clean)
            clean = og_companion_re.sub('', clean)
            lines = [l for l in clean.splitlines() if not ssl_re.match(l)]
            vhosts.append("\n".join(lines))
        if not vhosts:
            return None, ("All VirtualHost blocks in " + conf_path +
                          " were filtered as pure-redirect; nothing safe to clone.")
        return vhosts, None

    def _write_apache_backend_conf(self, vhost_dir, internal_port, vhost_bodies, fname_hint=""):
        """Write og_backend.conf with Apache VirtualHost blocks on the internal port."""
        backend_path = os.path.join(vhost_dir, self.__backend_conf)
        existing = ""
        if self._file_exists(backend_path):
            ok, existing, _ = self._read_file_shell(backend_path)
            if not ok:
                existing = ""
        header = self.__backend_marker + "\n# Auto-generated by Onion Guard — do not edit manually\n"
        listen_line = "Listen 127.0.0.1:" + str(internal_port)
        if listen_line not in existing:
            header += listen_line + "\n"
        body = ""
        for vb in vhost_bodies:
            body += "\n<VirtualHost 127.0.0.1:" + str(internal_port) + ">" + vb + "\n</VirtualHost>\n"
        footer = self.__backend_end + "\n"
        marker_hint = "# source:" + fname_hint
        if marker_hint and marker_hint in existing:
            pattern = re.escape(marker_hint) + r'.*?(?=# source:|' + re.escape(self.__backend_end) + r')'
            new_content = re.sub(pattern, marker_hint + "\n" + body + "\n", existing, flags=re.DOTALL)
        elif self.__backend_marker in existing:
            new_content = existing.replace(
                self.__backend_end,
                "# source:" + fname_hint + "\n" + body + "\n" + self.__backend_end)
        else:
            new_content = header + "# source:" + fname_hint + "\n" + body + "\n" + footer
        return self._write_file_shell(backend_path, new_content)

    # ------------- nginx backend server block -------------------------------

    def _iter_nginx_server_blocks(self, content):
        """Yield (kind, text) for each segment: kind is 'block' for full `server { ... }`
        regions (with proper brace nesting), 'between' for everything outside."""
        pos = 0
        head_re = re.compile(r'\bserver\s*\{')
        while True:
            m = head_re.search(content, pos)
            if not m:
                if pos < len(content):
                    yield ('between', content[pos:])
                return
            if m.start() > pos:
                yield ('between', content[pos:m.start()])
            i = m.end()
            depth = 1
            while i < len(content) and depth > 0:
                ch = content[i]
                if ch == '{': depth += 1
                elif ch == '}': depth -= 1
                i += 1
            yield ('block', content[m.start():i])
            pos = i

    def _build_nginx_backend_server(self, conf_path, internal_port):
        """Clone nginx server blocks into an internal HTTP backend.
        Strips: marker-delimited OG snippets, SSL directives, unmarked self-referencing
        proxy_pass directives (defense-in-depth), and skips pure-redirect server blocks
        (HTTP->HTTPS) that would cause 301 loops on the internal port.
        """
        ok, content, _ = self._read_file_shell(conf_path)
        if not ok:
            return None, "Cannot read " + conf_path
        # Remove existing backend block
        content_clean = re.sub(
            r'\n*\s*' + re.escape(self.__backend_marker) + r'.*?' + re.escape(self.__backend_end),
            '', content, flags=re.DOTALL)
        # Remove OG snippet
        og_re = re.compile(
            r'\s*' + re.escape(self.__snippet_marker) + r'.*?' + re.escape(self.__snippet_end) + r'\s*',
            re.DOTALL)
        content_clean = og_re.sub('\n', content_clean)
        # Restore any OG-disabled lines
        content_clean = content_clean.replace(self.__nginx_disabled, '')

        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        listen_port = int(cfg.get('listen_port', 7777))
        og_proxy_re = re.compile(
            r'^[ \t]*proxy_pass[ \t]+https?://127\.0\.0\.1:' + str(listen_port) + r'[^;]*;[ \t]*$',
            re.IGNORECASE | re.MULTILINE)
        has_real_backend_re = re.compile(
            r'^\s*(root\s|proxy_pass\s|fastcgi_pass\s|uwsgi_pass\s|grpc_pass\s|alias\s)',
            re.IGNORECASE | re.MULTILINE)
        pure_redirect_re = re.compile(
            r'(return\s+30\d\s+https?://|rewrite\s+\S+\s+https?://)',
            re.IGNORECASE | re.MULTILINE)

        kept = []
        for kind, text in self._iter_nginx_server_blocks(content_clean):
            if kind == 'between':
                kept.append(text)
                continue
            body = og_proxy_re.sub('', text)
            if pure_redirect_re.search(body) and not has_real_backend_re.search(body):
                continue
            kept.append(body)
        content_clean = ''.join(kept)

        # Strip SSL directives
        ssl_re = re.compile(r'^\s*(ssl_certificate|ssl_certificate_key|ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers|ssl_session_\w+|ssl_stapling\w*|ssl_trusted_certificate)\b[^;]*;\s*$', re.IGNORECASE | re.MULTILINE)
        content_clean = ssl_re.sub('', content_clean)
        # Replace listen directives
        content_clean = re.sub(r'listen\s+\d+\s*ssl[^;]*;', 'listen 127.0.0.1:' + str(internal_port) + ';', content_clean)
        content_clean = re.sub(r'listen\s+\[::\]:\d+\s*ssl[^;]*;', '', content_clean)
        # Replace remaining listen with internal port
        content_clean = re.sub(r'listen\s+\d+[^;]*;', 'listen 127.0.0.1:' + str(internal_port) + ';', content_clean)
        content_clean = re.sub(r'listen\s+\[::\]:\d+[^;]*;', '', content_clean)
        # Deduplicate listen lines
        lines = content_clean.splitlines()
        seen_listen = False
        deduped = []
        for line in lines:
            if re.match(r'\s*listen\s+127\.0\.0\.1:', line):
                if seen_listen:
                    continue
                seen_listen = True
            deduped.append(line)
        if not any(kind == 'block' for kind, _ in self._iter_nginx_server_blocks(content_clean)):
            return None, ("All server blocks in " + conf_path +
                          " were filtered as pure-redirect; nothing safe to clone.")
        return "\n".join(deduped), None

    def _write_nginx_backend_conf(self, vhost_dir, internal_port, backend_content, fname_hint=""):
        """Write og_backend.conf for nginx."""
        backend_path = os.path.join(vhost_dir, self.__backend_conf)
        existing = ""
        if self._file_exists(backend_path):
            ok, existing, _ = self._read_file_shell(backend_path)
            if not ok:
                existing = ""
        header = self.__backend_marker + "\n# Auto-generated by Onion Guard — do not edit manually\n"
        footer = self.__backend_end + "\n"
        marker_hint = "# source:" + fname_hint
        if marker_hint and marker_hint in existing:
            pattern = re.escape(marker_hint) + r'.*?(?=# source:|' + re.escape(self.__backend_end) + r')'
            new_content = re.sub(pattern, marker_hint + "\n" + backend_content + "\n", existing, flags=re.DOTALL)
        elif self.__backend_marker in existing:
            new_content = existing.replace(
                self.__backend_end,
                marker_hint + "\n" + backend_content + "\n" + self.__backend_end)
        else:
            new_content = header + marker_hint + "\n" + backend_content + "\n" + footer
        return self._write_file_shell(backend_path, new_content)

    # ------------- remove backend entries -----------------------------------

    def _remove_from_backend_conf(self, vhost_dir, fname_hint):
        """Remove a source's entries from og_backend.conf (works for both Apache/nginx)."""
        backend_path = os.path.join(vhost_dir, self.__backend_conf)
        if not self._file_exists(backend_path):
            return
        ok, content, _ = self._read_file_shell(backend_path)
        if not ok:
            return
        marker = "# source:" + fname_hint
        if marker not in content:
            return
        pattern = r'\n?# source:' + re.escape(fname_hint) + r'.*?(?=# source:|' + re.escape(self.__backend_end) + r')'
        new_content = re.sub(pattern, '', content, flags=re.DOTALL)
        has_content = '<VirtualHost' in new_content or 'server {' in new_content or 'server{' in new_content
        if not has_content:
            self._exec("rm -f " + backend_path)
        else:
            self._write_file_shell(backend_path, new_content)

    # ------------- backend health check -------------------------------------

    def _check_backend_conf_health(self):
        """Scan og_backend.conf for self-referencing proxy or pure-redirect blocks.
        Returns a list of human-readable warnings (empty list if healthy)."""
        issues = []
        ws = self._detect_webserver()
        vhost_dir = self._find_vhost_dir(ws)
        if not vhost_dir:
            return issues
        backend_path = os.path.join(vhost_dir, self.__backend_conf)
        if not self._file_exists(backend_path):
            return issues
        ok, content, _ = self._read_file_shell(backend_path)
        if not ok:
            return issues
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        listen_port = int(cfg.get('listen_port', 7777))
        port_re = str(listen_port)
        if re.search(
            r'^[ \t]*(?:ProxyPass(?:Reverse)?|proxy_pass)[ \t]+\S*[ \t]*https?://127\.0\.0\.1:' + port_re,
            content, re.IGNORECASE | re.MULTILINE
        ):
            issues.append(
                'Backend config has a proxy directive pointing back to OG port ' + port_re +
                ' — this causes infinite request loops (4xx/header-too-large). '
                'Re-inject snippets from the Web Server tab to regenerate cleanly.'
            )
        # Detect a pure-redirect block: a vhost/server region containing https-redirect with
        # no DocumentRoot / root / proxy_pass to actual backend.
        if ws == 'nginx':
            for kind, text in self._iter_nginx_server_blocks(content):
                if kind != 'block':
                    continue
                has_real = re.search(r'^\s*(root\s|proxy_pass\s|fastcgi_pass\s|uwsgi_pass\s|grpc_pass\s|alias\s)',
                                     text, re.IGNORECASE | re.MULTILINE)
                has_redir = re.search(r'(return\s+30\d\s+https?://|rewrite\s+\S+\s+https?://)',
                                      text, re.IGNORECASE | re.MULTILINE)
                if has_redir and not has_real:
                    issues.append(
                        'Backend config contains a pure HTTP->HTTPS redirect server block — '
                        'this causes 301 loops. Re-inject snippets to regenerate.')
                    break
        else:
            for body in re.findall(r'<VirtualHost[^>]*>(.*?)</VirtualHost>', content, re.DOTALL):
                has_doc = re.search(r'^\s*DocumentRoot\b', body, re.IGNORECASE | re.MULTILINE)
                has_redir = re.search(
                    r'^\s*(RewriteRule\s+\S+\s+https?://|Redirect(?:Match)?\s+(?:permanent\s+|\d+\s+)?\S*\s*https?://)',
                    body, re.IGNORECASE | re.MULTILINE)
                if has_redir and not has_doc:
                    issues.append(
                        'Backend config contains a pure HTTP->HTTPS redirect VirtualHost — '
                        'this causes 301 loops. Re-inject snippets to regenerate.')
                    break
        return issues

    def check_backend_health(self, args=None):
        """Public API for the panel to query backend-config health warnings."""
        return json.dumps({'status': True, 'issues': self._check_backend_conf_health()})

    # ------------- scan vhosts ----------------------------------------------

    def scan_vhosts(self, args=None):
        """List vhost .conf files and whether they contain the OG snippet."""
        ws = self._detect_webserver()
        vhost_dir = self._find_vhost_dir(ws)
        if not vhost_dir:
            return json.dumps({"status": False, "msg": "No vhost directory found.", "webserver": ws,
                               "searched": self.__nginx_vhost_dirs if ws == 'nginx' else self.__apache_vhost_dirs})

        out, _, c = self._exec("ls -1 %s/*.conf 2>/dev/null" % vhost_dir)
        if c != 0 or not out.strip():
            return json.dumps({"status": True, "vhost_dir": vhost_dir, "vhosts": [], "webserver": ws,
                               "msg": "No .conf files found in " + vhost_dir})
        results = []
        for conf_path in out.strip().splitlines():
            conf_path = conf_path.strip()
            if not conf_path:
                continue
            fname = os.path.basename(conf_path)
            if fname == self.__backend_conf:
                continue
            ok, content, _ = self._read_file_shell(conf_path)
            if not ok:
                results.append({"file": fname, "path": conf_path, "has_snippet": False, "error": "cannot read"})
                continue
            has_snippet = self.__snippet_marker in content
            results.append({"file": fname, "path": conf_path, "has_snippet": has_snippet, "error": ""})
        return json.dumps({"status": True, "vhost_dir": vhost_dir, "vhosts": results, "webserver": ws})

    # ------------- inject / remove snippet ----------------------------------

    def inject_vhost_snippet(self, args=None):
        """Inject or remove the OG proxy snippet (auto-detects Apache/nginx)."""
        target = (args or {}).get('target', '').strip()
        remove = (args or {}).get('remove', False)
        if not target:
            return json.dumps({"status": False, "msg": "Missing target parameter."})

        ws = self._detect_webserver()
        vhost_dir = self._find_vhost_dir(ws)
        if not vhost_dir:
            return json.dumps({"status": False, "msg": "No vhost directory found."})

        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        internal_port = int(cfg.get("internal_port", 7780))

        if target == 'all':
            out, _, _ = self._exec("ls -1 %s/*.conf 2>/dev/null" % vhost_dir)
            files = [f.strip() for f in (out or '').splitlines()
                     if f.strip() and not f.strip().endswith('/' + self.__backend_conf)]
        else:
            if not target.startswith(vhost_dir + '/') or '..' in target:
                return json.dumps({"status": False, "msg": "Invalid path."})
            files = [target]

        snippet_block = self._build_snippet_lines(webserver=ws)
        logs = []
        injected = 0
        removed = 0

        for conf_path in files:
            fname = os.path.basename(conf_path)
            ok, content, _ = self._read_file_shell(conf_path)
            if not ok:
                logs.append(fname + ": cannot read, skipped")
                continue

            has_snippet = self.__snippet_marker in content

            if remove:
                if not has_snippet:
                    logs.append(fname + ": no snippet found, skipped")
                    continue
                pattern = r'\n? *' + re.escape(self.__snippet_marker) + r'.*?' + re.escape(self.__snippet_end) + r' *'
                new_content = re.sub(pattern, '', content, flags=re.DOTALL)
                if ws == 'nginx':
                    new_content = new_content.replace(self.__nginx_disabled, '')
                wok, werr = self._write_file_shell(conf_path, new_content)
                if wok:
                    logs.append(fname + ": snippet removed")
                    removed += 1
                    self._remove_from_backend_conf(vhost_dir, fname)
                    logs.append(fname + ": backend cleaned up")
                else:
                    logs.append(fname + ": write failed — " + werr)
                continue

            # Inject mode
            if has_snippet:
                logs.append(fname + ": already has snippet, skipped")
                continue

            if ws == 'nginx':
                new_content, ok_inject, inject_msg = self._inject_nginx(content, snippet_block)
            else:
                new_content, ok_inject, inject_msg = self._inject_apache(content, snippet_block)

            if not ok_inject:
                logs.append(fname + ": " + inject_msg)
                continue

            wok, werr = self._write_file_shell(conf_path, new_content)
            if wok:
                logs.append(fname + ": snippet injected")
                injected += 1
                # Create backend vhost
                if ws == 'nginx':
                    bc, berr = self._build_nginx_backend_server(conf_path, internal_port)
                    if bc:
                        bok, bwerr = self._write_nginx_backend_conf(vhost_dir, internal_port, bc, fname)
                        logs.append(fname + (": backend on port " + str(internal_port) if bok else ": backend write failed"))
                    else:
                        logs.append(fname + ": backend skipped — " + (berr or "parse error"))
                else:
                    bodies, berr = self._build_apache_backend_vhost(conf_path, internal_port)
                    if bodies:
                        bok, bwerr = self._write_apache_backend_conf(vhost_dir, internal_port, bodies, fname)
                        logs.append(fname + (": backend on port " + str(internal_port) if bok else ": backend write failed"))
                    else:
                        logs.append(fname + ": backend skipped — " + (berr or "parse error"))
            else:
                logs.append(fname + ": write failed — " + werr)

        # Reload web server
        reloaded = False
        if injected > 0 or removed > 0:
            if ws == 'nginx':
                reload_cmds = ["nginx -t 2>&1 && nginx -s reload 2>&1",
                               "/www/server/nginx/sbin/nginx -t 2>&1 && /www/server/nginx/sbin/nginx -s reload 2>&1"]
            else:
                reload_cmds = ["systemctl reload apache2 2>&1",
                               "/www/server/apache/bin/apachectl -k graceful 2>&1"]
            for cmd in reload_cmds:
                _, _, c = self._exec(cmd)
                if c == 0:
                    reloaded = True
                    break
            if not reloaded:
                logs.append("⚠ Web server reload failed — please reload manually.")

        action = "removed" if remove else "injected"
        count = removed if remove else injected
        ws_label = "nginx" if ws == 'nginx' else "Apache"
        msg = "%d vhost(s) %s." % (count, action)
        if reloaded:
            msg += " " + ws_label + " reloaded."
        return json.dumps({"status": True, "msg": msg, "logs": logs, "count": count, "reloaded": reloaded, "webserver": ws})

    # ------------- Apache injection helper ----------------------------------

    def _inject_apache(self, content, snippet_block):
        """Inject snippet into all Apache VirtualHost blocks. Returns (new_content, success, msg)."""
        vh_closes = [m.start() for m in re.finditer(r'</VirtualHost>', content)]
        if not vh_closes:
            return content, False, "no </VirtualHost> found"
        new_content = content
        for pos in reversed(vh_closes):
            new_content = new_content[:pos] + snippet_block + "\n" + new_content[pos:]
        return new_content, True, ""

    # ------------- nginx injection helper -----------------------------------

    def _inject_nginx(self, content, snippet_block):
        """Inject snippet into nginx server blocks. Uses location ^~ / which beats all regex locations."""
        # Find each 'server {' and inject snippet right after the opening brace
        server_opens = []
        i = 0
        while i < len(content):
            m = re.search(r'\bserver\s*\{', content[i:])
            if not m:
                break
            server_opens.append(i + m.end())
            i = i + m.end()
        if not server_opens:
            return content, False, "no server { } block found"
        new_content = content
        for pos in reversed(server_opens):
            new_content = new_content[:pos] + "\n" + snippet_block + new_content[pos:]
        return new_content, True, ""

    # ------------- module / config checks -----------------------------------

    def check_webserver_modules(self, args=None):
        """Check required modules/config for the detected web server."""
        ws = self._detect_webserver()
        if ws == 'nginx':
            return self._check_nginx_config()
        return self._check_apache_modules()

    # keep old name as alias
    def check_apache_modules(self, args=None):
        return self.check_webserver_modules(args)

    def _check_apache_modules(self):
        required = ["proxy", "proxy_http", "headers"]
        loaded = set()
        for cmd in ["apache2ctl -M 2>/dev/null", "apachectl -M 2>/dev/null", "/www/server/apache/bin/apachectl -M 2>/dev/null"]:
            out, _, c = self._exec(cmd)
            if c == 0 and out:
                for line in out.splitlines():
                    line = line.strip().lower()
                    if "_module" in line:
                        loaded.add(line.split("_module")[0].strip())
                break
        results = {}
        all_ok = True
        for mod in required:
            ok = mod in loaded
            if not ok: all_ok = False
            results[mod] = "OK" if ok else "MISSING"
        enable_cmd = ""
        if not all_ok:
            _, _, c1 = self._exec("which a2enmod 2>/dev/null")
            if c1 == 0:
                missing = [m for m in required if results[m] == "MISSING"]
                enable_cmd = "a2enmod " + " ".join(missing) + " && systemctl reload apache2"
            else:
                enable_cmd = "# Enable modules via aaPanel -> App Store -> Apache settings"
        return json.dumps({"status": True, "modules": results, "all_ok": all_ok, "enable_cmd": enable_cmd, "webserver": "apache"})

    def _check_nginx_config(self):
        """For nginx, validate config syntax."""
        results = {}
        # Test nginx config syntax
        for cmd in ["nginx -t 2>&1", "/www/server/nginx/sbin/nginx -t 2>&1"]:
            o, _, c = self._exec(cmd)
            if 'syntax is ok' in (o or '').lower() or 'test is successful' in (o or '').lower():
                results["config_syntax"] = "OK"
                results["config_test"] = "OK"
                return json.dumps({"status": True, "modules": results, "all_ok": True, "enable_cmd": "", "webserver": "nginx"})
            if c == 0:
                results["config_syntax"] = "OK"
                results["config_test"] = "OK"
                return json.dumps({"status": True, "modules": results, "all_ok": True, "enable_cmd": "", "webserver": "nginx"})
        # Config test failed
        results["config_syntax"] = "ERROR"
        error_detail = (o or '').strip().split('\n')[-1] if o else "nginx -t failed"
        results["config_test"] = error_detail
        return json.dumps({"status": True, "modules": results, "all_ok": False,
                           "enable_cmd": "Fix nginx config errors, then: nginx -t && nginx -s reload", "webserver": "nginx"})

    def enable_webserver_modules(self, args=None):
        """Enable missing modules (Apache) or validate config (nginx)."""
        ws = self._detect_webserver()
        if ws == 'nginx':
            # Nothing to enable for nginx, just test + reload
            for cmd in ["nginx -t 2>&1 && nginx -s reload 2>&1",
                        "/www/server/nginx/sbin/nginx -t 2>&1 && /www/server/nginx/sbin/nginx -s reload 2>&1"]:
                o, _, c = self._exec(cmd)
                if c == 0:
                    return json.dumps({"status": True, "msg": "nginx config valid and reloaded.", "logs": [(o or '').strip()]})
            return json.dumps({"status": False, "msg": "nginx config test failed.", "logs": [(o or '').strip()]})
        return self._enable_apache_modules()

    # keep old name
    def enable_apache_modules(self, args=None):
        return self.enable_webserver_modules(args)

    def _enable_apache_modules(self):
        required = ["proxy", "proxy_http", "headers"]
        logs = []
        check = json.loads(self._check_apache_modules())
        missing = [m for m, s in check.get("modules", {}).items() if s == "MISSING"]
        if not missing:
            return json.dumps({"status": True, "msg": "All modules already enabled."})
        logs.append("Missing: " + ", ".join(missing))
        _, _, c = self._exec("which a2enmod 2>/dev/null")
        if c == 0:
            o, e, c2 = self._exec("a2enmod " + " ".join(missing) + " 2>&1")
            logs.append(o or e)
            if c2 == 0:
                _, _, c3 = self._exec("systemctl reload apache2 2>&1")
                logs.append("Apache reloaded." if c3 == 0 else "Reload failed.")
                return json.dumps({"status": True, "msg": "Modules enabled.", "logs": logs})
            return json.dumps({"status": False, "msg": "a2enmod failed.", "logs": logs})
        conf_paths = ["/www/server/apache/conf/httpd.conf", "/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf"]
        conf_file = None
        for p in conf_paths:
            if self._file_exists(p): conf_file = p; break
        if not conf_file:
            return json.dumps({"status": False, "msg": "Could not find Apache config.", "logs": logs})
        ok, content, _ = self._read_file_shell(conf_file)
        if not ok:
            return json.dumps({"status": False, "msg": "Cannot read Apache config.", "logs": logs})
        mod_map = {"proxy": "LoadModule proxy_module modules/mod_proxy.so",
                   "proxy_http": "LoadModule proxy_http_module modules/mod_proxy_http.so",
                   "headers": "LoadModule headers_module modules/mod_headers.so"}
        changed = False
        for mod in missing:
            directive = mod_map.get(mod)
            if not directive: continue
            if "#" + directive in content:
                content = content.replace("#" + directive, directive); changed = True; logs.append(mod + ": uncommented")
            elif directive not in content:
                content += "\n" + directive + "\n"; changed = True; logs.append(mod + ": added")
        if changed:
            ok, err = self._write_file_shell(conf_file, content)
            if not ok: return json.dumps({"status": False, "msg": "Write failed: " + err, "logs": logs})
            for cmd in ["systemctl reload apache2", "/www/server/apache/bin/apachectl -k graceful"]:
                _, _, c = self._exec(cmd + " 2>/dev/null")
                if c == 0: logs.append("Apache reloaded."); break
            return json.dumps({"status": True, "msg": "Modules added.", "logs": logs})
        return json.dumps({"status": False, "msg": "Could not enable automatically.", "logs": logs})

    def test_connection(self, args=None):
        cfg = self._read_json(self.__config_file, dict(self.__default_config))
        port = int(cfg.get("listen_port", 7777))
        import socket
        s = socket.socket(); s.settimeout(3)
        try:
            s.connect(("127.0.0.1", port)); s.close()
        except Exception as e:
            return json.dumps({"status": False, "msg": "Port %d not reachable: %s" % (port, str(e))})
        try:
            import urllib.request
            req = urllib.request.Request("http://127.0.0.1:%d/pow/challenge" % port, headers={"User-Agent": "OnionGuard-HealthCheck/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                if "challenge" in data:
                    return json.dumps({"status": True, "msg": "OK — challenge endpoint responding on port %d." % port})
                return json.dumps({"status": True, "msg": "Port %d open, unexpected response." % port})
        except Exception as e:
            return json.dumps({"status": False, "msg": "Port %d open but HTTP error: %s" % (port, str(e))})

    def get_logs(self, args=None):
        lines = 100
        if args and args.get('lines'):
            try: lines = min(max(int(args['lines']), 10), 1000)
            except: pass
        o, _, c = self._exec('journalctl -u %s --no-pager -n %d 2>/dev/null' % (self.__service_name, lines))
        if c == 0 and o and len(o) > 20:
            return json.dumps({'status': True, 'logs': o, 'source': 'journalctl'})
        return json.dumps({'status': False, 'logs': 'No logs found.', 'source': ''})

    def clear_stats(self, args=None):
        self._write_json(self.__stats_file, {'pow_solved': 0, 'blocked': 0, 'rate_limited': 0, 'tokens_active': 0})
        return json.dumps({'status': True, 'msg': 'Stats cleared.'})

    # =========================================================================
    # SERVER.PY SOURCE
    # =========================================================================
    def _get_server_script_src(self):
        return r'''#!/usr/bin/env python3
"""Onion Guard v2.2 - Multi-domain PoW + Firewall server (JS + no-JS CAPTCHA)"""
import hashlib, hmac, io, json, logging, os, random, secrets, signal, threading, time
from urllib.parse import urljoin
import httpx, jwt
from flask import Flask, make_response, redirect, render_template_string, request, send_file

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
    _PIL_OK = True
except Exception:
    _PIL_OK = False

CONFIG_FILE    = os.environ.get("CONFIG_FILE",    "/opt/onion_guard/config.json")
BLOCKLIST_FILE = os.environ.get("BLOCKLIST_FILE", "/opt/onion_guard/blocklist.json")
BRANDING_FILE  = os.environ.get("BRANDING_FILE",  "/opt/onion_guard/branding.json")
STATS_FILE     = os.environ.get("STATS_FILE",     "/tmp/onion_guard_stats.json")

def _load_config():
    try:
        with open(CONFIG_FILE, "r") as f: return json.load(f)
    except: return {}

def _load_branding():
    try:
        with open(BRANDING_FILE, "r") as f: return json.load(f)
    except: return {}

_cfg = _load_config()
SECRET_KEY  = _cfg.get("pow_secret", secrets.token_hex(32))
DIFFICULTY  = int(_cfg.get("difficulty", 4))
TOKEN_TTL   = int(_cfg.get("token_ttl", 3600))
LISTEN_PORT = int(_cfg.get("listen_port", 7777))
RATE_LIMIT  = int(_cfg.get("rate_limit", 120))
INTERNAL_PORT = int(_cfg.get("internal_port", 7780))
DOMAINS     = _cfg.get("domains", {})
LOGO_DIR    = os.path.join(os.path.dirname(CONFIG_FILE), "logo")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("onion_guard")
app = Flask(__name__, instance_path='/opt/onion_guard')

_blocklist   = {"paths": [], "user_agents": []}
_rate_store  = {}
_stats       = {"pow_solved": 0, "blocked": 0, "rate_limited": 0, "tokens_active": 0}
_req_times   = []
_current_diff = DIFFICULTY

def _load_blocklist():
    global _blocklist
    try:
        with open(BLOCKLIST_FILE, "r") as f: _blocklist = json.load(f)
    except: pass

def _save_stats():
    try:
        _stats["current_difficulty"] = _current_diff
        _stats["requests_last_60s"]  = len([t for t in _req_times if time.time() - t < 60])
        with open(STATS_FILE, "w") as f: json.dump(_stats, f)
    except: pass

def _reload_handler(signum, frame):
    global DOMAINS, _cfg, _gate_html_cache
    log.info("SIGUSR1: reloading config + blocklist + branding")
    _load_blocklist()
    _cfg = _load_config()
    DOMAINS = _cfg.get("domains", {})
    _gate_html_cache = None

signal.signal(signal.SIGUSR1, _reload_handler)
_load_blocklist()

def _update_adaptive_difficulty():
    global _current_diff, _req_times
    now = time.time()
    _req_times = [t for t in _req_times if now - t < 60]
    rps = len(_req_times)
    if rps > 500: _current_diff = min(DIFFICULTY + 3, 8)
    elif rps > 200: _current_diff = min(DIFFICULTY + 2, 7)
    elif rps > 80: _current_diff = min(DIFFICULTY + 1, 6)
    else: _current_diff = DIFFICULTY

def _issue_token():
    return jwt.encode({"iat": int(time.time()), "exp": int(time.time()) + TOKEN_TTL}, SECRET_KEY, algorithm="HS256")

def _valid_token(token):
    try: jwt.decode(token, SECRET_KEY, algorithms=["HS256"]); return True
    except: return False

# --- CAPTCHA (no-JS fallback) ---
_captcha_store = {}
_captcha_lock  = threading.Lock()
_CAPTCHA_TTL   = 300   # 5 min per challenge
_CAPTCHA_MAX   = 5000  # cap to prevent memory growth
_CAPTCHA_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/1, O/0

def _captcha_sweep():
    now = time.time()
    with _captcha_lock:
        for t in [tok for tok,(_,exp) in _captcha_store.items() if exp < now]:
            _captcha_store.pop(t, None)
        if len(_captcha_store) > _CAPTCHA_MAX:
            for t,_ in sorted(_captcha_store.items(), key=lambda x:x[1][1])[:len(_captcha_store)-_CAPTCHA_MAX+500]:
                _captcha_store.pop(t, None)

def _captcha_new():
    _captcha_sweep()
    code  = ''.join(secrets.choice(_CAPTCHA_CHARS) for _ in range(5))
    token = secrets.token_urlsafe(18)
    with _captcha_lock:
        _captcha_store[token] = (code, time.time() + _CAPTCHA_TTL)
    return token

def _captcha_peek(token):
    with _captcha_lock:
        entry = _captcha_store.get(token)
    if not entry: return None
    code, exp = entry
    if exp < time.time(): return None
    return code

def _captcha_consume(token, answer):
    with _captcha_lock:
        entry = _captcha_store.pop(token, None)
    if not entry: return False
    code, exp = entry
    if exp < time.time(): return False
    return (answer or "").strip().upper() == code

def _captcha_render(code, color_hex):
    if not _PIL_OK:
        # Minimal valid 1x1 transparent PNG when Pillow is unavailable
        return bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6300010000000500010d0a2db40000000049454e44ae426082")
    c = (color_hex or "#00bf80").lstrip("#")
    try:
        rgb = (int(c[0:2],16), int(c[2:4],16), int(c[4:6],16)) if len(c)==6 else (0,191,128)
    except: rgb = (0,191,128)
    W, H = 240, 80
    img  = Image.new("RGB", (W, H), (15, 15, 15))
    draw = ImageDraw.Draw(img)
    font = None
    for fp in ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
               "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
               "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
               "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"):
        try:
            font = ImageFont.truetype(fp, 42); break
        except Exception: pass
    if font is None:
        font = ImageFont.load_default()
    x = 22
    for ch in code:
        y = random.randint(8, 22)
        layer = Image.new("RGBA", (48, 60), (0, 0, 0, 0))
        ImageDraw.Draw(layer).text((4, 0), ch, font=font, fill=rgb + (255,))
        layer = layer.rotate(random.randint(-26, 26), resample=Image.BICUBIC)
        img.paste(layer, (x, y), layer)
        x += 40
    for _ in range(8):
        draw.line([(random.randint(0,W), random.randint(0,H)),
                   (random.randint(0,W), random.randint(0,H))],
                  fill=(70, 70, 70), width=1)
    for _ in range(260):
        draw.point((random.randint(0, W), random.randint(0, H)), fill=(95, 95, 95))
    img = img.filter(ImageFilter.SMOOTH)
    buf = io.BytesIO(); img.save(buf, "PNG")
    return buf.getvalue()

def _is_blocked_path(path):
    for b in _blocklist.get("paths", []):
        if b and (path == b or path.startswith(b) or b in path): return True
    return False

def _is_blocked_agent(ua):
    ua_lower = (ua or "").lower()
    for b in _blocklist.get("user_agents", []):
        if b and b.lower() in ua_lower: return True
    return False

def _rate_limited(ip):
    now = time.time()
    bucket = _rate_store.get(ip, [])
    bucket = [t for t in bucket if now - t < 120]
    bucket.append(now)
    _rate_store[ip] = bucket
    return len(bucket) > RATE_LIMIT

def _get_domain_config(host):
    if not host: return None
    host_clean = host.split(":")[0].strip().lower()
    for domain, dcfg in DOMAINS.items():
        if domain.lower() == host_clean: return dcfg
    return None

_gate_html_cache = None

def _get_gate_html():
    global _gate_html_cache
    if _gate_html_cache is None:
        _gate_html_cache = _build_gate_html()
    return _gate_html_cache

def _build_gate_html():
    br = _load_branding()
    color  = br.get("primary_color", "#00bf80")
    title  = br.get("page_title", "Security Verification")
    sub    = br.get("subtitle", "Your browser is completing a proof-of-work challenge.<br>This protects the network from automated attacks.")
    bg     = br.get("background_color", "#0a0a0a")
    card   = br.get("card_color", "#111111")
    txt    = br.get("text_color", "#e0e0e0")
    show_branding = bool(br.get("show_branding", True))
    has_logo = _find_logo_file() is not None or bool(br.get("logo_url", ""))
    logo_src = "/pow/logo" if _find_logo_file() else br.get("logo_url", "")
    logo_h = '<div class="logo"><img src="' + logo_src + '" alt="Logo" onerror="this.parentElement.style.display=\'none\'"></div>' if has_logo else ''
    branding_h = '<div class="branding">Provided by <a href="https://imprezahost.com" target="_blank" rel="noopener">Impreza Host</a></div>' if show_branding else ''
    return """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>"""+title+"""</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:"""+bg+""";color:"""+txt+""";min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:"""+card+""";border:1px solid #1e1e1e;border-radius:12px;padding:48px 40px;max-width:420px;width:90%;text-align:center;box-shadow:0 0 60px """+color+"""10}
.logo{margin-bottom:36px}.logo img{height:36px;width:auto}
.shield{width:56px;height:56px;background:"""+color+"""18;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;border:1px solid """+color+"""33}
.shield svg{width:26px;height:26px}
h1{font-size:18px;font-weight:600;color:#fff;margin-bottom:8px}
.subtitle{font-size:13px;color:#666;margin-bottom:32px;line-height:1.5}
.progress-wrap{background:#1a1a1a;border-radius:6px;height:4px;overflow:hidden;margin-bottom:12px}
.progress-bar{height:100%;width:0%;background:linear-gradient(90deg,"""+color+""","""+color+"""cc);border-radius:6px;transition:width .3s}
.status{font-size:12px;color:#555;margin-bottom:28px;min-height:16px}
.status.active{color:"""+color+"""}.status.done{color:"""+color+"""}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:#444;border:1px solid #222;border-radius:20px;padding:5px 12px}
.badge .dot{width:6px;height:6px;border-radius:50%;background:#333}
.badge.secured .dot{background:"""+color+""";box-shadow:0 0 6px """+color+"""99}
.badge.secured{color:"""+color+""";border-color:"""+color+"""44}
.error{color:#ff4d4d;font-size:13px;margin-top:16px;display:none}
.branding{margin-top:24px;font-size:10px;color:#444;letter-spacing:.5px}
.branding a{color:#555;text-decoration:none}
.nojs{display:none}
.nojs-info{font-size:12px;color:#888;margin-bottom:16px;line-height:1.5}
.captcha-img{display:block;margin:0 auto 14px;border:1px solid #1e1e1e;border-radius:6px;max-width:100%;height:auto;image-rendering:auto}
.captcha-input{width:100%;background:#1a1a1a;border:1px solid #2a2a2a;border-radius:6px;color:#fff;padding:10px 12px;font-size:14px;text-align:center;letter-spacing:6px;text-transform:uppercase;font-family:monospace;margin-bottom:12px}
.captcha-input:focus{outline:none;border-color:"""+color+"""}
.captcha-btn{width:100%;background:"""+color+""";border:none;border-radius:6px;color:#000;padding:10px 16px;font-size:14px;font-weight:600;cursor:pointer}
.captcha-btn:hover{filter:brightness(1.1)}
.captcha-err{color:#ff4d4d;font-size:12px;margin-bottom:12px}
</style>
<noscript><style>.jsf{display:none!important}.nojs{display:block!important}</style></noscript>
</head><body><div class="card">
"""+logo_h+"""
<div class="shield"><svg viewBox="0 0 24 24" fill="none" stroke=\""""+color+"""\" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
<h1>"""+title+"""</h1><p class="subtitle">"""+sub+"""</p>
<div class="jsf">
<div class="progress-wrap"><div class="progress-bar" id="bar"></div></div>
<div class="status" id="status">Initializing...</div>
<div class="badge" id="badge"><span class="dot"></span> Verifying connection</div>
<div class="error" id="err"></div>
</div>
<div class="nojs">
<p class="nojs-info">JavaScript is disabled. Type the code below to continue.</p>
{% if captcha_error %}<div class="captcha-err">Incorrect code. Please try again.</div>{% endif %}
<form method="POST" action="/pow/captcha-verify" autocomplete="off">
<img src="/pow/captcha.png?t={{captcha_token}}" alt="CAPTCHA" class="captcha-img" width="240" height="80">
<input type="hidden" name="token" value="{{captcha_token}}">
<input type="hidden" name="next" value="{{next_url}}">
<input type="text" name="answer" class="captcha-input" required maxlength="5" pattern="[A-Za-z0-9]{5}" autocapitalize="characters" spellcheck="false" autocomplete="off" autofocus>
<button type="submit" class="captcha-btn">Verify</button>
</form>
</div>
"""+branding_h+"""
</div><script>
const NEXT="{{next_url}}",COLOR=\""""+color+"""\",bar=document.getElementById("bar"),st=document.getElementById("status"),bdg=document.getElementById("badge"),err=document.getElementById("err");
function setProgress(p,m){bar.style.width=p+"%";st.textContent=m;st.className="status active"}
async function run(){setProgress(10,"Requesting challenge...");let ch;try{const r=await fetch("/pow/challenge");ch=await r.json()}catch(e){showErr();return}
const{challenge,difficulty}=ch;setProgress(25,"Solving challenge (difficulty "+difficulty+")...");let nonce=0;const prefix="0".repeat(difficulty),t0=Date.now();
async function tick(){const dl=Date.now()+40;while(Date.now()<dl){const h=await sha256hex(challenge+nonce);if(h.startsWith(prefix)){setProgress(80,"Solved in "+((Date.now()-t0)/1000).toFixed(1)+"s — verifying...");verify(challenge,nonce);return}nonce++}
setProgress(Math.min(25+Math.floor(nonce/5000),75),"Computing... ("+nonce.toLocaleString()+")");requestAnimationFrame(tick)}requestAnimationFrame(tick)}
async function verify(c,n){try{const r=await fetch("/pow/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({challenge:c,nonce:n})});const d=await r.json();
if(d.ok){setProgress(100,"Verified!");st.className="status done";bdg.className="badge secured";bdg.innerHTML='<span class="dot"></span> Secured';setTimeout(()=>{window.location.href=NEXT||"/"},400)}
else{showErr(d.error||"Invalid solution")}}catch(e){showErr("Network error")}}
function showErr(m){st.textContent="";err.style.display="block";err.innerHTML=(m||"Verification failed")+'. <a href="?" style="color:'+COLOR+'">Retry</a>';bar.style.background="#ff4d4d"}
async function sha256hex(s){const b=new TextEncoder().encode(s),h=await crypto.subtle.digest("SHA-256",b);return Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,"0")).join("")}
run();</script></body></html>"""

SKIP_REQ={"host","connection","transfer-encoding"}
SKIP_RESP={"content-encoding","transfer-encoding","connection","keep-alive"}

def _proxy(dcfg, incoming_host):
    bh = dcfg.get("backend_host","127.0.0.1")
    bp = dcfg.get("backend_port",443)
    bd = dcfg.get("backend_domain","") or incoming_host
    # For localhost backends, always use the internal port (HTTP, no SSL, no loop)
    if bh in ("127.0.0.1","localhost","::1") and INTERNAL_PORT:
        scheme = "http"
        bp = INTERNAL_PORT
    else:
        scheme = "https" if bp == 443 else "http"
    backend_url = f"{scheme}://{bh}:{bp}"
    path = request.full_path if request.query_string else request.path
    url = urljoin(backend_url, path)
    hdrs = {k:v for k,v in request.headers if k.lower() not in SKIP_REQ}
    hdrs["Host"] = bd
    hdrs["X-Forwarded-Proto"] = "https"
    hdrs["X-Forwarded-Ssl"] = "on"
    try:
        up = httpx.request(request.method, url, headers=hdrs, content=request.get_data(), follow_redirects=False, timeout=30, verify=False)
    except httpx.RequestError as ex:
        log.error("Upstream: %s", ex); return "Bad Gateway", 502
    rh = []
    for k, v in up.headers.items():
        if k.lower() in SKIP_RESP: continue
        if k.lower() == "location" and bd and incoming_host:
            v = v.replace("https://"+bd, "https://"+incoming_host)
            v = v.replace("http://"+bd, "https://"+incoming_host)
        rh.append((k, v))
    return up.content, up.status_code, rh

@app.route("/pow/challenge")
def pow_challenge():
    return {"challenge": secrets.token_hex(16), "difficulty": _current_diff}

@app.route("/pow/verify", methods=["POST"])
def pow_verify():
    data = request.get_json(silent=True) or {}
    ch, nonce = str(data.get("challenge","")), data.get("nonce")
    if not ch or nonce is None: return {"error":"Missing fields"}, 400
    if not hashlib.sha256(f"{ch}{nonce}".encode()).hexdigest().startswith("0"*_current_diff):
        _stats["blocked"] += 1; _save_stats(); return {"error":"Invalid solution"}, 400
    token = _issue_token()
    _stats["pow_solved"] += 1; _save_stats()
    resp = make_response({"ok":True})
    resp.set_cookie("pow_token", token, httponly=True, samesite="Lax", max_age=TOKEN_TTL, secure=True)
    return resp

@app.route("/pow/gate")
def pow_gate():
    return render_template_string(
        _get_gate_html(),
        next_url=request.args.get("next", "/"),
        captcha_token=_captcha_new(),
        captcha_error=(request.args.get("err") == "1"),
    )

@app.route("/pow/captcha.png")
def pow_captcha_img():
    tok = request.args.get("t", "")
    code = _captcha_peek(tok)
    if not code:
        return "Expired", 404
    color = _load_branding().get("primary_color", "#00bf80")
    png = _captcha_render(code, color)
    resp = make_response(png)
    resp.headers["Content-Type"]  = "image/png"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"]        = "no-cache"
    return resp

@app.route("/pow/captcha-verify", methods=["POST"])
def pow_captcha_verify():
    tok   = request.form.get("token", "")
    ans   = request.form.get("answer", "")
    nxt   = request.form.get("next", "/") or "/"
    if not nxt.startswith("/"): nxt = "/"
    if not _captcha_consume(tok, ans):
        _stats["blocked"] += 1; _save_stats()
        return redirect("/pow/gate?next=" + nxt + "&err=1")
    jwt_token = _issue_token()
    _stats["pow_solved"] += 1; _save_stats()
    resp = make_response(redirect(nxt))
    resp.set_cookie("pow_token", jwt_token, httponly=True, samesite="Lax", max_age=TOKEN_TTL, secure=True)
    return resp

def _find_logo_file():
    if not os.path.isdir(LOGO_DIR): return None
    for ext in ("png","svg","jpg","jpeg","webp","gif"):
        p = os.path.join(LOGO_DIR, "logo." + ext)
        if os.path.isfile(p): return p
    return None

@app.route("/pow/logo")
def pow_logo():
    p = _find_logo_file()
    if not p: return "", 204
    return send_file(p)

@app.route("/", defaults={"path":""})
@app.route("/<path:path>", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
def catch_all(path):
    if path.startswith("pow/"): return "Not found", 404
    ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent","")
    host = request.headers.get("Host","")
    _req_times.append(time.time()); _update_adaptive_difficulty()
    if _is_blocked_agent(ua): _stats["blocked"]+=1; _save_stats(); return "Forbidden", 403
    if _is_blocked_path(request.path): _stats["blocked"]+=1; _save_stats(); return "Forbidden", 403
    dcfg = _get_domain_config(host)
    if dcfg is None:
        # Fail-secure: refuse unknown hosts rather than silently proxying without PoW.
        log.warning("Reject unknown host: %r (configured: %s)", host, list(DOMAINS.keys()))
        _stats["blocked"] += 1; _save_stats()
        return ("This host is not registered with Onion Guard. "
                "Add it under Domains in the aaPanel UI."), 503
    if not dcfg.get("enabled", True):
        return _proxy(dcfg, host)
    token = request.cookies.get("pow_token")
    if token and _valid_token(token): return _proxy(dcfg, host)
    skip_ext = (".js",".css",".png",".jpg",".ico",".svg",".woff",".woff2")
    if not request.path.endswith(skip_ext):
        if _rate_limited(ip): _stats["rate_limited"]+=1; _save_stats(); return "Too Many Requests", 429
    next_url = request.path
    if request.query_string: next_url += "?" + request.query_string.decode()
    return redirect(f"/pow/gate?next={next_url}")

if __name__ == "__main__":
    log.info("Onion Guard v2 on port %d (difficulty=%d, domains=%d)", LISTEN_PORT, DIFFICULTY, len(DOMAINS))
    app.run(host="127.0.0.1", port=LISTEN_PORT)
'''
