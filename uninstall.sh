#!/bin/bash
# Onion Guard Plugin v1.0 - Uninstall Script

echo "Uninstalling Onion Guard plugin files..."

# Remove icons
rm -f /www/server/panel/BTPanel/static/img/soft_ico/ico-onion_guard.png
rm -f /www/server/panel/BTPanel/static/vite/images/soft-ico/ico-onion_guard.png
rm -f /www/server/panel/static/img/soft_ico/ico-onion_guard.png

echo "Plugin files removed. Service/data cleanup is handled by the plugin UI (Uninstall button)."
