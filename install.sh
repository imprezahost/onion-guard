#!/bin/bash
# Onion Guard Plugin v2.5 - Install Script

PLUGIN_DIR="/www/server/panel/plugin/onion_guard"
ICON_SOURCE="${PLUGIN_DIR}/icon.png"

echo "Installing Onion Guard v2.5..."

# Clear Python cache
find "${PLUGIN_DIR}" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
find "${PLUGIN_DIR}" -name "*.pyc" -delete 2>/dev/null

# Copy icon to all known aaPanel icon locations
if [ -f "${ICON_SOURCE}" ]; then
    echo "Installing plugin icon..."

    ICO_DIR1="/www/server/panel/BTPanel/static/img/soft_ico"
    if [ -d "$(dirname "$ICO_DIR1")" ]; then
        mkdir -p "$ICO_DIR1"
        cp -f "${ICON_SOURCE}" "${ICO_DIR1}/ico-onion_guard.png"
        echo "  -> ${ICO_DIR1}/ico-onion_guard.png"
    fi

    ICO_DIR2="/www/server/panel/BTPanel/static/vite/images/soft-ico"
    if [ -d "$(dirname "$ICO_DIR2")" ]; then
        mkdir -p "$ICO_DIR2"
        cp -f "${ICON_SOURCE}" "${ICO_DIR2}/ico-onion_guard.png"
        chmod 755 "${ICO_DIR2}/ico-onion_guard.png"
        echo "  -> ${ICO_DIR2}/ico-onion_guard.png"
    fi

    ICO_DIR3="/www/server/panel/static/img/soft_ico"
    if [ -d "$(dirname "$ICO_DIR3")" ]; then
        mkdir -p "$ICO_DIR3"
        cp -f "${ICON_SOURCE}" "${ICO_DIR3}/ico-onion_guard.png"
        echo "  -> ${ICO_DIR3}/ico-onion_guard.png"
    fi
else
    echo "WARNING: icon.png not found."
fi

# Set permissions
chmod -R 755 "${PLUGIN_DIR}"
chmod 644 "${PLUGIN_DIR}"/*.py "${PLUGIN_DIR}"/*.html "${PLUGIN_DIR}"/*.json 2>/dev/null

echo ""
echo "Onion Guard v2.5 installed. Restart aaPanel: bt restart"
echo "NOTE: Clear browser cache (Ctrl+Shift+R) to see the plugin icon."
