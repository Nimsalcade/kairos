#!/usr/bin/env bash
# Kairos testnet seed node setup for Ubuntu 24.04.
# Run as root, passing the IPs of the OTHER seed nodes (or none to rely on discovery):
#     bash setup-seed.sh [PEER_IP ...]
# Expects /root/kairos-0.3.0.zip to be present (a zip of this repository whose
# top-level folder is kairos-0.3.0), e.g. made with:
#     git archive --prefix=kairos-0.3.0/ -o kairos-0.3.0.zip HEAD
set -euo pipefail

VERSION=kairos-0.3.0
ZIP=/root/$VERSION.zip
APP=/opt/kairos
PORT=19333

[ "$(id -u)" -eq 0 ] || { echo "Please run as root."; exit 1; }
[ -f "$ZIP" ] || { echo "Missing $ZIP - upload it first with scp."; exit 1; }

echo "== 1/7 Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q unzip python3-venv ufw

echo "== 2/7 Creating unprivileged 'kairos' service user"
id kairos >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/kairos \
    --shell /usr/sbin/nologin kairos

echo "== 3/7 Installing Kairos to $APP"
mkdir -p "$APP"
rm -rf "$APP/$VERSION"
unzip -q -o "$ZIP" -d "$APP"
[ -d "$APP/venv" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q coincurve
chown -R root:root "$APP"          # the service can run the code but never modify it

echo "== 4/7 Running the test suite (must pass before going live)"
cd "$APP/$VERSION"
"$APP/venv/bin/python" -W ignore -m unittest discover -s tests 2>&1 | tail -3
"$APP/venv/bin/python" -c "import kairos.crypto as c; assert c.HARDENED, 'libsecp256k1 missing'; print('crypto backend:', c.BACKEND)"

echo "== 5/7 Firewall: SSH + Kairos peer port only (RPC stays on localhost)"
ufw allow OpenSSH
ufw allow $PORT/tcp
ufw --force enable

echo "== 6/7 Wallet"
if [ ! -f /etc/kairos.env ]; then
  echo "Choose a wallet passphrase: 10+ characters; letters, numbers, spaces and - _ . only."
  while true; do
    read -rsp "Passphrase: " P1; echo
    read -rsp "Repeat:     " P2; echo
    if [ "$P1" != "$P2" ]; then echo "They differ, try again."; continue; fi
    if [ ${#P1} -lt 10 ]; then echo "Too short, try again."; continue; fi
    if ! [[ "$P1" =~ ^[A-Za-z0-9\ ._-]+$ ]]; then echo "Please use only letters, numbers, spaces and - _ ."; continue; fi
    break
  done
  ( umask 077; printf 'KAIROS_WALLET_PASSPHRASE=%s\n' "$P1" > /etc/kairos.env )
  unset P1 P2
fi
PASS=$(sed -n 's/^KAIROS_WALLET_PASSPHRASE=//p' /etc/kairos.env)
runuser -u kairos -- env HOME=/home/kairos KAIROS_WALLET_PASSPHRASE="$PASS" \
    "$APP/venv/bin/python" -m kairos --testnet wallet show
unset PASS

echo "== 7/7 Installing and starting the systemd service"
CONNECT=""
for ip in "$@"; do CONNECT="$CONNECT --connect $ip:$PORT"; done
cat > /etc/systemd/system/kairos.service <<EOF
[Unit]
Description=Kairos testnet node
After=network-online.target
Wants=network-online.target

[Service]
User=kairos
Group=kairos
EnvironmentFile=/etc/kairos.env
Environment=HOME=/home/kairos
WorkingDirectory=$APP/$VERSION
ExecStart=$APP/venv/bin/python -m kairos --testnet node --daemon$CONNECT
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/home/kairos
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/kairos-cli <<EOF
#!/bin/sh
# Query the local node over RPC, e.g.:  kairos-cli getpeerinfo
cd $APP/$VERSION && exec runuser -u kairos -- env HOME=/home/kairos \\
    $APP/venv/bin/python -m kairos --testnet rpc "\$@"
EOF
chmod 755 /usr/local/bin/kairos-cli

systemctl daemon-reload
systemctl enable kairos >/dev/null
systemctl restart kairos
sleep 6
systemctl --no-pager --lines=0 status kairos | head -3

echo
echo "================================================================"
echo " Seed node is running."
echo " SAVE THE BACKUP CODE (krsseed1...) PRINTED ABOVE, offline."
echo "   Live log:     journalctl -u kairos -f"
echo "   Peers:        kairos-cli getpeerinfo"
echo "   Chain status: kairos-cli getblockchaininfo"
echo "================================================================"
