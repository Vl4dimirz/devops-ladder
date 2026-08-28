#!/usr/bin/env bash
# ============================================================================
# R1 - Server hardening for a fresh Ubuntu VPS  (DevSecOps: secure it FIRST)
#
# What it does, and WHY each step matters:
#   1. Update packages            - close known CVEs before anything is exposed
#   2. Create a non-root user     - never operate as root day-to-day
#   3. Install your SSH key       - log in with a key, not a guessable password
#   4. Lock down SSH              - kill root login + password login (the #1
#                                   thing bots brute-force on every new server)
#   5. Firewall (ufw)             - deny everything except SSH + web
#   6. fail2ban                   - auto-ban IPs that hammer SSH
#   7. Auto security updates      - stay patched without thinking about it
#
# RUN IT (as root, on the VPS):
#   bash harden.sh <your-username> "<your-ssh-public-key-one-line>"
#
# Oracle Cloud note: its Ubuntu image already gives you an 'ubuntu' user with
# your key, and it uses iptables + a cloud "Security List". So on Oracle you
# ALSO open ports 80/443 in the VCN Security List (console), and you may skip
# ufw (or align it with the existing iptables). We'll handle that together.
# ============================================================================
set -euo pipefail

USER_NAME="${1:?usage: bash harden.sh <username> \"<ssh_public_key>\"}"
SSH_PUBKEY="${2:?provide your SSH public key (the contents of id_ed25519.pub) as arg 2}"

echo "[1/7] Updating the system..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y

echo "[2/7] Creating non-root sudo user: $USER_NAME"
if ! id "$USER_NAME" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$USER_NAME"
  usermod -aG sudo "$USER_NAME"
fi
# Passwordless sudo makes CI/CD deploys simple; remove this line for a stricter box.
echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-$USER_NAME"
chmod 440 "/etc/sudoers.d/90-$USER_NAME"

echo "[3/7] Installing your SSH public key for $USER_NAME"
install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
printf '%s\n' "$SSH_PUBKEY" > "/home/$USER_NAME/.ssh/authorized_keys"
chmod 600 "/home/$USER_NAME/.ssh/authorized_keys"
chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.ssh/authorized_keys"

echo "[4/7] Hardening SSH (key-only, no root)..."
# ---------------------------------------------------------------------------
# Editing /etc/ssh/sshd_config alone DOES NOT WORK on a modern Ubuntu image.
#
# The stock file begins with:
#     Include /etc/ssh/sshd_config.d/*.conf
# and sshd takes the FIRST value it sees for a keyword, not the last. So every
# file in that directory is read before the rest of the main file and wins.
#
# Ubuntu cloud images ship /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
# containing `PasswordAuthentication yes`. Every provider built on those images
# has it: DigitalOcean, AWS, Oracle Cloud, Hetzner, and the GitHub Actions
# runner this script is tested on.
#
# Caught in CI on 2026-08-28. The old version of this script ran to completion,
# printed "password login is now OFF", and left password login ON. sed reports
# success whether or not it changed anything, so nothing looked wrong.
#
# The fix is to drop our own file in that directory with a name that sorts
# FIRST, so it wins the first-match rule, and then to verify the result against
# `sshd -T` — the config sshd actually resolves — before restarting anything.
# ---------------------------------------------------------------------------
SSHD=/etc/ssh/sshd_config
DROPIN=/etc/ssh/sshd_config.d/00-hardening.conf

install -d -m 755 /etc/ssh/sshd_config.d
cat > "$DROPIN" <<'SSHD_CONF'
# Written by harden.sh. Named 00- so it is read before any vendor drop-in;
# sshd uses the first value it finds for each keyword.
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
SSHD_CONF
chmod 644 "$DROPIN"

# Also patch the main file, for older images that have no Include line at all.
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/'              "$SSHD"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD"
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/'    "$SSHD"

# Refuse to restart on a config sshd cannot parse: a bad restart locks you out.
sshd -t

# Verify the resolved config before touching the running service. If a vendor
# drop-in still wins, stop here with the file named, rather than reporting
# success and leaving the door open.
for PAIR in "permitrootlogin no" "passwordauthentication no" "pubkeyauthentication yes"; do
  KEY="${PAIR%% *}"; WANT="${PAIR##* }"
  GOT="$(sshd -T | awk -v k="$KEY" 'tolower($1)==k {print tolower($2); exit}')"
  if [ "$GOT" != "$WANT" ]; then
    echo "ABORT: sshd resolves $KEY to '${GOT:-nothing}', expected '$WANT'." >&2
    echo "Something in /etc/ssh/sshd_config.d/ is overriding it:" >&2
    grep -riEl "^[[:space:]]*$KEY" /etc/ssh/sshd_config.d/ 2>/dev/null >&2 || true
    exit 1
  fi
done

systemctl restart ssh 2>/dev/null || systemctl restart sshd

echo "[5/7] Firewall (ufw): allow SSH + HTTP + HTTPS, deny the rest"
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "[6/7] fail2ban: auto-ban SSH brute-force"
apt-get install -y fail2ban
systemctl enable --now fail2ban

echo "[7/7] Unattended security upgrades"
apt-get install -y unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

echo
echo "DONE. Root login and password login are now OFF."
echo "From your PC, log in with:  ssh $USER_NAME@<server-ip>"
echo "Next: R2 - install Docker and deploy the app."
