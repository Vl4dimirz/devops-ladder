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
# Ubuntu cloud images ship a drop-in that sets `PasswordAuthentication yes`.
# Observed on the GitHub Actions runner as /etc/ssh/sshd_config.d/50-cloud-init.conf;
# other images use 60-cloudimg-settings.conf for the same thing. Anything built
# on an Ubuntu cloud image is likely to have one of them -- DigitalOcean, AWS,
# Oracle Cloud, Hetzner. Do not assume the filename; check what is in the
# directory and check what `sshd -T` resolves to.
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

# `sshd -t` and `sshd -T` both refuse to run without the privilege separation
# directory, with "Missing privilege separation directory: /run/sshd" and exit
# 255. It is a tmpfs path that systemd creates via RuntimeDirectory=sshd, so it
# is absent whenever sshd is not currently running -- which is exactly the state
# apt leaves it in for a moment after upgrading openssh-server in step 1.
# Caught in CI on 2026-08-28. Creating it here is what the service unit does
# anyway, and is a no-op when sshd is already up.
install -d -m 0755 /run/sshd

# Refuse to restart on a config sshd cannot parse: a bad restart locks you out.
sshd -t

# Verify the resolved config before touching the running service. If a vendor
# drop-in still wins, stop here with the file named, rather than reporting
# success and leaving the door open.
for PAIR in "permitrootlogin no" "passwordauthentication no" "pubkeyauthentication yes"; do
  KEY="${PAIR%% *}"; WANT="${PAIR##* }"
  # ⛔ ห้ามใช้ awk ที่ exit กลางทาง หรือ `| head -1` ตรงนี้
  #    ตัวรับท่อที่ปิดตัวเองก่อน ทำให้ sshd โดน SIGPIPE
  #    แล้ว `set -o pipefail` เห็นเป็นความล้มเหลว `set -e` จึงฆ่าสคริปต์ทิ้ง
  #    อาการคือสคริปต์ตายเงียบๆ ที่ขั้นนี้ด้วย exit code 141 (128+13)
  #    เจอบนเครื่องจริง 2026-08-28 ขั้นที่ 5-7 เลยไม่เคยถูกรันเลยสองรอบ
  #    ⭐ ให้ awk อ่านจนจบแล้วค่อยพิมพ์ใน END แทน ไม่มีใครปิดท่อก่อน
  GOT="$(sshd -T | awk -v k="$KEY" 'tolower($1)==k {v=tolower($2)} END {print v}')"
  if [ "$GOT" != "$WANT" ]; then
    echo "ABORT: sshd resolves $KEY to '${GOT:-nothing}', expected '$WANT'." >&2
    echo "Something in /etc/ssh/sshd_config.d/ is overriding it:" >&2
    grep -riEl "^[[:space:]]*$KEY" /etc/ssh/sshd_config.d/ 2>/dev/null >&2 || true
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# ⛔ Do NOT `systemctl restart ssh` here.
#
# Restarting kills the sshd process that owns your session, so if you are
# running this over SSH — which is how a remote server is always set up — the
# script dies here and steps 5-7 never run. Found on a real box on 2026-08-28:
# the firewall and fail2ban were silently never installed, and the log showed
# sshd stopped for two minutes with nothing running to start it again.
#
# It only recovered because Ubuntu 24.04 enables `ssh.socket`, which listens on
# port 22 and starts ssh.service on demand. On a host without socket activation
# that is a permanent lockout with no way back in except the provider's console.
#
# `reload` sends SIGHUP: sshd re-reads its configuration and keeps every
# established connection. It is the correct verb for a config change, and the
# restart below is only a fallback for the case where sshd is not running.
# ---------------------------------------------------------------------------
if ! systemctl reload ssh 2>/dev/null && ! systemctl reload sshd 2>/dev/null; then
  echo "reload failed, falling back to restart (this may drop your session)" >&2
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
fi

# On Ubuntu 24.04+ port 22 is held by ssh.socket, not by ssh.service. Make sure
# whichever one owns the port comes back after a reboot: a hardened box you
# cannot log into after a restart is just a brick.
if systemctl list-unit-files ssh.socket >/dev/null 2>&1; then
  systemctl enable ssh.socket >/dev/null 2>&1 || true
else
  systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1 || true
fi

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
