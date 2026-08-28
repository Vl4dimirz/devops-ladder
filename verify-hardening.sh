#!/usr/bin/env bash
# ============================================================================
# verify-hardening.sh — ตรวจว่า harden.sh ทำสำเร็จจริงหรือแค่รันจบโดยไม่ error
# ============================================================================
# ⭐ ทำไมต้องมีไฟล์นี้ ในเมื่อ harden.sh มี `set -e` อยู่แล้ว
#
#    `set -e` บอกได้แค่ว่า "ไม่มีคำสั่งไหนคืนค่าผิดพลาด"
#    ซึ่งไม่ใช่คำถามเดียวกับ "เครื่องนี้ปลอดภัยขึ้นจริงไหม"
#
#    ตัวอย่างที่เกิดขึ้นจริงและเป็นเหตุผลหลักที่เขียนไฟล์นี้:
#    ขั้นที่ 4 ของ harden.sh ใช้ sed แก้ /etc/ssh/sshd_config
#    sed คืนค่าสำเร็จเสมอแม้ไม่มีบรรทัดไหนถูกแก้เลย
#    และ Ubuntu รุ่นใหม่มี `Include /etc/ssh/sshd_config.d/*.conf` อยู่บนสุด
#    ซึ่ง sshd ใช้กติกา "ค่าแรกที่เจอชนะ" ไฟล์ใน include จึงทับค่าที่เราเพิ่งแก้ได้
#
#    ⛔ ตัวตรวจนี้จึงอ่านจาก `sshd -T` = ค่าที่ sshd ใช้จริงหลังรวมทุกไฟล์แล้ว
#       ห้าม grep ไฟล์ที่เพิ่งแก้ เพราะนั่นคือการตรวจว่า "เราเขียนอะไรลงไป"
#       ไม่ใช่ "ระบบอ่านได้เป็นอะไร"
#
# ใช้:  sudo bash verify-hardening.sh <username>
# คืนค่า 0 เมื่อผ่านครบ · คืนค่า 1 เมื่อมีข้อใดข้อหนึ่งไม่ผ่าน
# ============================================================================

USER_NAME="${1:-deploy}"
PASS=0
FAIL=0
WARN=0

ok()   { printf '  \033[32mOK  \033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }
# ⭐ ระดับ "เตือน" มีไว้สำหรับของที่ยังไม่ใช่ช่องโหว่วันนี้ แต่จะกลายเป็นได้ในวันหน้า
#    ⛔ ห้ามเอาไปใช้กับข้อที่เป็นช่องโหว่จริง การลดระดับเพื่อให้ CI เขียว
#       คือวิธีที่ทีมส่วนใหญ่ใช้ปิดตาตัวเอง
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; WARN=$((WARN + 1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# ── 1. อัปเดตแพ็กเกจ + อัปเดตความปลอดภัยอัตโนมัติ ────────────────────────
head_ "[1] แพ็กเกจและการอัปเดตอัตโนมัติ"
if dpkg -s unattended-upgrades >/dev/null 2>&1; then
  ok "ติดตั้ง unattended-upgrades แล้ว"
else
  bad "ไม่พบ unattended-upgrades"
fi

# ⚠️ ติดตั้งแล้วไม่ได้แปลว่าเปิดใช้ ต้องมีไฟล์สั่งเปิดด้วย
if grep -qs '^APT::Periodic::Unattended-Upgrade *"1"' /etc/apt/apt.conf.d/20auto-upgrades; then
  ok "เปิดใช้การอัปเดตความปลอดภัยอัตโนมัติแล้ว"
else
  bad "ติดตั้งแล้วแต่ยังไม่ได้เปิดใช้ (20auto-upgrades ไม่ได้ตั้งเป็น 1)"
fi

# ── 2. ผู้ใช้ที่ไม่ใช่ root ────────────────────────────────────────────────
head_ "[2] ผู้ใช้ที่ไม่ใช่ root"
if id "$USER_NAME" >/dev/null 2>&1; then
  ok "มีผู้ใช้ $USER_NAME"
else
  bad "ไม่มีผู้ใช้ $USER_NAME"
fi

if id -nG "$USER_NAME" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
  ok "$USER_NAME อยู่ในกลุ่ม sudo"
else
  bad "$USER_NAME ไม่ได้อยู่ในกลุ่ม sudo"
fi

# ⚠️ ไฟล์ใน sudoers.d ที่สิทธิ์กว้างเกิน sudo จะเมินทั้งไฟล์แบบเงียบๆ
SUDOERS="/etc/sudoers.d/90-$USER_NAME"
if [ -f "$SUDOERS" ]; then
  MODE=$(stat -c '%a' "$SUDOERS")
  if [ "$MODE" = "440" ]; then
    ok "ไฟล์ sudoers ของ $USER_NAME สิทธิ์ 440"
  else
    bad "ไฟล์ sudoers สิทธิ์เป็น $MODE ควรเป็น 440"
  fi
else
  bad "ไม่มีไฟล์ $SUDOERS"
fi

# ── 3. กุญแจ SSH ──────────────────────────────────────────────────────────
head_ "[3] กุญแจ SSH"
SSH_DIR="/home/$USER_NAME/.ssh"
AUTH="$SSH_DIR/authorized_keys"

if [ -d "$SSH_DIR" ] && [ "$(stat -c '%a' "$SSH_DIR")" = "700" ]; then
  ok "โฟลเดอร์ .ssh สิทธิ์ 700"
else
  bad "โฟลเดอร์ .ssh ไม่มีหรือสิทธิ์ไม่ใช่ 700"
fi

# ⛔ sshd จะเมิน authorized_keys ที่สิทธิ์กว้างเกินไปโดยไม่บอกเหตุผลใน log ปกติ
#    อาการที่เห็นคือ "ล็อกอินไม่ได้" ทั้งที่กุญแจถูกต้องทุกอย่าง
if [ -f "$AUTH" ] && [ "$(stat -c '%a' "$AUTH")" = "600" ]; then
  ok "authorized_keys สิทธิ์ 600"
else
  bad "authorized_keys ไม่มีหรือสิทธิ์ไม่ใช่ 600"
fi

if [ -f "$AUTH" ] && [ "$(stat -c '%U' "$AUTH")" = "$USER_NAME" ]; then
  ok "authorized_keys เป็นของ $USER_NAME"
else
  bad "authorized_keys ไม่ได้เป็นของ $USER_NAME"
fi

# กุญแจต้องอ่านออกจริง ไม่ใช่แค่มีไฟล์
if [ -f "$AUTH" ] && ssh-keygen -l -f "$AUTH" >/dev/null 2>&1; then
  ok "authorized_keys อ่านเป็นกุญแจได้จริง ($(ssh-keygen -l -f "$AUTH" | awk '{print $4}'))"
else
  bad "authorized_keys ไม่ใช่กุญแจที่ถูกต้อง"
fi

# ── 4. ค่าที่ sshd ใช้จริง ────────────────────────────────────────────────
head_ "[4] ค่าที่ sshd ใช้จริง (อ่านจาก sshd -T ไม่ใช่จากไฟล์)"
# ⚠️ sshd -t และ sshd -T จะไม่ยอมทำงานถ้าไม่มีโฟลเดอร์ /run/sshd
#    มันเป็น tmpfs ที่ systemd สร้างให้ตอนสตาร์ตบริการ จึงหายไปช่วงที่ sshd ไม่ได้รัน
#    เช่นจังหวะที่ apt เพิ่งอัปเกรด openssh-server เสร็จ (เจอใน CI 2026-08-28)
[ -d /run/sshd ] || install -d -m 0755 /run/sshd 2>/dev/null || true

if sshd -t 2>/dev/null; then
  ok "ไฟล์ตั้งค่า sshd ถูกไวยากรณ์"
else
  bad "ไฟล์ตั้งค่า sshd ผิดไวยากรณ์ (sshd จะไม่ยอมรีสตาร์ต = ล็อกตัวเองออกจากเครื่อง)"
fi

EFFECTIVE=$(sshd -T 2>/dev/null)
check_sshd() {
  # $1 = ชื่อค่า  $2 = ค่าที่ต้องได้
  local got
  got=$(printf '%s\n' "$EFFECTIVE" | awk -v k="$1" 'tolower($1)==k {print tolower($2); exit}')
  if [ "$got" = "$2" ]; then
    ok "$1 = $2"
  else
    bad "$1 = ${got:-อ่านไม่ได้} (ต้องเป็น $2)"
  fi
}
check_sshd permitrootlogin no
check_sshd passwordauthentication no
check_sshd pubkeyauthentication yes

# ⚠️ ข้อนี้จับกับดักที่ตั้งใจดักไว้: ไฟล์หลักถูกแก้แล้ว แต่ include ทับกลับ
if [ -d /etc/ssh/sshd_config.d ] && ls /etc/ssh/sshd_config.d/*.conf >/dev/null 2>&1; then
  CULPRITS=$(grep -riEl '^\s*(PasswordAuthentication\s+yes|PermitRootLogin\s+(yes|prohibit-password))' \
       /etc/ssh/sshd_config.d/ 2>/dev/null | tr '\n' ' ')
  if [ -n "$CULPRITS" ]; then
    # ⭐ การมีไฟล์ที่ตั้งค่าตรงข้าม ไม่ได้แปลว่าประตูเปิด
    #    ตัวชี้ขาดคือค่าที่ sshd อ่านได้จริง ซึ่งตรวจไปแล้วสามข้อข้างบน
    #    ถ้าสามข้อนั้นผ่าน แปลว่าไฟล์ของเราเรียงมาก่อนและชนะแล้ว
    #    ⛔ แต่ยังต้องเตือน เพราะมันคือระเบิดเวลา ไม่ใช่เรื่องที่จบแล้ว
    warn "ยังมีไฟล์ที่ตั้งค่าตรงข้ามอยู่: $CULPRITS"
    warn "  ตอนนี้ 00-hardening.conf ชนะเพราะชื่อเรียงมาก่อน (sshd ใช้ค่าแรกที่เจอ)"
    warn "  ถ้ามีใครลบไฟล์ของเรา หรือ cloud-init เขียนไฟล์ที่เรียงก่อน 00- ประตูจะเปิดกลับทันที"
  else
    ok "ไม่มีไฟล์ใน sshd_config.d ที่ย้อนค่ากลับ"
  fi
else
  ok "ไม่มีไฟล์ใน sshd_config.d ให้ต้องกังวล"
fi

# ── 5. ไฟร์วอลล์ ──────────────────────────────────────────────────────────
head_ "[5] ไฟร์วอลล์ ufw"
UFW=$(ufw status verbose 2>/dev/null)
case "$UFW" in
  *"Status: active"*) ok "ufw เปิดใช้งานอยู่" ;;
  *)                  bad "ufw ยังไม่เปิดใช้งาน" ;;
esac
case "$UFW" in
  *"deny (incoming)"*) ok "ขาเข้าปฏิเสธเป็นค่าเริ่มต้น" ;;
  *)                   bad "ขาเข้าไม่ได้ปฏิเสธเป็นค่าเริ่มต้น" ;;
esac
case "$UFW" in
  *"allow (outgoing)"*) ok "ขาออกอนุญาต (ไม่งั้นเครื่องจะออกเน็ตไม่ได้)" ;;
  *)                    bad "ขาออกไม่ได้อนุญาต" ;;
esac
for PORT in 22 80 443; do
  if printf '%s\n' "$UFW" | grep -qE "^${PORT}/tcp +ALLOW IN"; then
    ok "เปิดพอร์ต $PORT/tcp"
  else
    bad "ไม่ได้เปิดพอร์ต $PORT/tcp"
  fi
done

# ── 6. fail2ban ───────────────────────────────────────────────────────────
head_ "[6] fail2ban"
if systemctl is-active --quiet fail2ban; then
  ok "บริการ fail2ban ทำงานอยู่"
else
  bad "บริการ fail2ban ไม่ทำงาน"
fi

# ⚠️ ติดตั้งและรันอยู่ ไม่ได้แปลว่ามีกฎเฝ้า ssh
#    ต้องมี jail ที่เปิดอยู่จริง ไม่งั้นมันรันเฉยๆ โดยไม่แบนใครเลย
if fail2ban-client status 2>/dev/null | grep -qiE 'sshd|ssh'; then
  ok "มี jail เฝ้า ssh อยู่จริง"
else
  bad "fail2ban ทำงานแต่ไม่มี jail เฝ้า ssh (รันเฉยๆ ไม่แบนใคร)"
fi

# ── สรุป ──────────────────────────────────────────────────────────────────
printf '\n\033[1mสรุป\033[0m  ผ่าน %d ข้อ · เตือน %d ข้อ · ไม่ผ่าน %d ข้อ\n' "$PASS" "$WARN" "$FAIL"
# ⭐ คำเตือนไม่ทำให้ล้ม แต่ต้องโผล่ในรายงานเสมอ
#    ของที่ซ่อนไว้เพราะ "ยังไม่พังวันนี้" คือของที่ไม่มีใครกลับมาแก้
[ "$FAIL" -eq 0 ]
