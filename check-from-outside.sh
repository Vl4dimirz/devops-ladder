#!/usr/bin/env bash
# ============================================================================
# check-from-outside.sh — ตรวจเครื่องที่ harden แล้ว จากมุมของคนที่อยู่ข้างนอก
# ============================================================================
# ⭐⭐ ทำไมต้องมีตัวนี้ ในเมื่อมี verify-hardening.sh อยู่แล้ว
#
#    verify-hardening.sh รัน **บนเครื่องนั้น** จึงตอบได้แค่ว่า
#    "เครื่องคิดว่าตัวเองตั้งค่าไว้ยังไง"
#
#    แต่คำถามที่ลูกค้าถามจริงคือ "คนข้างนอกเห็นอะไรบ้าง"
#    ซึ่งเป็นคนละคำถาม และตอบได้จากข้างนอกเท่านั้น
#
#    ตัวอย่างที่ต่างกันจริง:
#    · ufw บอกว่าปิดพอร์ต 3306 แล้ว แต่ผู้ให้บริการมีไฟร์วอลล์ของตัวเองอีกชั้น
#      ที่เปิดทิ้งไว้ หรือกลับกันคือบล็อกพอร์ตที่เราตั้งใจเปิด
#    · sshd บอกว่าปิดรหัสผ่านแล้ว แต่ยังต้องพิสูจน์ว่าคนที่ยิงเข้ามาจริงถูกปฏิเสธ
#    · fail2ban บอกว่ามี jail เฝ้า ssh อยู่ **แต่ไม่เคยมีใครพิสูจน์ว่ามันแบนจริง**
#
# ⭐ ข้อสุดท้ายคือเหตุผลหลักที่ต้องมีเครื่องจริง ไม่ใช่แค่ container ใน CI
#
# ใช้:  bash check-from-outside.sh <ไอพี> [ชื่อผู้ใช้] [--test-fail2ban]
# ============================================================================

set -uo pipefail

HOST="${1:?ใช้: bash check-from-outside.sh <ไอพี> [ผู้ใช้] [--test-fail2ban]}"
USER_NAME="${2:-deploy}"
TEST_BAN="${3:-}"

PASS=0; FAIL=0; WARN=0
ok()    { printf '  \033[32mOK  \033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
warn()  { printf '  \033[33mWARN\033[0m %s\n' "$1"; WARN=$((WARN+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }
note()  { printf '       %s\n' "$1"; }

printf '\033[1mตรวจ %s จากภายนอก\033[0m\n' "$HOST"

# ── 1. พอร์ตที่มองเห็นจากข้างนอก ─────────────────────────────────────────
head_ "[1] พอร์ตที่คนข้างนอกเห็น"

# ⭐ ใช้ /dev/tcp ของ bash จะได้ไม่ต้องพึ่ง nmap
#    เปิดได้ = ต่อติดใน 3 วินาที · ปิดหรือถูกกรอง = ต่อไม่ติด
port_open() {
  timeout 3 bash -c "exec 3<>/dev/tcp/$HOST/$1" 2>/dev/null && exec 3<&- && return 0
  return 1
}

for P in 22 80 443; do
  if port_open "$P"; then
    ok "พอร์ต $P เปิด (ตั้งใจให้เปิด)"
  else
    bad "พอร์ต $P ต่อไม่ติด ทั้งที่ ufw ควรอนุญาต"
  fi
done

# ⚠️ พอร์ตกลุ่มนี้คือของที่ "ไม่ควรโผล่ออกมาข้างนอก" ในเครื่องที่ตั้งค่าถูก
#    ถ้าเปิด แปลว่า ufw ไม่ทำงาน หรือมีบริการที่ผูกกับ 0.0.0.0 โดยไม่ตั้งใจ
declare -A RISKY=(
  [3306]="MySQL" [5432]="PostgreSQL" [6379]="Redis" [27017]="MongoDB"
  [9200]="Elasticsearch" [8080]="HTTP สำรอง" [2375]="Docker API ไม่เข้ารหัส"
  [25]="SMTP" [111]="rpcbind" [5900]="VNC"
)
RISKY_FOUND=0
for P in "${!RISKY[@]}"; do
  if port_open "$P"; then
    bad "พอร์ต $P เปิดอยู่ (${RISKY[$P]}) — ไม่ควรมองเห็นจากอินเทอร์เน็ต"
    RISKY_FOUND=1
  fi
done
[ "$RISKY_FOUND" -eq 0 ] && ok "ไม่มีพอร์ตเสี่ยงเปิดออกมา (ตรวจ ${#RISKY[@]} พอร์ต)"

if command -v nmap >/dev/null 2>&1; then
  note "สแกนเต็มด้วย nmap ใช้:  nmap -Pn --top-ports 1000 $HOST"
else
  warn "ไม่มี nmap ตรวจได้แค่พอร์ตที่ระบุไว้ ไม่ใช่ทั้งเครื่อง"
  note "ติดตั้ง: sudo apt install -y nmap"
fi

# ── 2. SSH ที่คนข้างนอกเห็น ──────────────────────────────────────────────
head_ "[2] SSH จากมุมคนข้างนอก"

BANNER=$(timeout 5 bash -c "exec 3<>/dev/tcp/$HOST/22; head -1 <&3" 2>/dev/null)
if [ -n "$BANNER" ]; then
  ok "ตอบกลับ: $BANNER"
  # ⚠️ แบนเนอร์บอกรุ่น OpenSSH กับรุ่น OS ให้คนโจมตีรู้ว่าควรลองช่องไหน
  #    ไม่ใช่ช่องโหว่ แต่เป็นข้อมูลที่ให้ฟรีโดยไม่จำเป็น
  case "$BANNER" in
    *Ubuntu*|*Debian*) warn "แบนเนอร์บอกรุ่นระบบปฏิบัติการด้วย ปิดได้ด้วย DebianBanner no" ;;
  esac
else
  bad "ต่อพอร์ต 22 ไม่ได้"
fi

# ⭐⭐ ข้อนี้คือหัวใจ: บังคับให้ ssh ใช้รหัสผ่านอย่างเดียว แล้วต้องถูกปฏิเสธ
#    ⛔ ห้ามใส่รหัสจริง เราไม่ได้จะเข้า เราจะดูว่าเซิร์ฟเวอร์ "เสนอ" วิธีนี้ไหม
ssh_auth_methods() {
  timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
      -o PreferredAuthentications=none -o PubkeyAuthentication=no \
      -o ConnectTimeout=8 "$1@$HOST" true 2>&1 | grep -i "Permission denied" | head -1
}

METHODS=$(ssh_auth_methods "$USER_NAME")
if [ -n "$METHODS" ]; then
  note "วิธียืนยันตัวตนที่เซิร์ฟเวอร์เสนอ: $METHODS"
  if printf '%s' "$METHODS" | grep -qi "password"; then
    bad "เซิร์ฟเวอร์ยังเสนอการล็อกอินด้วยรหัสผ่าน = ปิดไม่สำเร็จ"
  else
    ok "ไม่เสนอการล็อกอินด้วยรหัสผ่าน (เหลือแต่ publickey)"
  fi
else
  warn "อ่านวิธียืนยันตัวตนไม่ได้ อาจเพราะ ssh รุ่นนี้ตอบต่างออกไป"
fi

# root ต้องเข้าไม่ได้ ไม่ว่าจะด้วยวิธีไหน
ROOT_TRY=$(timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o ConnectTimeout=8 "root@$HOST" true 2>&1 | head -1)
case "$ROOT_TRY" in
  *"Permission denied"*|*"denied"*) ok "root เข้าไม่ได้จากภายนอก" ;;
  *)                                bad "ผลการลองเข้าเป็น root ผิดคาด: $ROOT_TRY" ;;
esac

if command -v ssh-audit >/dev/null 2>&1; then
  note "ตรวจอัลกอริทึมเต็มด้วย:  ssh-audit $HOST"
else
  warn "ไม่มี ssh-audit จึงยังไม่ได้ตรวจอัลกอริทึมที่เซิร์ฟเวอร์รับ"
  note "ติดตั้ง: pip install ssh-audit"
fi

# ── 3. fail2ban แบนจริงไหม ───────────────────────────────────────────────
head_ "[3] fail2ban แบนจริงหรือแค่รันอยู่เฉยๆ"

if [ "$TEST_BAN" != "--test-fail2ban" ]; then
  warn "ข้ามการทดสอบนี้ (ต้องใส่ --test-fail2ban เอง)"
  note "⛔ ข้อนี้จะทำให้ไอพีบ้านของคุณ 'ถูกแบน' จากเครื่องนั้นชั่วคราว"
  note "   ค่าปริยายของ fail2ban คือแบน 10 นาที แล้วปลดเอง"
  note "   ⚠️ ก่อนรัน ต้องมั่นใจว่ามี console ของผู้ให้บริการไว้เข้าเครื่องได้"
  note "   เพราะถ้าตั้ง bantime ไว้นาน จะเข้าเครื่องทาง SSH ไม่ได้จนกว่าจะหมดเวลา"
else
  note "กำลังยิงล็อกอินผิดซ้ำๆ เพื่อดูว่าโดนแบนไหม"
  BANNED=0
  for i in $(seq 1 8); do
    timeout 8 ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o PreferredAuthentications=publickey -o IdentitiesOnly=yes \
        -o IdentityFile=/dev/null -o ConnectTimeout=5 \
        "ไม่มีผู้ใช้ชื่อนี้@$HOST" true >/dev/null 2>&1
    printf '       ครั้งที่ %d ' "$i"
    if port_open 22; then
      printf 'ยังต่อได้\n'
    else
      printf 'ต่อไม่ได้แล้ว = โดนแบน\n'
      BANNED=1
      break
    fi
  done

  if [ "$BANNED" -eq 1 ]; then
    ok "fail2ban แบนจริง หยุดการยิงซ้ำได้"
    note "ไอพีของคุณจะถูกปลดเองตาม bantime (ปริยาย 10 นาที)"
    note "ถ้าอยากปลดทันที เข้าผ่าน console แล้วสั่ง:"
    note "  sudo fail2ban-client set sshd unbanip <ไอพีของคุณ>"
  else
    warn "ยิงผิด 8 ครั้งแล้วยังไม่โดนแบน"
    note "อาจเป็นเพราะ maxretry ตั้งไว้สูงกว่านี้ (ปริยายบางรุ่นคือ 5)"
    note "หรือ jail เฝ้า log คนละไฟล์กับที่ sshd เขียนจริง"
    note "ตรวจบนเครื่อง:  sudo fail2ban-client status sshd"
  fi
fi

# ── สรุป ──────────────────────────────────────────────────────────────────
printf '\n\033[1mสรุป\033[0m  ผ่าน %d ข้อ · เตือน %d ข้อ · ไม่ผ่าน %d ข้อ\n' "$PASS" "$WARN" "$FAIL"
[ "$FAIL" -eq 0 ]
