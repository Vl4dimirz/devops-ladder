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

# ⭐⭐ พอร์ตหนึ่งพอร์ตมีได้สามสถานะ ไม่ใช่สอง และการแยกไม่ออกทำให้อ่านผลผิด
#
#    open     ต่อติด            = ไฟร์วอลล์อนุญาต และมีบริการฟังอยู่
#    refused  ถูกปฏิเสธทันที     = ไฟร์วอลล์อนุญาต แต่ไม่มีอะไรฟัง (เคอร์เนลส่ง RST)
#    filtered เงียบจนหมดเวลา     = ไฟร์วอลล์ทิ้งแพ็กเก็ต ไม่ตอบอะไรเลย
#
#    ⛔ ตัวตรวจรุ่นแรกนับ refused เป็นความล้มเหลว ซึ่งผิด
#       พอร์ต 80/443 ที่ ufw อนุญาตแต่ยังไม่มีเว็บเซิร์ฟเวอร์ จะเป็น refused
#       และนั่นคือพฤติกรรมที่ถูกต้อง ไม่ใช่ปัญหา
#
#    ⭐ ความต่างที่สำคัญด้านความปลอดภัยคือ refused บอกคนโจมตีว่า
#       "ที่นี่มีเครื่องอยู่จริงนะ แค่พอร์ตนี้ไม่มีใครฟัง"
#       ส่วน filtered ไม่บอกอะไรเลย ซึ่งเป็นเหตุผลที่ตั้งค่าปริยายเป็น deny ไม่ใช่ reject
probe_state() {
  # $1 = ไอพี  $2 = พอร์ต  คืนค่า open | refused | filtered
  local out
  out=$(timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2" 2>&1)
  if [ $? -eq 0 ]; then echo open; return; fi
  case "$out" in
    *"Connection refused"*|*refused*) echo refused ;;
    *)                                echo filtered ;;
  esac
}

# ⭐⭐ ตัวควบคุมด้านลบของตัวสแกนเอง — หลักการเดียวกับ mutation test
#    192.0.2.0/24 คือช่วง TEST-NET-1 ตาม RFC 5737 ที่สงวนไว้ทำเอกสาร
#    ไม่มีเครื่องจริงใช้ช่วงนี้ ดังนั้นถ้ายิงแล้ว "ต่อติด" แปลว่ามีตัวกลาง
#    (ISP, เราเตอร์, พร็อกซีใส) ตอบแทนอยู่ ผลของพอร์ตนั้นจึงเชื่อไม่ได้
#
#    ⛔ เจอของจริง 2026-08-28: ISP ดักพอร์ต 25 ไว้ทั้งหมด
#       ตัวตรวจเลยรายงานว่าเซิร์ฟเวอร์เปิด SMTP ทั้งที่ในเครื่องไม่มีอะไรฟังเลย
CONTROL_IP="192.0.2.1"
path_hijacked() { [ "$(probe_state "$CONTROL_IP" "$1")" = "open" ]; }

for P in 22 80 443; do
  case "$(probe_state "$HOST" "$P")" in
    open)     ok "พอร์ต $P เปิดและมีบริการฟังอยู่" ;;
    refused)  ok "พอร์ต $P ไฟร์วอลล์อนุญาต แต่ยังไม่มีบริการฟัง (ถูกต้องถ้ายังไม่ได้ติดตั้ง)" ;;
    filtered) bad "พอร์ต $P ถูกไฟร์วอลล์ทิ้ง ทั้งที่ ufw ควรอนุญาต" ;;
  esac
done

# ⚠️ พอร์ตกลุ่มนี้คือของที่ "ไม่ควรโผล่ออกมาข้างนอก" ในเครื่องที่ตั้งค่าถูก
#    ต้องเป็น filtered เท่านั้น ถ้าเป็น refused แปลว่า ufw ไม่ได้บล็อกมัน
declare -A RISKY=(
  [3306]="MySQL" [5432]="PostgreSQL" [6379]="Redis" [27017]="MongoDB"
  [9200]="Elasticsearch" [8080]="HTTP สำรอง" [2375]="Docker API ไม่เข้ารหัส"
  [25]="SMTP" [111]="rpcbind" [5900]="VNC"
)
RISKY_BAD=0
for P in "${!RISKY[@]}"; do
  STATE=$(probe_state "$HOST" "$P")
  [ "$STATE" = "filtered" ] && continue

  if path_hijacked "$P"; then
    warn "พอร์ต $P (${RISKY[$P]}) ตอบว่า $STATE แต่เชื่อไม่ได้"
    note "ไอพีที่ไม่มีอยู่จริงก็ตอบเหมือนกัน = มีตัวกลางในเส้นทางดักพอร์ตนี้ไว้"
    note "ต้องไปตรวจจากในเครื่องด้วย: sudo ss -tlnp | grep :$P"
    RISKY_BAD=1
    continue
  fi

  if [ "$STATE" = "open" ]; then
    bad "พอร์ต $P เปิดอยู่ (${RISKY[$P]}) — ไม่ควรมองเห็นจากอินเทอร์เน็ต"
  else
    bad "พอร์ต $P ถูกปฏิเสธแทนที่จะถูกทิ้ง (${RISKY[$P]}) — ufw ไม่ได้บล็อกพอร์ตนี้"
  fi
  RISKY_BAD=1
done
[ "$RISKY_BAD" -eq 0 ] && ok "พอร์ตเสี่ยงทั้ง ${#RISKY[@]} ตัวถูกไฟร์วอลล์ทิ้งหมด"

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
