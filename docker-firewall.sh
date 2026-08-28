#!/usr/bin/env bash
# ============================================================================
# docker-firewall.sh — ปิดช่องที่ Docker ทะลุ ufw
# ============================================================================
# ⭐⭐ ปัญหาที่แก้ และทำไมคนส่วนใหญ่ไม่รู้ว่ามีอยู่
#
#    เวลาสั่ง `docker run -p 8080:80` Docker ไปแก้ iptables เองโดยตรง
#    และแทรก chain ของมันไว้ **ก่อน** chain ของ ufw ในสาย FORWARD
#
#      -A FORWARD -j DOCKER-USER          <- ของ Docker
#      -A FORWARD -j DOCKER-FORWARD       <- ของ Docker
#      -A FORWARD -j ufw-before-forward   <- ของ ufw มาทีหลัง
#
#    ผลคือ `ufw status` ยังบอกว่าพอร์ตนั้นปิดอยู่ **แต่คนข้างนอกเข้าถึงได้จริง**
#    และไม่มีอะไรเตือนเลยสักอย่าง
#
#    พิสูจน์แล้วบนเครื่องจริง 2026-08-28: รันคอนเทนเนอร์ที่ -p 8080:80
#    ufw ไม่มีกฎอนุญาต 8080 สักข้อ แต่ยิงจากอินเทอร์เน็ตได้ 200
#
# ⭐ วิธีแก้: Docker เว้น chain ชื่อ DOCKER-USER ไว้ให้เราโดยเฉพาะ
#    มันถูกประเมิน **ก่อน** กฎที่ Docker สร้างเอง จึงเป็นที่เดียวที่เราชนะได้
#    ⛔ ห้ามไปแก้ chain อื่นของ Docker เพราะมันเขียนทับทุกครั้งที่บริการรีสตาร์ต
#
# ⚠️ ทางแก้ที่ดีกว่าและควรทำคู่กัน: ผูกพอร์ตกับ localhost เท่านั้น
#      docker run -p 127.0.0.1:8080:80 ...
#    แล้วให้ reverse proxy ตัวเดียวเป็นคนเปิดออกสู่ภายนอก
#    สคริปต์นี้เป็นตาข่ายรองรับ ไม่ใช่ข้ออ้างที่จะเผลอ publish พอร์ตมั่ว
#
# ใช้:  sudo bash docker-firewall.sh [พอร์ตที่อนุญาต คั่นด้วยจุลภาค]
#       ค่าปริยายคือ 80,443
# ============================================================================
set -euo pipefail

PORTS="${1:-80,443}"

# หาชื่ออินเทอร์เฟซที่ออกอินเทอร์เน็ต ไม่เดาว่าเป็น eth0
IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"
[ -n "$IFACE" ] || { echo "หาอินเทอร์เฟซสาธารณะไม่เจอ" >&2; exit 1; }

echo "อินเทอร์เฟซสาธารณะ: $IFACE"
echo "พอร์ตที่อนุญาตให้เข้าถึงคอนเทนเนอร์: $PORTS"

# ล้างกฎเดิมของเราออกก่อน เพื่อให้รันซ้ำได้โดยไม่สะสมกฎซ้อน
# ⭐ ใช้ comment เป็นเครื่องหมายว่ากฎไหนเป็นของเรา จะได้ไม่ไปลบของคนอื่น
while iptables -S DOCKER-USER 2>/dev/null | grep -q "ladder-docker-guard"; do
  N="$(iptables -L DOCKER-USER --line-numbers -n 2>/dev/null | grep "ladder-docker-guard" | head -1 | awk '{print $1}')"
  iptables -D DOCKER-USER "$N"
done

# ⛔⛔⛔ กับดักที่ทำให้กฎรุ่นแรกไม่ทำงาน ทั้งที่หน้าตาถูกต้องทุกอย่าง
#
#    รุ่นแรกเขียนว่า  -m multiport --dports 80,443 -j RETURN
#    ซึ่ง **ปล่อยทราฟฟิกของพอร์ต 8080 ผ่านไปด้วย** และตัวนับพิสูจน์แล้ว
#    (กฎอนุญาตมี pkts=1 ส่วนกฎ DROP มี pkts=0 คือไม่เคยถูกใช้เลย)
#
#    เพราะ **DNAT เกิดใน PREROUTING ซึ่งมาก่อน FORWARD**
#    พอแพ็กเก็ตมาถึง DOCKER-USER พอร์ตปลายทางถูกแปลงเป็นพอร์ตของคอนเทนเนอร์
#    ไปแล้ว (8080 -> 80) กฎที่เทียบ --dports จึงเทียบกับพอร์ตผิดตัว
#
# ⭐ ต้องเทียบกับพอร์ต "ก่อนแปลง" ซึ่ง conntrack จำไว้ให้: --ctorigdstport
#    ⚠️ ค่านี้รับได้ทีละพอร์ตหรือช่วง ไม่รับรายการ จึงต้องวนทีละพอร์ต
#
# ลำดับ อ่านจากบนลงล่าง เจอตัวไหนตรงก่อนใช้ตัวนั้น
#    1     ปล่อยการเชื่อมต่อที่เปิดค้างอยู่แล้ว ไม่งั้นตัดของที่กำลังใช้งาน
#    2..n  ปล่อยเฉพาะพอร์ตที่ตั้งใจเปิด เทียบจากพอร์ตก่อนแปลง
#    ท้าย  ทิ้งที่เหลือทั้งหมดที่มาจากอินเทอร์เน็ต
iptables -I DOCKER-USER 1 -i "$IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "ladder-docker-guard: keep established" -j RETURN

POS=2
IFS=',' read -ra PORT_LIST <<< "$PORTS"
for P in "${PORT_LIST[@]}"; do
  iptables -I DOCKER-USER "$POS" -i "$IFACE" -p tcp -m conntrack --ctorigdstport "$P" -m comment --comment "ladder-docker-guard: allow $P" -j RETURN
  POS=$((POS + 1))
done

# ⚠️ ทิ้ง ไม่ใช่ ปฏิเสธ — ปฏิเสธจะบอกคนสแกนว่ามีเครื่องอยู่ตรงนี้
#    ทิ้งเฉยๆ ทำให้เขาต้องรอจนหมดเวลาทุกครั้ง
iptables -I DOCKER-USER "$POS" -i "$IFACE" -m comment --comment "ladder-docker-guard: drop the rest" -j DROP

echo ""
echo "กฎใน DOCKER-USER ตอนนี้:"
iptables -S DOCKER-USER | sed 's/^/  /'
