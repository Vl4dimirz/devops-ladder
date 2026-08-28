#!/usr/bin/env bash
# ============================================================================
# setup-state-db.sh — เตรียม Postgres ให้เป็นที่เก็บ state ของ Terraform
# ============================================================================
# รันบนเครื่องที่จะเป็นฐานข้อมูล (ไม่ใช่เครื่องที่รัน Terraform)
# ใช้:  sudo bash setup-state-db.sh <ไอพีของเครื่องที่รัน Terraform>
#
# ⭐ ทำไมต้องเป็นคนละเครื่องกับที่รัน Terraform
#    ถ้า state อยู่บนเครื่องเดียวกับที่รัน มันก็ยังหายไปพร้อมเครื่องนั้นอยู่ดี
#    ซึ่งเป็นปัญหาข้อหนึ่งที่ remote state มีไว้แก้
#
# ⛔ เครื่องนี้เก็บ "แผนที่ของทุกอย่างที่ Terraform ดูแล" จึงต้องปิดให้แน่น
#    ไฟล์ state มีค่าที่ประกาศว่า sensitive อยู่ในนั้นแบบอ่านได้ด้วย
# ============================================================================
set -euo pipefail

ALLOW_IP="${1:?ใช้: sudo bash setup-state-db.sh <ไอพีของเครื่องที่รัน Terraform>}"
DB=terraform_state
DBUSER=tfstate
PGVER="$(ls /etc/postgresql/ | sort -n | tail -1)"
CONF="/etc/postgresql/${PGVER}/main"

echo "[1/5] สร้างรหัสผ่านแบบสุ่ม"
# ⭐ สร้างบนเครื่อง ไม่ให้มนุษย์เห็นและไม่ต้องพิมพ์
#    รหัสที่คนพิมพ์ได้ คือรหัสที่คนจำได้ และรหัสที่คนจำได้ คือรหัสที่เดาได้
PW="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 40)"

echo "[2/5] สร้างผู้ใช้และฐานข้อมูล"
# ⚠️ ใช้ psql ผ่าน stdin จะได้ไม่มีรหัสโผล่ในรายการโปรเซส
#    คำสั่งที่ใส่รหัสไว้ใน argument จะถูกคนอื่นในเครื่องเห็นได้ด้วย ps
sudo -u postgres psql -v ON_ERROR_STOP=1 >/dev/null <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${DBUSER}') THEN
    CREATE ROLE ${DBUSER} LOGIN PASSWORD '${PW}';
  ELSE
    ALTER ROLE ${DBUSER} PASSWORD '${PW}';
  END IF;
END
\$\$;
SQL
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB}'" | grep -q 1 || \
  sudo -u postgres createdb -O "${DBUSER}" "${DB}"

echo "[3/5] ให้ Postgres รับการเชื่อมต่อจากเครือข่าย"
# ค่าปริยายฟังเฉพาะ localhost ซึ่งใช้จากเครื่องอื่นไม่ได้
sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "${CONF}/postgresql.conf"

echo "[4/5] อนุญาตเฉพาะไอพี ${ALLOW_IP} และบังคับ SSL"
# ⭐⭐ hostssl ไม่ใช่ host — บังคับให้เข้ารหัสระหว่างทาง
#    ถ้าใช้ host เฉยๆ รหัสผ่านกับเนื้อ state จะวิ่งข้ามอินเทอร์เน็ตแบบอ่านได้
# ⭐ /32 คือไอพีเดียวเท่านั้น ไม่ใช่ทั้งช่วง
# ⛔ scram-sha-256 ไม่ใช่ md5 ซึ่งเลิกใช้ได้แล้ว
RULE="hostssl ${DB} ${DBUSER} ${ALLOW_IP}/32 scram-sha-256"
grep -qF "${RULE}" "${CONF}/pg_hba.conf" || echo "${RULE}" >> "${CONF}/pg_hba.conf"

systemctl restart postgresql

echo "[5/5] เปิดพอร์ต 5432 เฉพาะไอพีนั้น"
# ⛔ ห้ามเปิด 5432 ให้ทั้งอินเทอร์เน็ตเด็ดขาด
#    ฐานข้อมูลที่เปิดสู่สาธารณะคือเป้าที่บอตกวาดหาตลอดเวลา
ufw allow from "${ALLOW_IP}" to any port 5432 proto tcp >/dev/null

# เก็บสายเชื่อมต่อไว้ให้เจ้าของเครื่องอ่าน สิทธิ์ 600
umask 077
cat > /root/.tfstate_conn <<EOF
postgres://${DBUSER}:${PW}@${ALLOW_IP_PLACEHOLDER:-HOST}/${DB}?sslmode=require
EOF

echo ""
echo "เรียบร้อย ฐานข้อมูล ${DB} พร้อมใช้"
echo "สายเชื่อมต่ออยู่ที่ /root/.tfstate_conn (สิทธิ์ 600)"
echo "⚠️ ต้องแทน HOST ด้วยไอพีของเครื่องฐานข้อมูลเอง"
