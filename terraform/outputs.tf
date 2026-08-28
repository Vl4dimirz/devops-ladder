// ⭐ output มีไว้ส่งต่อให้เครื่องมือถัดไป ไม่ใช่แค่ให้คนอ่าน
//    ตัวอย่างการต่อกับ Ansible โดยไม่ต้องพิมพ์ไอพีเอง:
//      terraform output -raw droplet_ip > /tmp/ip
//      ansible -i "$(cat /tmp/ip)," all -m ping

output "droplet_ip" {
  description = "ไอพีสาธารณะ"
  value       = digitalocean_droplet.ladder.ipv4_address
}

output "droplet_urn" {
  description = "ตัวระบุของ DigitalOcean ใช้ผูกกับทรัพยากรอื่น"
  value       = digitalocean_droplet.ladder.urn
}

output "firewall_ports" {
  description = "พอร์ตที่ไฟร์วอลล์ชั้นเครือข่ายเปิดอยู่ ควรตรงกับ ufw"
  value       = var.allowed_ports
}

output "monthly_cost_usd" {
  description = "ค่าใช้จ่ายต่อเดือนของ droplet ตัวนี้"
  value       = digitalocean_droplet.ladder.price_monthly
}
