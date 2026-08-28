// ค่าที่ต้องตรงกับเครื่องจริง ดูได้จาก metadata service บนเครื่องเอง
// โดยไม่ต้องใช้ token:  curl http://169.254.169.254/metadata/v1/id

variable "droplet_id" {
  description = "เลข id ของ droplet ที่มีอยู่แล้ว ใช้ตอน import"
  type        = string
}

variable "droplet_name" {
  description = "ชื่อเครื่อง ต้องตรงกับของจริง ไม่งั้น plan จะเสนอเปลี่ยนชื่อ"
  type        = string
  default     = "ladder-01"
}

variable "region" {
  description = "ภูมิภาค เปลี่ยนไม่ได้หลังสร้าง ถ้าใส่ผิด Terraform จะเสนอสร้างเครื่องใหม่"
  type        = string
  default     = "sgp1"
}

variable "droplet_size" {
  type    = string
  default = "s-1vcpu-1gb"
}

variable "droplet_image" {
  type    = string
  default = "ubuntu-24-04-x64"
}

variable "allowed_ports" {
  description = "พอร์ตที่เปิดให้เข้าจากอินเทอร์เน็ต ต้องตรงกับที่ ufw เปิดไว้"
  type        = list(number)
  default     = [22, 80, 443]
}
