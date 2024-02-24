variable "resource_group_location" {
  type        = string
  default     = "uksouth"
}

variable "resource_group_name" {
  default = "random-resource-group"
}

variable "cluster_name" {
  default = "random-azure-aci-cluster"
}

variable "ip_address_type" {
  default = "Private"
}

variable "aci_subnet" {
  default = "random_subnet"
}

variable "dns_name_label" {
  default = "azure-aci"
}

variable "os_type" {
  default = "Linux"
}

variable "common_tags" {}
