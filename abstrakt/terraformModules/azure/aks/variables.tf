variable "resource_group_location" {
  type        = string
  default     = "uksouth"
  description = "Location of the resource group."
}

variable "vm_size" {
  default = "Standard_DS3_v2"
}

variable "cluster_name" {
  default = "crwd_aks_cluster"
}

variable "resource_group_name" {
  default = "crwd_resource_group"
}

variable "dns_prefix" {
  default = "company"
}

variable "node_count" {
  type        = number
  description = "The initial quantity of nodes for the node pool."
  default     = 3
}

variable "msi_id" {
  type        = string
  description = "The Managed Service Identity ID. Set this value if you're running this example using Managed Identity as the authentication method."
  default     = null
}

variable "cluster_username" {
  type        = string
  description = "The admin username for the new cluster."
  default     = "azureadmin"
}

#variable "arm_subscription_id" {}
#
#variable "arm_tenant_id" {}
#
#variable "arm_client_id" {}
#
#variable "arm_client_secret" {}

variable "common_tags" {}
