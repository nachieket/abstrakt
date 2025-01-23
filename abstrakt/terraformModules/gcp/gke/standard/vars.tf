variable "cluster_name" {}

variable "vpc_network" {}

variable "subnet_name" {}

variable "container_node_pool_name" {}

variable "machine_type" {
  default = "n4-standard-16"
}

variable "project_id" {
  description = "project id"
}

variable "region" {
  description = "region"
}

variable "gke_num_nodes" {
  default     = 2
  description = "number of gke nodes"
}

variable "cidr_range" {
  default = "10.10.0.0/24"
}

variable "version_prefix" {
  default = "1.31."
}

variable "gke_username" {
  default     = ""
  description = "gke username"
}

variable "gke_password" {
  default     = ""
  description = "gke password"
}

variable "common_tags" {}
